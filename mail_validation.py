"""Adapters for checkdmarc, cryptography and dkimpy. No paid APIs."""
import base64
import json
from email import policy
from email.parser import BytesParser

import dns.message
import dns.name
import dns.rdatatype
import dns.resolver
import dns.rrset
from checkdmarc.dmarc import check_dmarc
from checkdmarc.spf import check_spf
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
import dkim


class DNSAdapter:
    """Keep library queries on the caller's resolver, including offline fixtures."""
    def __init__(self, resolver):
        self.resolver = resolver
        self.errors = []
        self.nameservers = getattr(resolver, 'nameservers', [])
        self.lifetime = getattr(resolver, 'timeout', 10)

    def resolve(self, name, rdtype='A', *args, **kwargs):
        name = str(name).rstrip('.').lower()
        rdtype = dns.rdatatype.to_text(rdtype) if isinstance(rdtype, int) else str(rdtype)
        result = self.resolver.query(name, rdtype)
        if result.status == 'error':
            self.errors.append(f'{name} {rdtype}: {result.error}')
            raise dns.exception.Timeout(timeout=self.lifetime)
        if result.status == 'nxdomain':
            raise dns.resolver.NXDOMAIN()
        if not result.records:
            raise dns.resolver.NoAnswer()
        records = list(result.records)
        if rdtype == 'TXT':
            # TXT character strings are limited to 255 bytes. JSON quoting
            # preserves embedded quotes and backslashes for dnspython's parser.
            records = [' '.join(json.dumps(record[i:i+100], ensure_ascii=False)
                                for i in range(0, len(record), 100)) or '""'
                       for record in records]
        query = dns.message.make_query(name, rdtype)
        response = dns.message.make_response(query)
        response.answer.append(dns.rrset.from_text_list(name + '.', 60, 'IN', rdtype, records))
        response = dns.message.from_wire(response.to_wire())
        return dns.resolver.Answer(dns.name.from_text(name), dns.rdatatype.from_text(rdtype),
                                   dns.rdataclass.IN, response)


def validate_spf(domain, resolver):
    adapter = DNSAdapter(resolver)
    result = check_spf(domain, resolver=adapter, timeout=getattr(resolver, 'timeout', 10))
    result['dns_errors'] = adapter.errors
    return result


def validate_dmarc(domain, resolver):
    adapter = DNSAdapter(resolver)
    result = check_dmarc(domain, resolver=adapter, timeout=getattr(resolver, 'timeout', 10))
    result['dns_errors'] = adapter.errors
    return result


def inspect_dkim_key(record):
    info = {'bits': None, 'flags': [], 'key_status': 'INVALID', 'key_type': None}
    tags = {}
    for part in record.split(';'):
        name, sep, value = part.partition('=')
        if sep:
            name = name.strip().lower()
            if name in tags:
                info['flags'].append(f'Duplicate tag: {name}')
                return info
            tags[name] = value.strip()
    kind = tags.get('k', 'rsa').lower()
    info['key_type'] = kind
    if tags.get('v', 'DKIM1') != 'DKIM1':
        info['flags'].append('Invalid DKIM version')
        return info
    if 'p' not in tags:
        info['flags'].append('Missing p tag')
        return info
    if not tags['p']:
        info['key_status'] = 'REVOKED'
        info['flags'].append('Revoked key')
        return info
    if kind not in ('rsa', 'ed25519'):
        info['key_status'] = 'UNSUPPORTED'
        info['flags'].append(f'Unsupported key type: {kind}')
        return info
    try:
        raw = base64.b64decode(''.join(tags['p'].split()), validate=True)
        if kind == 'rsa':
            key = serialization.load_der_public_key(raw)
            if not isinstance(key, rsa.RSAPublicKey):
                raise ValueError('Expected RSA')
            info['bits'] = key.key_size
            if key.key_size < 1024:
                info['flags'].append(f'Weak RSA key: {key.key_size} bits')
        else:
            ed25519.Ed25519PublicKey.from_public_bytes(raw)
            info['bits'] = 256
        info['key_status'] = 'VALID'
    except (ValueError, TypeError) as exc:
        info['flags'].append(f'Invalid {kind} key: {type(exc).__name__}')
    if 'y' in tags.get('t', '').lower().split(':'):
        info['flags'].append('Testing mode: t=y')
    return info


def verify_eml(path, resolver):
    with open(path, 'rb') as stream:
        data = stream.read()
    message = BytesParser(policy=policy.default).parsebytes(data, headersonly=True)
    signatures = message.get_all('DKIM-Signature', [])
    result = {'file': str(path), 'status': 'UNSIGNED', 'signatures': []}
    for index, header in enumerate(signatures):
        fields = {}
        for part in str(header).split(';'):
            name, sep, value = part.partition('=')
            if sep:
                fields[name.strip().lower()] = value.strip()
        entry = {'domain': fields.get('d', ''), 'selector': fields.get('s', ''), 'status': 'FAIL'}
        errors = []

        def lookup(name, timeout=5):
            answer = resolver.txt(name.decode('ascii').rstrip('.'))
            if answer.status == 'error':
                errors.append(answer.error or 'DNS error')
            if len(answer.records) != 1:
                return None
            return answer.records[0].encode('utf-8')

        try:
            verified = dkim.DKIM(data, timeout=getattr(resolver, 'timeout', 10)).verify(index, dnsfunc=lookup)
            entry['status'] = 'PASS' if verified else 'FAIL'
        except (dkim.DKIMException, ValueError, UnicodeError) as exc:
            entry['error'] = type(exc).__name__
        if errors:
            entry['status'] = 'ERROR'
            entry['error'] = ', '.join(errors)
        result['signatures'].append(entry)
    statuses = [entry['status'] for entry in result['signatures']]
    if statuses:
        result['status'] = 'PASS' if 'PASS' in statuses else ('ERROR' if 'ERROR' in statuses else 'FAIL')
    return result
