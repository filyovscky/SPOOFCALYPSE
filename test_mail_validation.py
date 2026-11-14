import base64
import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest.mock import patch

import dkim
import spf as pyspf
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from checkdmarc.utils import DNS_CACHE

import spoof_check as s
from mail_validation import inspect_dkim_key, verify_eml
from test_spoof_check import FakeResolver


class LibraryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.public = base64.b64encode(cls.private.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()

    def setUp(self):
        DNS_CACHE.clear()

    def test_rsa_actual_modulus_size(self):
        result = inspect_dkim_key('v=DKIM1; p=' + self.public)
        self.assertEqual(result['bits'], 2048)
        self.assertEqual(result['key_status'], 'VALID')

    def test_ed25519_not_marked_weak(self):
        key = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        result = inspect_dkim_key('v=DKIM1; k=ed25519; p=' + base64.b64encode(key).decode())
        self.assertEqual(result['key_status'], 'VALID')
        self.assertEqual(result['flags'], [])

    def test_invalid_and_revoked_keys(self):
        for value, expected in [('p=', 'REVOKED'), ('p=!!!!', 'INVALID'),
                                ('p=AAAA; p=BBBB', 'INVALID'), ('k=unknown; p=AAAA', 'UNSUPPORTED'),
                                ('v=DKIM2; p=AAAA', 'INVALID')]:
            with self.subTest(value=value):
                self.assertEqual(inspect_dkim_key(value)['key_status'], expected)

    def test_multiple_txt_keys_not_concatenated(self):
        resolver = FakeResolver({('s1._domainkey.example.com', 'TXT'): ['p=' + self.public, 'p=AAAA']})
        found = s.check_dkim('example.com', resolver, ['s1'])['found'][0]
        self.assertEqual(found['key_status'], 'INVALID')
        self.assertIn('Multiple DKIM keys', found['flags'])

    def test_signed_email_tamper_and_dns_error(self):
        message = b'From: sender@example.com\r\nTo: receiver@example.net\r\nSubject: Test\r\n\r\nOriginal body\r\n'
        private = self.private.private_bytes(serialization.Encoding.PEM,
                                            serialization.PrivateFormat.TraditionalOpenSSL,
                                            serialization.NoEncryption())
        signed = dkim.sign(message, b'custom-selector', b'example.com', private) + message
        resolver = FakeResolver({('custom-selector._domainkey.example.com', 'TXT'): ['v=DKIM1; p=' + self.public]})
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'message.eml')
            for content, expected in [(signed, 'PASS'),
                                      (signed.replace(b'Original body', b'Altered body'), 'FAIL'),
                                      (message, 'UNSIGNED')]:
                with self.subTest(expected=expected):
                    with open(path, 'wb') as stream:
                        stream.write(content)
                    result = verify_eml(path, resolver)
                    self.assertEqual(result['status'], expected)
            with open(path, 'wb') as stream:
                stream.write(signed)
            broken = FakeResolver({('custom-selector._domainkey.example.com', 'TXT'):
                                   s.DNSResult('error', error='Timeout')})
            self.assertEqual(verify_eml(path, broken)['status'], 'ERROR')

    def test_eml_only_cli_json_markdown(self):
        with tempfile.TemporaryDirectory() as directory:
            path, md = os.path.join(directory, 'unsigned.eml'), os.path.join(directory, 'report.md')
            with open(path, 'wb') as stream:
                stream.write(b'From: sender@example.com\r\n\r\nHello\r\n')
            out = io.StringIO()
            with patch('sys.argv', ['spoof_check.py', '--eml', path, '--json', '--md', md]), \
                    patch.object(s, 'Resolver', return_value=FakeResolver({})), \
                    contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                s.main()
            result = json.loads(out.getvalue())
            self.assertEqual(result['emails'][0]['status'], 'UNSIGNED')
            with open(md, encoding='utf-8') as stream:
                self.assertIn('UNSIGNED', stream.read())

    def test_pct_removed_under_rfc9989(self):
        resolver = FakeResolver({('example.com', 'TXT'): ['v=spf1 -all'],
                                 ('_dmarc.example.com', 'TXT'): ['v=DMARC1; p=quarantine; pct=0']})
        result = s.analyze_domain('example.com', resolver, with_dkim=False)
        self.assertTrue(result['dmarc']['validation']['valid'])
        self.assertIsNone(result['dmarc']['pct'])
        self.assertTrue(any('pct' in warning for warning in result['dmarc']['warnings']))
        self.assertNotEqual(result['code'], s.PARTIAL)

    def test_psd_boundary(self):
        resolver = FakeResolver({('child.example.com', 'TXT'): ['v=spf1 -all'],
                                 ('_dmarc.example.com', 'TXT'): ['v=DMARC1; p=reject; psd=n'],
                                 ('_dmarc.com', 'TXT'): ['v=DMARC1; p=none; psd=y']})
        result = s.analyze_domain('child.example.com', resolver, with_dkim=False)
        self.assertEqual(result['dmarc']['record_domain'], 'example.com')
        self.assertEqual(result['dmarc']['policy'], 'reject')

    def test_spf_results_against_pyspf_offline(self):
        cases = [('v=spf1 -all', 'fail'), ('v=spf1 +all', 'pass'),
                 ('v=spf1 ~all', 'softfail'), ('v=spf1 ?all', 'neutral')]
        for record, expected in cases:
            with self.subTest(record=record):
                DNS_CACHE.clear()
                resolver = FakeResolver({('example.com', 'TXT'): [record]})
                result = s.SPFAnalysis('example.com', resolver)
                query = pyspf.query(i='192.0.2.1', s='sender@example.com', h='mail.example.com')
                self.assertEqual(query.check(spf=record)[0], expected)
                self.assertTrue(result.validation['valid'])


if __name__ == '__main__':
    unittest.main()
