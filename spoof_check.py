#!/usr/bin/env python3
"""SPOOFCALYPSE: SPF / DKIM / DMARC checks.

The spoofability matrix (TABLE) is derived from MattKeeley/Spoofy
(https://github.com/MattKeeley/Spoofy). The source project reports Microsoft 365 testing.
This adaptation has not repeated those delivery tests. Spoofy is licensed under
CC BY-NC 4.0: the table is reused here with attribution for non-commercial
use. See https://github.com/MattKeeley/Spoofy for the original project.

Extensions over the original:
  - DKIM selector enumeration over DNS (no third-party API)
  - dangling include detection (takeover of include targets => SPF bypass)
  - risk score + detailed PASS/WARN/FAIL/INFO checklist per domain
  - scope input (file or args), sorted output: spoofable first
"""
import argparse
import base64
import csv
import json
import ipaddress
import html
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urlparse

import dns.exception
import dns.resolver

from mail_validation import validate_spf, validate_dmarc, inspect_dkim_key, verify_eml

__version__ = "0.1.0"

DEFAULT_TIMEOUT = 10
DEFAULT_WORKERS = 16
DNS_RETRIES = 3
USE_COLOR = True

# ---------------------------------------------------------------------------
# Spoofability matrix (source: MattKeeley/Spoofy, tested against M365)
# Keys: (SPF state, DMARC tags as written) -> code
# SPF state: "-all", "~all", "?all", "+all", "noall" (no all), "nospf"
# DMARC part: None (no record) or (p, sp, aspf), None = tag absent
# ---------------------------------------------------------------------------

TABLE = {
    ("-all", None): 0,
    ("-all", ("quarantine", "none", None)): 1,
    ("-all", ("reject", "none", None)): 1,
    ("-all", ("none", "none", "r")): 1,
    ("-all", ("none", "none", "s")): 1,
    ("-all", ("quarantine", "none", "r")): 1,
    ("-all", ("reject", "none", "r")): 1,
    ("-all", ("none", "quarantine", "r")): 2,
    ("-all", ("none", "reject", "r")): 2,
    ("-all", ("none", None, None)): 4,
    ("-all", ("none", None, "r")): 4,
    ("-all", ("none", None, "s")): 4,
    ("-all", ("none", "quarantine", None)): 5,
    ("-all", ("none", "reject", None)): 5,
    ("-all", ("none", "none", None)): 7,
    ("-all", ("quarantine", None, None)): 8,
    ("-all", ("reject", None, None)): 8,
    ("-all", ("quarantine", "quarantine", None)): 8,
    ("-all", ("quarantine", "reject", None)): 8,
    ("-all", ("reject", "quarantine", None)): 8,
    ("-all", ("reject", "reject", None)): 8,
    ("-all", ("none", "quarantine", "s")): 8,
    ("-all", ("none", "reject", "s")): 8,
    ("-all", ("quarantine", "none", "s")): 8,
    ("-all", ("quarantine", "quarantine", "r")): 8,
    ("-all", ("quarantine", "quarantine", "s")): 8,
    ("-all", ("quarantine", "reject", "r")): 8,
    ("-all", ("quarantine", "reject", "s")): 8,
    ("-all", ("reject", "none", "s")): 8,
    ("-all", ("reject", "quarantine", "r")): 8,
    ("-all", ("reject", "quarantine", "s")): 8,
    ("-all", ("reject", "reject", "r")): 8,
    ("-all", ("reject", "reject", "s")): 8,
    ("?all", ("none", None, "r")): 0,
    ("?all", ("none", "none", "r")): 0,
    ("?all", None): 0,
    ("?all", ("quarantine", "none", "r")): 1,
    ("?all", ("quarantine", "none", "s")): 1,
    ("?all", ("reject", "none", "r")): 1,
    ("?all", ("reject", "none", "s")): 1,
    ("?all", ("none", None, None)): 4,
    ("?all", ("none", "none", None)): 4,
    ("?all", ("none", None, "s")): 4,
    ("?all", ("none", "none", "s")): 4,
    ("?all", ("none", "quarantine", None)): 5,
    ("?all", ("none", "reject", None)): 5,
    ("?all", ("none", "quarantine", "r")): 5,
    ("?all", ("none", "quarantine", "s")): 5,
    ("?all", ("none", "reject", "r")): 5,
    ("?all", ("none", "reject", "s")): 5,
    ("?all", ("quarantine", "none", None)): 6,
    ("?all", ("reject", "none", None)): 6,
    ("?all", ("quarantine", None, None)): 8,
    ("?all", ("reject", None, None)): 8,
    ("?all", ("quarantine", "quarantine", None)): 8,
    ("?all", ("quarantine", "reject", None)): 8,
    ("?all", ("reject", "quarantine", None)): 8,
    ("?all", ("reject", "reject", None)): 8,
    ("?all", ("quarantine", "quarantine", "r")): 8,
    ("?all", ("quarantine", "quarantine", "s")): 8,
    ("?all", ("quarantine", "reject", "r")): 8,
    ("?all", ("quarantine", "reject", "s")): 8,
    ("?all", ("reject", "quarantine", "r")): 8,
    ("?all", ("reject", "quarantine", "s")): 8,
    ("?all", ("reject", "reject", "r")): 8,
    ("?all", ("reject", "reject", "s")): 8,
    ("+all", ("none", None, None)): 4,
    ("+all", ("quarantine", None, None)): 4,
    ("+all", ("reject", None, None)): 4,
    ("+all", ("none", "none", None)): 4,
    ("+all", ("none", "quarantine", None)): 4,
    ("+all", ("none", "reject", None)): 4,
    ("+all", ("none", None, "r")): 4,
    ("+all", ("none", None, "s")): 4,
    ("+all", ("quarantine", "none", None)): 4,
    ("+all", ("quarantine", "quarantine", None)): 4,
    ("+all", ("quarantine", "reject", None)): 4,
    ("+all", ("reject", "none", None)): 4,
    ("+all", ("reject", "quarantine", None)): 4,
    ("+all", ("reject", "reject", None)): 4,
    ("+all", ("none", "none", "r")): 4,
    ("+all", ("none", "none", "s")): 4,
    ("+all", ("none", "quarantine", "r")): 4,
    ("+all", ("none", "quarantine", "s")): 4,
    ("+all", ("none", "reject", "r")): 4,
    ("+all", ("none", "reject", "s")): 4,
    ("+all", ("quarantine", "none", "r")): 4,
    ("+all", ("quarantine", "none", "s")): 4,
    ("+all", ("quarantine", "quarantine", "r")): 4,
    ("+all", ("quarantine", "quarantine", "s")): 4,
    ("+all", ("quarantine", "reject", "r")): 4,
    ("+all", ("quarantine", "reject", "s")): 4,
    ("+all", ("reject", "none", "r")): 4,
    ("+all", ("reject", "none", "s")): 4,
    ("+all", ("reject", "quarantine", "r")): 4,
    ("+all", ("reject", "quarantine", "s")): 4,
    ("+all", ("reject", "reject", "r")): 4,
    ("+all", ("reject", "reject", "s")): 4,
    ("+all", None): 4,
    ("~all", ("none", "none", None)): 0,
    ("~all", None): 0,
    ("~all", ("quarantine", "none", None)): 1,
    ("~all", ("reject", "none", None)): 1,
    ("~all", ("none", "quarantine", None)): 2,
    ("~all", ("none", "reject", None)): 2,
    ("~all", ("none", None, "r")): 2,
    ("~all", ("none", None, "s")): 2,
    ("~all", ("none", "quarantine", "r")): 2,
    ("~all", ("none", "quarantine", "s")): 2,
    ("~all", ("none", "reject", "r")): 2,
    ("~all", ("none", "reject", "s")): 2,
    ("~all", ("none", "none", "r")): 7,
    ("~all", ("none", "none", "s")): 7,
    ("~all", ("none", None, None)): 0,
    ("~all", ("quarantine", None, None)): 8,
    ("~all", ("reject", None, None)): 8,
    ("~all", ("quarantine", "quarantine", None)): 8,
    ("~all", ("quarantine", "reject", None)): 8,
    ("~all", ("reject", "quarantine", None)): 8,
    ("~all", ("reject", "reject", None)): 8,
    ("~all", ("quarantine", "none", "r")): 8,
    ("~all", ("quarantine", "none", "s")): 8,
    ("~all", ("quarantine", "quarantine", "r")): 8,
    ("~all", ("quarantine", "quarantine", "s")): 8,
    ("~all", ("quarantine", "reject", "r")): 8,
    ("~all", ("quarantine", "reject", "s")): 8,
    ("~all", ("reject", "none", "r")): 8,
    ("~all", ("reject", "none", "s")): 8,
    ("~all", ("reject", "quarantine", "r")): 8,
    ("~all", ("reject", "quarantine", "s")): 8,
    ("~all", ("reject", "reject", "r")): 8,
    ("~all", ("reject", "reject", "s")): 8,
    ("noall", ("none", None, "r")): 0,
    ("noall", ("none", "none", "r")): 0,
    ("noall", None): 0,
    ("noall", ("quarantine", "none", "r")): 1,
    ("noall", ("quarantine", "none", "s")): 1,
    ("noall", ("reject", "none", "r")): 1,
    ("noall", ("reject", "none", "s")): 1,
    ("noall", ("none", None, None)): 4,
    ("noall", ("none", "none", None)): 4,
    ("noall", ("none", None, "s")): 4,
    ("noall", ("none", "none", "s")): 4,
    ("noall", ("none", "quarantine", None)): 5,
    ("noall", ("none", "reject", None)): 5,
    ("noall", ("none", "quarantine", "r")): 5,
    ("noall", ("none", "quarantine", "s")): 5,
    ("noall", ("none", "reject", "r")): 5,
    ("noall", ("none", "reject", "s")): 5,
    ("noall", ("quarantine", "none", None)): 6,
    ("noall", ("reject", "none", None)): 6,
    ("noall", ("quarantine", None, None)): 8,
    ("noall", ("reject", None, None)): 8,
    ("noall", ("quarantine", "quarantine", None)): 8,
    ("noall", ("quarantine", "reject", None)): 8,
    ("noall", ("reject", "quarantine", None)): 8,
    ("noall", ("reject", "reject", None)): 8,
    ("noall", ("quarantine", "quarantine", "r")): 8,
    ("noall", ("quarantine", "quarantine", "s")): 8,
    ("noall", ("quarantine", "reject", "r")): 8,
    ("noall", ("quarantine", "reject", "s")): 8,
    ("noall", ("reject", "quarantine", "r")): 8,
    ("noall", ("reject", "quarantine", "s")): 8,
    ("noall", ("reject", "reject", "r")): 8,
    ("noall", ("reject", "reject", "s")): 8,
    ("nospf", None): 0,
    ("nospf", ("none", "none", "r")): 2,
    ("nospf", ("none", "none", "s")): 2,
    ("nospf", ("none", None, None)): 4,
    ("nospf", ("quarantine", None, None)): 8,
    ("nospf", ("reject", None, None)): 8,
    ("nospf", ("none", "none", None)): 8,
    ("nospf", ("none", "quarantine", None)): 8,
    ("nospf", ("none", "reject", None)): 8,
    ("nospf", ("none", None, "r")): 8,
    ("nospf", ("none", None, "s")): 8,
    ("nospf", ("quarantine", "none", None)): 8,
    ("nospf", ("quarantine", "quarantine", None)): 8,
    ("nospf", ("quarantine", "reject", None)): 8,
    ("nospf", ("reject", "none", None)): 8,
    ("nospf", ("reject", "quarantine", None)): 8,
    ("nospf", ("reject", "reject", None)): 8,
    ("nospf", ("none", "quarantine", "r")): 8,
    ("nospf", ("none", "quarantine", "s")): 8,
    ("nospf", ("none", "reject", "r")): 8,
    ("nospf", ("none", "reject", "s")): 8,
    ("nospf", ("quarantine", "none", "r")): 8,
    ("nospf", ("quarantine", "none", "s")): 8,
    ("nospf", ("quarantine", "quarantine", "r")): 8,
    ("nospf", ("quarantine", "quarantine", "s")): 8,
    ("nospf", ("quarantine", "reject", "r")): 8,
    ("nospf", ("quarantine", "reject", "s")): 8,
    ("nospf", ("reject", "none", "r")): 8,
    ("nospf", ("reject", "none", "s")): 8,
    ("nospf", ("reject", "quarantine", "r")): 8,
    ("nospf", ("reject", "quarantine", "s")): 8,
    ("nospf", ("reject", "reject", "r")): 8,
    ("nospf", ("reject", "reject", "s")): 8,
}

PARTIAL = 3   # p=quarantine with pct < 100
UNKNOWN = 9   # DNS lookup failed, records may be missing

MESSAGES = {
    0: "Spoofing possible",
    1: "Subdomain spoofing possible",
    2: "Organizational domain spoofing possible",
    3: "Spoofing might be possible (partial DMARC coverage)",
    4: "Spoofing might be possible (mailbox dependent)",
    5: "Organizational domain spoofing might be possible (mailbox dependent)",
    6: "Subdomain spoofing might be possible (mailbox dependent)",
    7: "Subdomain spoofing possible, organizational domain spoofing might be possible",
    8: "No bypass identified",
    9: "Unable to determine (DNS error, invalid SPF, or incomplete evaluation)",
}

VERDICTS = {
    0: "SPOOFABLE", 1: "SPOOFABLE", 2: "SPOOFABLE", 7: "SPOOFABLE",
    3: "POSSIBLE", 4: "POSSIBLE", 5: "POSSIBLE", 6: "POSSIBLE",
    8: "NOT_SPOOFABLE",
    9: "UNKNOWN",
}
VERDICT_ORDER = {"SPOOFABLE": 0, "POSSIBLE": 1, "NOT_SPOOFABLE": 2, "UNKNOWN": 3}
VERDICT_LABELS = {
    "SPOOFABLE": "SPOOFABLE (high probability)",
    "POSSIBLE": "POSSIBLE (mailbox dependent)",
    "NOT_SPOOFABLE": "NOT_SPOOFABLE",
    "UNKNOWN": "UNKNOWN (DNS/configuration/evaluation)",
}

# What the table says about spoofing a subdomain of a domain with that code.
AS_SUBDOMAIN = {0: 0, 1: 0, 2: 8, 3: 4, 4: 4, 5: 8, 6: 4, 7: 0, 8: 8, 9: 9}

DKIM_SELECTORS = [
    # generic / widely used
    "default", "selector", "selector1", "selector2", "selector3",
    "sel", "sel1", "sel2", "sel3", "s1", "s2", "s3", "s4",
    "k1", "k2", "k3", "p1", "p2", "p3",
    # ESP / vendor specific
    "google", "gmail", "outlook", "ms", "zoho", "yandex", "mail",
    "mandrill", "mailchimp", "mc", "sendgrid", "sg", "sparkpost", "sp",
    "salesforce", "sf", "zendesk", "esk", "hubspot", "hs", "brevo",
    "atlassian", "jira", "slack", "zoom", "dropbox", "apple", "icloud",
    "proton", "pp", "tutanota", "fastmail", "hey", "zimbra", "zm",
    # platforms
    "port25", "mta", "relay", "bulk", "list", "news", "cm", "em",
    "dkim", "dk", "sig", "sig1", "sig2", "key", "rsa", "public",
    "mx", "smtp", "global", "ext", "vm", "pr", "d1", "d2", "e1", "e2",
    "t01", "t02", "s01", "s02", "m1", "m2",
    # date-based selectors (Microsoft 365 style and common rotations)
    "20161025", "20170413", "20190601", "20210601", "20220601",
    "20230601", "20240601", "20250601",
    # mail.ru / VK ecosystem (relevant for .ru scopes)
    "mailru", "yam", "ydx", "vk", "bk",
]

# Common multi-part public suffixes (enough for dangling-include detection
# without adding a tldextract/PSL dependency).
MULTI_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "co.jp",
    "com.au", "net.au", "org.au", "com.br", "com.mx", "co.in", "co.za",
    "com.tr", "com.cn", "com.tw", "co.kr", "com.hk", "com.sg", "com.ar",
    "com.ua", "co.nz", "com.co", "com.pe", "com.ve", "com.uy", "com.ec",
    "co.id", "com.my", "com.ph", "com.vn", "com.ng", "com.eg", "com.sa",
    "com.pk", "com.bd", "com.np", "com.lk", "com.kw", "com.qa", "com.bh",
    "com.om", "com.jo", "com.lb", "com.iq", "com.ly", "com.dz", "com.ma",
    "com.tn", "com.kz", "com.ge", "com.am", "com.az", "com.by", "com.md",
    "com.ro", "com.bg", "com.rs", "com.ba", "com.hr", "com.si", "com.mk",
    "com.al", "com.me", "com.gr", "com.cy", "com.mt", "com.lv", "com.lt",
    "com.ee", "com.is", "com.lu", "com.be", "com.nl", "com.de", "com.fr",
    "com.es", "com.it", "com.pt", "com.pl", "com.cz", "com.sk", "com.hu",
}

SPF_DNS_MECHANISMS = {"include", "a", "mx", "ptr", "exists"}
SPF_KNOWN_MECHANISMS = SPF_DNS_MECHANISMS | {"all", "ip4", "ip6"}
LOOKUP_LIMIT = 10
VOID_LOOKUP_LIMIT = 2
MAX_DEPTH = 10

_SPF_VERSION = re.compile(r"^v=spf1(\s|$)", re.IGNORECASE)
_DMARC_VERSION = re.compile(r"^[vV]\s*=\s*DMARC1\s*(;|$)")
_TERM = re.compile(r"^([+\-~?]?)([^:=/]*)([:=/]?)(.*)$")
DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")


# ---------------------------------------------------------------------------
# DNS layer
# ---------------------------------------------------------------------------

class DNSResult:
    """status: ok | nodata | nxdomain | error (error is never cached)."""

    def __init__(self, status, records=(), error=None):
        self.status = status
        self.records = tuple(records)
        self.error = error

    @property
    def void(self):
        return self.status in ("nxdomain", "nodata")


def _txt_to_str(rdata):
    try:
        return b"".join(rdata.strings).decode("utf-8", errors="replace")
    except Exception:
        return rdata.to_text().strip('"')


class Resolver:
    """Thread-safe caching resolver shared by all lookups of a run."""

    def __init__(self, nameserver=None, timeout=DEFAULT_TIMEOUT):
        self.nameserver = nameserver
        self.timeout = timeout
        self._resolver = dns.resolver.Resolver()
        if nameserver:
            self._resolver.nameservers = [nameserver]
        self._resolver.timeout = timeout
        self._resolver.lifetime = timeout
        self._cache = {}
        self._lock = threading.Lock()

    @property
    def nameservers(self):
        return list(self._resolver.nameservers)

    def query(self, name, rdtype):
        key = (name.lower().rstrip("."), rdtype)
        with self._lock:
            if key in self._cache:
                return self._cache[key]
        result = self._query(key[0], rdtype)
        if result.status != "error":
            with self._lock:
                self._cache[key] = result
        return result

    def txt(self, name):
        return self.query(name, "TXT")

    def _query(self, name, rdtype):
        result = None
        for attempt in range(DNS_RETRIES):
            result = self._attempt(name, rdtype)
            if result.status != "error":
                break
            if attempt < DNS_RETRIES - 1:
                time.sleep(0.5 * (attempt + 1))  # transient failure (timeout/SERVFAIL)
        return result

    def _attempt(self, name, rdtype):
        try:
            answer = self._resolver.resolve(name, rdtype, raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            return DNSResult("nxdomain")
        except dns.exception.DNSException as exc:
            return DNSResult("error", error=type(exc).__name__)
        if answer.rrset is None:
            return DNSResult("nodata")
        if rdtype == "TXT":
            records = [_txt_to_str(r) for r in answer.rrset]
        else:
            records = [r.to_text() for r in answer.rrset]
        return DNSResult("ok", records)


# ---------------------------------------------------------------------------
# Domain helpers
# ---------------------------------------------------------------------------

def normalize_scope_line(raw):
    """'https://Example.com/x' / ' пример.рф # note' -> 'example.com' or None.

    Returns (domain, error). error is a short reason when the line cannot be used.
    """
    value = raw.split("#", 1)[0].strip().lower()
    if not value:
        return None, None
    if "://" in value:
        value = urlparse(value).hostname or value
    value = value.split("/", 1)[0].split("@")[-1].split(":", 1)[0]
    value = value.strip().rstrip(".")
    if not value:
        return None, None
    if not value.isascii():
        try:
            value = value.encode("idna").decode("ascii")
        except UnicodeError:
            return None, "not a valid IDN domain"
    if not DOMAIN_RE.match(value):
        return None, "not a valid domain name"
    return value, None


def registered_domain(name):
    """Registrable domain with a built-in multi-suffix list ('' for public suffixes)."""
    labels = name.lower().rstrip(".").split(".")
    if len(labels) < 2:
        return ""
    if ".".join(labels[-2:]) in MULTI_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


# ---------------------------------------------------------------------------
# SPF analysis
# ---------------------------------------------------------------------------

def is_spf_record(txt):
    return bool(_SPF_VERSION.match(txt.strip()))


def parse_spf_terms(record):
    """Mechanisms default to '+' qualifier (RFC 7208 4.6.2)."""
    terms = []
    for token in record.split()[1:]:
        qualifier, name, sep, value = _TERM.match(token).groups()
        if sep == "=":
            terms.append({"qualifier": None, "name": name.lower(), "value": value, "modifier": True})
        else:
            terms.append({
                "qualifier": qualifier or "+",
                "name": name.lower(),
                "value": value if sep == ":" else "",
                "modifier": False,
            })
    return terms


class SPFAnalysis:
    """Evaluates an SPF record the way a receiver would, without an IP."""

    def __init__(self, domain, resolver):
        self.domain = domain
        self.resolver = resolver
        self.record = None
        self.state = "nospf"
        self.all_mechanism = None
        self.dns_lookups = 0
        self.void_lookups = 0
        self.errors = []
        self.warnings = []
        self.dangling_includes = []
        self.permissive_includes = []
        self.broad_ip_ranges = []
        self.lookup_error = False
        self.pass_blockers = False

        self._fetch()
        if self.record:
            self.all_mechanism = self._walk(domain, self.record, 0, {domain})
            self.state = self.all_mechanism or "noall"
            if self.dns_lookups > LOOKUP_LIMIT:
                self.errors.append(f"{self.dns_lookups} DNS-querying terms (limit {LOOKUP_LIMIT})")
            if self.void_lookups > VOID_LOOKUP_LIMIT:
                self.errors.append(f"{self.void_lookups} void lookups (limit {VOID_LOOKUP_LIMIT})")

        self.validation = validate_spf(domain, resolver)
        self.warnings.extend(self.validation.get("warnings", []))
        if self.validation.get("dns_errors"):
            self.lookup_error = True
        if self.record and not self.validation.get("valid"):
            error = self.validation.get("error", "Invalid SPF")
            if error not in self.errors:
                self.errors.append(error)

    def _fetch(self):
        result = self.resolver.txt(self.domain)
        if result.status == "error":
            self.lookup_error = True
            self.warnings.append(
                f"SPF lookup for {self.domain} failed ({result.error}): UNKNOWN"
            )
            return
        records = [r.strip() for r in result.records if is_spf_record(r)]
        if len(records) > 1:
            self.errors.append(f"{len(records)} SPF records published (only one allowed)")
        self.record = records[0] if records else None

    def _walk(self, domain, record, depth, stack, allow_pass=True):
        all_mechanism = None
        redirect = None
        for term in parse_spf_terms(record):
            if not all_mechanism and not term["modifier"] and term["name"] != "all" and term["qualifier"] != "+":
                self.pass_blockers = True
            if term["modifier"]:
                if term["name"] == "redirect":
                    redirect = term["value"]
            elif term["name"] not in SPF_KNOWN_MECHANISMS:
                self.errors.append(f"unknown mechanism '{term['name']}' in SPF for {domain}")
            elif all_mechanism:
                continue
            elif term["name"] in ("ip4", "ip6") and not term["value"]:
                self.errors.append(f"'{term['name']}' without an address in SPF for {domain}")
            elif term["name"] in ("ip4", "ip6"):
                try:
                    network = ipaddress.ip_network(term["value"], strict=False)
                    if network.version != (4 if term["name"] == "ip4" else 6):
                        raise ValueError("address family mismatch")
                except ValueError:
                    self.errors.append(f"invalid {term['name']} network: {term['value']}")
                else:
                    if allow_pass and term["qualifier"] == "+":
                        self._check_broad_range(term)
            elif term["name"] == "all":
                all_mechanism = f"{term['qualifier']}all"
            elif term["name"] in SPF_DNS_MECHANISMS:
                self.dns_lookups += 1
                if term["name"] == "ptr":
                    self.warnings.append(f"deprecated 'ptr' mechanism in SPF for {domain}")
                if term["name"] == "include":
                    self._follow(term["value"], "include", depth, stack,
                                 allow_pass and term["qualifier"] == "+")

        if redirect and all_mechanism is None:
            self.dns_lookups += 1
            all_mechanism = self._follow(redirect, "redirect", depth, stack, allow_pass)
        return all_mechanism

    def _check_broad_range(self, term):
        """ip4:0.0.0.0/0-style records authorize huge networks, not real servers."""
        value = term["value"]
        if "/" in value:
            try:
                prefix = int(value.rsplit("/", 1)[1])
            except ValueError:
                return
            limit = 8 if term["name"] == "ip4" else 32
            if prefix <= limit and value not in self.broad_ip_ranges:
                self.broad_ip_ranges.append(f"{term['name']}:{value}")
                self.warnings.append(
                    f"very broad {term['name']}:{value} in SPF for {self.domain} "
                    f"({'the whole internet' if prefix == 0 else 'millions of hosts'} are authorized)"
                )

    def _follow(self, target, kind, depth, stack, allow_pass=True):
        if not target:
            self.errors.append(f"{kind} without a domain in SPF")
            return None
        if "%" in target:
            self.lookup_error = True
            self.warnings.append(f"{kind}:{target}: unsupported macros")
            return None
        target = target.lower().rstrip(".")
        if target in stack:
            self.errors.append(f"{kind} loop via {target}")
            return None
        if depth >= MAX_DEPTH:
            self.errors.append("SPF recursion limit exceeded")
            return None

        result = self.resolver.txt(target)
        if result.status == "error":
            self.lookup_error = True
            self.warnings.append(f"{kind}:{target} lookup failed ({result.error})")
            return None
        records = [r.strip() for r in result.records if is_spf_record(r)]
        if not records:
            if result.void:
                self.void_lookups += 1
            if result.status == "nxdomain":
                self._check_dangling(target)
            self.errors.append(f"{kind}:{target} has no SPF record")
            return None
        if len(records) > 1:
            self.errors.append(f"{len(records)} SPF records at {target}")
        all_mechanism = self._walk(target, records[0], depth + 1, stack | {target}, allow_pass)
        if all_mechanism == "+all" and allow_pass:
            # include matches only on 'pass'; a target with +all makes SPF pass for anyone
            self.permissive_includes.append(target)
        return all_mechanism

    def _check_dangling(self, target):
        registered = registered_domain(target)
        if registered and self.resolver.query(registered, "NS").status == "nxdomain":
            if registered not in self.dangling_includes:
                self.dangling_includes.append(registered)


# ---------------------------------------------------------------------------
# DMARC analysis (RFC 7489 DNS tree walk)
# ---------------------------------------------------------------------------

def parse_dmarc_tags(record):
    """Tags matched by name, never by substring (so 'sp=' is not read as 'p=')."""
    tags = {}
    for part in record.split(";"):
        key, sep, value = part.partition("=")
        key = key.strip().lower()
        if sep and key and key not in tags:
            tags[key] = value.strip()
    return tags


def is_dmarc_record(txt):
    return bool(_DMARC_VERSION.match(txt.strip()))


def dmarc_tree_walk_targets(domain):
    labels = domain.split(".")
    rest = labels[1:] if len(labels) <= 8 else labels[-7:]
    targets = [domain]
    while rest:
        targets.append(".".join(rest))
        rest = rest[1:]
    return targets


class DMARCAnalysis:
    POLICIES = ("none", "quarantine", "reject")

    def __init__(self, domain, resolver):
        self.domain = domain
        self.resolver = resolver
        self.record = None
        self.record_domain = None
        self.inherited = False
        self.policy = None
        self.sp = None
        self.np = None
        self.pct = None
        self.aspf = None
        self.adkim = None
        self.t = None
        self.rua = None
        self.ruf = None
        self.domain_exists = True
        self.lookup_error = False
        self.warnings = []

        self._fetch()
        if self.record:
            raw_tags = parse_dmarc_tags(self.record)
            normalized = {name: entry['value'] for name, entry in self.validation.get('tags', {}).items()
                          if name not in ('pct', 'rf', 'ri', 'rua', 'ruf')}
            for name in ('rua', 'ruf'):
                if name in raw_tags:
                    normalized[name] = raw_tags[name]
            self._load_tags(normalized)
            self.inherited = self.record_domain not in (None, self.domain)
            if self.inherited:
                self.domain_exists = self.resolver.query(self.domain, "A").status != "nxdomain"

    def _fetch(self):
        self.validation = validate_dmarc(self.domain, self.resolver)
        self.record = self.validation.get("record")
        self.record_domain = self.validation.get("location")
        self.warnings.extend(self.validation.get("warnings", []))
        self.lookup_error = bool(self.validation.get("dns_errors"))
        if self.record and not self.validation.get("valid"):
            self.lookup_error = True
        if self.validation.get("error"):
            self.warnings.append(self.validation["error"])

    def _load_tags(self, tags):
        self.rua, self.ruf = tags.get("rua"), tags.get("ruf")
        self.t = tags.get("t", "").lower() or None

        policy, sp, np = (tags.get(tag, "").lower() or None for tag in ("p", "sp", "np"))
        if policy not in self.POLICIES or {sp, np} - {None, *self.POLICIES}:
            # receivers treat an invalid record as p=none (if reports requested), else ignore it
            policy = "none" if self.rua else None
            sp = np = None
            self.warnings.append("invalid p/sp/np tag")
        self.policy, self.sp, self.np = policy, sp, np

        pct = tags.get("pct")
        if pct is not None and not (pct.isdigit() and int(pct) <= 100):
            self.warnings.append(f"invalid pct={pct!r} ignored")
            pct = None
        self.pct = pct

        aspf = tags.get("aspf", "").lower() or None
        if aspf not in (None, "r", "s"):
            self.warnings.append(f"invalid aspf={aspf!r}. Default: r")
            aspf = None
        self.aspf = aspf

        adkim = tags.get("adkim", "").lower() or None
        if adkim not in (None, "r", "s"):
            self.warnings.append(f"invalid adkim={adkim!r}. Default: r")
            adkim = None
        self.adkim = adkim


# ---------------------------------------------------------------------------
# Spoofability matrix evaluation
# ---------------------------------------------------------------------------

def testing_mode(policy, t):
    """RFC 9989 t=y: failing mail gets the next weaker policy."""
    if t == "y":
        return {"reject": "quarantine", "quarantine": "none"}.get(policy, policy)
    return policy


def table_lookup(spf_state, p=None, sp=None, aspf=None):
    if p is None:
        return TABLE.get((spf_state, None), UNKNOWN)
    key = (spf_state, (p, sp, aspf))
    if key not in TABLE:
        key = (spf_state, (p, sp or p, aspf))
    return TABLE.get(key, UNKNOWN)


def table_code(spf_state, dmarc):
    if dmarc.policy is None:
        return table_lookup(spf_state)

    sp = dmarc.sp
    if dmarc.inherited and dmarc.np and not dmarc.domain_exists:
        sp = dmarc.np
    p = testing_mode(dmarc.policy, dmarc.t)
    sp = testing_mode(sp, dmarc.t)

    # pct < 100 under quarantine lets unsampled mail through (it gets p=none)
    policy = (sp or p) if dmarc.inherited else p
    if policy == "quarantine" and dmarc.pct is not None and int(dmarc.pct) < 100:
        return PARTIAL

    code = table_lookup(spf_state, p, sp, dmarc.aspf)
    return AS_SUBDOMAIN[code] if dmarc.inherited else code


def spoofability(spf, dmarc):
    """Master-table code for mail From: the analyzed domain."""
    if dmarc.lookup_error:
        return UNKNOWN
    if spf.errors or spf.lookup_error:
        return UNKNOWN
    if dmarc.inherited:
        policy = dmarc.np if dmarc.np and not dmarc.domain_exists else dmarc.sp
        policy = testing_mode(policy or dmarc.policy, dmarc.t)
        code = table_lookup(spf.state, policy, policy, dmarc.aspf)
        if policy == "quarantine" and dmarc.pct is not None and int(dmarc.pct) < 100:
            code = PARTIAL
    else:
        code = table_code(spf.state, dmarc)
    return UNKNOWN if spf.lookup_error and code != 8 else code


def selftest():
    """Validate the ported matrix: known anchors plus full combo coverage."""
    anchors = [
        (("-all", None), 0),
        (("+all", None), 4),
        (("~all", None), 0),
        (("noall", None), 0),
        (("?all", None), 0),
        (("nospf", None), 0),
        (("-all", ("none", None, None)), 4),
        (("-all", ("quarantine", None, None)), 8),
        (("-all", ("reject", None, None)), 8),
        (("~all", ("none", None, None)), 0),
        (("+all", ("none", "none", "r")), 4),
        (("nospf", ("reject", None, None)), 8),
        (("nospf", ("quarantine", "none", "r")), 8),
    ]
    failed = []
    for key, expected in anchors:
        got = TABLE.get(key, UNKNOWN)
        if got != expected:
            failed.append(f"anchor {key}: expected {expected}, got {got}")
    for state in ("nospf", "noall", "-all", "~all", "?all", "+all"):
        for p in ("none", "quarantine", "reject"):
            for sp in (None, "none", "quarantine", "reject"):
                for aspf in (None, "r", "s"):
                    if table_lookup(state, p, sp, aspf) == UNKNOWN:
                        failed.append(f"missing combo: {state} p={p} sp={sp} aspf={aspf}")
    if failed:
        for line in failed:
            print(f"SELFTEST FAILED: {line}")
        return 1
    print(f"selftest OK: {len(anchors)} anchors + every realistic matrix combo resolves")
    return 0


# ---------------------------------------------------------------------------
# DKIM / MX
# ---------------------------------------------------------------------------

def analyze_dkim_key(key):
    return inspect_dkim_key(key)


def check_dkim(domain, resolver, selectors):
    selectors = list(DKIM_SELECTORS) if selectors is None else selectors
    found = []
    query_errors = 0
    for selector in selectors:
        result = resolver.txt(f"{selector}._domainkey.{domain}")
        if result.status == "error":
            query_errors += 1
            continue
        if result.status == "ok":
            keys = [record for record in result.records if re.search(r"(?:^|;)\s*p\s*=", record)]
            if keys:
                key = keys[0]
                entry = {"selector": selector, "value": key[:160]}
                entry.update(analyze_dkim_key(key))
                if len(keys) > 1:
                    entry.update(key_status="INVALID", bits=None, flags=["Multiple DKIM keys"])
                found.append(entry)
    return {"checked": len(selectors), "found": found, "query_errors": query_errors}


def dkim_status(dkim):
    if dkim is None:
        return "SKIPPED"
    if dkim.get("query_errors"):
        return "PARTIAL" if dkim.get("found") else "ERROR"
    return "FOUND" if dkim.get("found") else "NOT_FOUND"


def check_mx(domain, resolver):
    result = resolver.query(domain, "MX")
    if result.status != "ok":
        return {"hosts": [], "error": result.error or result.status}
    hosts = []
    for record in result.records:
        parts = record.split()
        host = parts[-1].rstrip(".").lower() if parts else ""
        if host:
            hosts.append(host)
    return {"hosts": sorted(set(hosts)), "error": None}


def check_cname_takeover(name, resolver, target_rdtype="TXT"):
    """Return the CNAME target when name CNAMEs to something that does not resolve.

    A dead CNAME target is takeoverable: the attacker registers it and controls
    the records under `name` (e.g. their own DMARC or DKIM keys).
    """
    result = resolver.query(name, "CNAME")
    if result.status != "ok" or not result.records:
        return None
    target = result.records[0].rstrip(".").lower()
    target_lookup = resolver.query(target, target_rdtype)
    if target_lookup.status == "nxdomain":
        return target
    return None


def dkim_archive_selectors(domain, timeout=10):
    """Selectors other senders were seen using for this domain (archive.prove.email).

    Removed stale entries only after DNS confirms the record exists.
    """
    try:
        import requests
        response = requests.get(
            "https://archive.prove.email/api/key",
            params={"domain": domain},
            headers={"accept": "application/json"},
            timeout=timeout,
        )
        if response.status_code != 200:
            return []
        data = response.json()
        if isinstance(data, list):
            return sorted({entry.get("selector").lower() for entry in data
                           if isinstance(entry, dict) and entry.get("selector")})
    except Exception:  # noqa: BLE001 - archive is best-effort help, never a failure
        pass
    return []


def safe_check_cname_takeover(name, resolver):
    try:
        return check_cname_takeover(name, resolver)
    except Exception:  # noqa: BLE001 - probe failure must not break analysis
        return None


# ---------------------------------------------------------------------------
# Risk score
# ---------------------------------------------------------------------------

def risk_score(spf, dmarc, nxdomain, bypass=False, dkim_takeover=None, dmarc_takeover=None):
    factors = []

    def add(delta, reason):
        factors.append({"delta": delta, "reason": reason})

    if nxdomain:
        add(15, "NXDOMAIN")
    if dmarc.record is None and not dmarc.lookup_error:
        add(35, "no DMARC record - no policy for spoofed mail")
    elif dmarc.policy == "none":
        add(25, "DMARC p=none")
    elif dmarc.policy == "quarantine":
        add(10, "DMARC p=quarantine")
    if dmarc.pct is not None and int(dmarc.pct) < 100:
        add(8, f"DMARC pct={dmarc.pct} - policy applied to part of the mail only")
    if dmarc.policy in ("reject", "quarantine") and dmarc.sp == "none":
        add(6, "DMARC sp=none - subdomains left unprotected")
    if dmarc.t == "y":
        add(5, "DMARC t=y - testing mode weakens enforcement")

    spf_state_penalty = {"nospf": 15, "+all": 30, "?all": 20, "noall": 10, "~all": 8}
    if spf.record is None and spf.lookup_error:
        pass  # lookup failed: "no SPF" is not a confirmed finding
    else:
        penalty = spf_state_penalty.get(spf.state)
        if penalty:
            label = {"nospf": "no SPF record", "+all": "SPF +all (any sender authorized)",
                     "?all": "SPF ?all (neutral, does not block)", "noall": "SPF without 'all' mechanism",
                     "~all": "SPF ~all (softfail)"}[spf.state]
            add(penalty, label)
    if spf.dns_lookups > LOOKUP_LIMIT:
        add(8, f"SPF {spf.dns_lookups} DNS lookups (>10, receivers may return permerror)")
    if spf.void_lookups > VOID_LOOKUP_LIMIT:
        add(4, f"SPF {spf.void_lookups} void lookups (>2)")
    if any("SPF records published" in e for e in spf.errors):
        add(6, "multiple SPF records published (permerror)")
    if spf.dangling_includes:
        add(20, f"SPF include NXDOMAIN: {', '.join(spf.dangling_includes)}")
    if bypass:
        add(30, "SPF authorizes arbitrary senders")
    if spf.broad_ip_ranges:
        add(15, f"very broad network ranges authorized in SPF: {', '.join(spf.broad_ip_ranges)}")
    if dmarc_takeover:
        add(30, f"Dangling DMARC CNAME: {dmarc_takeover}")
    if dkim_takeover:
        add(25, f"Dangling DKIM CNAME: {dkim_takeover}")

    return min(100, sum(f["delta"] for f in factors)), factors


# ---------------------------------------------------------------------------
# Checklist
# ---------------------------------------------------------------------------

def build_checklist(domain, spf, dmarc, dkim, mx, nxdomain, code, sub_code, domain_status="resolved",
                    bypass=None, dmarc_takeover=None, dkim_takeover=None):
    items = []

    def add(section, status, text):
        items.append({"section": section, "status": status, "text": text})

    # --- domain ---
    if nxdomain:
        add("DOMAIN", "FAIL", "NXDOMAIN")
    elif domain_status == "unknown":
        add("DOMAIN", "WARN", "domain existence unknown (DNS lookup failed)")
    else:
        add("DOMAIN", "PASS", "domain exists in DNS")

    # --- SPF ---
    if spf.record:
        add("SPF", "PASS", f"SPF record present: {spf.record}")
    elif spf.lookup_error:
        add("SPF", "WARN", f"SPF lookup for {domain} failed (DNS error): UNKNOWN")
    else:
        add("SPF", "FAIL", f"no SPF record on {domain}: NOT_FOUND")

    all_map = {
        "-all": ("PASS", "SPF -all (fail): unauthorized senders are rejected"),
        "~all": ("WARN", "SPF ~all (softfail): many filters only raise the spam score and accept softfailed mail"),
        "?all": ("FAIL", "SPF ?all (neutral): SPF effectively does not block spoofed mail"),
        "+all": ("FAIL", "SPF +all: ANY server on the internet is authorized to send as this domain"),
        "noall": ("WARN", "SPF record has no 'all' mechanism - evaluation ends without a disposition"),
    }
    if spf.record:
        status, text = all_map.get(spf.all_mechanism or "noall", ("WARN", f"unusual 'all' state: {spf.all_mechanism}"))
        add("SPF", status, text)

    multi = [e for e in spf.errors if "SPF records published" in e]
    if multi:
        add("SPF", "FAIL", f"{multi[0]} - receivers return permerror and may skip SPF entirely")
    if spf.dns_lookups:
        if spf.dns_lookups > LOOKUP_LIMIT:
            add("SPF", "FAIL", f"{spf.dns_lookups} DNS lookups (RFC 7208 limit is {LOOKUP_LIMIT}): PERMERROR")
        else:
            add("SPF", "PASS", f"DNS lookups: {spf.dns_lookups}/{LOOKUP_LIMIT} (RFC 7208 limit)")
    if spf.void_lookups > VOID_LOOKUP_LIMIT:
        add("SPF", "WARN", f"{spf.void_lookups} void lookups (limit {VOID_LOOKUP_LIMIT}) - counts toward permerror")
    for target in spf.dangling_includes:
        add("SPF", "FAIL", f"SPF include NXDOMAIN: {target}")
    for target in spf.permissive_includes:
        add("SPF", "FAIL", f"Permissive include: {target}")
    for rng in spf.broad_ip_ranges:
        add("SPF", "FAIL", f"Broad SPF range: {rng}")
    for err in spf.errors:
        if "SPF records published" in err:
            continue
        add("SPF", "WARN", f"permerror: {err}")
    for warn in spf.warnings:
        add("SPF", "WARN", warn)

    # --- DMARC ---
    if dmarc.record:
        add("DMARC", "PASS", f"DMARC record present: {dmarc.record}")
        if dmarc.record_domain and dmarc.record_domain != domain:
            add("DMARC", "INFO", f"record inherited from _dmarc.{dmarc.record_domain}")
        policy_status = {"reject": "PASS", "quarantine": "WARN", "none": "FAIL"}.get(dmarc.policy, "WARN")
        policy_text = {
            "reject": "p=reject",
            "quarantine": "p=quarantine",
            "none": "p=none: monitoring",
        }.get(dmarc.policy, "policy tag missing/invalid - effective p=none")
        add("DMARC", policy_status, policy_text)

        if dmarc.sp:
            sp_status = "WARN" if dmarc.sp == "none" else "PASS"
            add("DMARC", sp_status, f"subdomain policy sp={dmarc.sp}" + (" - subdomains are unprotected" if dmarc.sp == "none" else ""))
        else:
            add("DMARC", "INFO", f"sp tag not set - subdomain policy defaults to p ({dmarc.policy or 'none'})")

        if dmarc.pct is not None and int(dmarc.pct) < 100:
            add("DMARC", "WARN", f"pct={dmarc.pct} - policy applies to only {dmarc.pct}% of mail")
        elif dmarc.pct is None:
            add("DMARC", "INFO", "pct not set (defaults to 100%)")

        if dmarc.t == "y":
            add("DMARC", "WARN", "t=y - testing mode: failing mail is downgraded to the next weaker policy")

        if dmarc.aspf == "s":
            add("DMARC", "INFO", "aspf=s - strict SPF alignment")
        elif dmarc.aspf == "r":
            add("DMARC", "INFO", "aspf=r - relaxed SPF alignment (default)")
        if dmarc.adkim == "s":
            add("DMARC", "INFO", "adkim=s - strict DKIM alignment")
        elif dmarc.adkim == "r":
            add("DMARC", "INFO", "adkim=r - relaxed DKIM alignment (default)")

        if dmarc.rua:
            add("DMARC", "INFO", f"aggregate reports (rua): {dmarc.rua}")
        if dmarc.ruf:
            add("DMARC", "INFO", f"forensic reports (ruf): {dmarc.ruf}")
    else:
        if dmarc.lookup_error:
            add("DMARC", "WARN", f"DMARC lookup failed (DNS error) while walking _dmarc.{domain} and parents: UNKNOWN")
        else:
            add("DMARC", "FAIL", f"no DMARC record at _dmarc.{domain} (or parents): NOT_FOUND")

    for warn in dmarc.warnings:
        add("DMARC", "WARN", warn)
    if dmarc_takeover:
        add("DMARC", "FAIL",
            f"Dangling CNAME: _dmarc.{domain} -> {dmarc_takeover}")

    # --- DKIM ---
    if dkim:
        found = dkim["found"]
        names = ", ".join(f["selector"] for f in found)
        if found:
            add("DKIM", "INFO", f"{len(found)}/{dkim['checked']} common selectors published: {names}")
            for f in found:
                bits = f" ({f['bits']} bits)" if f.get("bits") else ""
                add("DKIM", "INFO", f"{f['selector']}._domainkey -> {f['value']}{bits}")
                for flag in f.get("flags", []):
                    add("DKIM", "WARN", f"{f['selector']}: {flag}")
        else:
            add("DKIM", "INFO", f"{dkim_status(dkim)}: 0/{dkim['checked']} selectors")
        if dkim.get("archive_selectors"):
            add("DKIM", "INFO", f"Archive selectors checked: {len(dkim['archive_selectors'])}")
        if dkim["query_errors"]:
            add("DKIM", "WARN", f"{dkim['query_errors']} selector lookups failed (DNS errors)")
    if dkim_takeover:
        add("DKIM", "FAIL",
            f"Dangling CNAME: _domainkey.{domain} -> {dkim_takeover}")

    # --- MX ---
    if mx:
        if mx["hosts"]:
            add("MX", "INFO", f"MX: {', '.join(mx['hosts'])} - domain accepts mail")
        else:
            add("MX", "INFO", "MX NOT_FOUND" + (f" ({mx['error']})" if mx.get("error") else ""))

    # --- verdict ---
    if bypass:
        add("VERDICT", "FAIL", f"{bypass} - verdict overridden to SPOOFABLE (matrix code {code})")
    add("VERDICT", "INFO", f"domain From: {MESSAGES[code].lower()} (matrix code {code})")
    add("VERDICT", "INFO", f"subdomain From: {MESSAGES[sub_code].lower()} (matrix code {sub_code})")

    return items


# ---------------------------------------------------------------------------
# Per-domain analysis
# ---------------------------------------------------------------------------

def analyze_domain(domain, resolver, selectors=None, with_dkim=True, use_archive=False):
    domain_txt = resolver.txt(domain)
    nxdomain = domain_txt.status == "nxdomain"
    domain_status = "nxdomain" if nxdomain else ("unknown" if domain_txt.status == "error" else "resolved")

    spf = SPFAnalysis(domain, resolver)
    dmarc = DMARCAnalysis(domain, resolver)

    # SPF belongs to the MAIL FROM identity; it is never inherited with DMARC.
    spf_for_table = spf

    code = spoofability(spf_for_table, dmarc)
    sub_code = AS_SUBDOMAIN[code] if not dmarc.inherited else code

    # Positive include chains, +all and /0 networks can authorize arbitrary
    # senders. Exact envelope/header domain alignment also satisfies aspf=s.
    bypass_sources = list(spf.permissive_includes)
    if spf.state == "+all":
        bypass_sources.append("+all")
    bypass_sources.extend(r for r in spf.broad_ip_ranges
                          if ipaddress.ip_network(r.split(":", 1)[1], strict=False).prefixlen == 0)
    bypass = bool(bypass_sources) and not (spf.errors or spf.lookup_error or spf.pass_blockers)
    if bypass:
        # An attacker can use the exact same envelope and header domain, even
        # with strict alignment. Keep matrix codes and exported verdicts consistent.
        code = 0
        sub_code = 0 if dmarc.aspf != "s" and not dmarc.lookup_error else UNKNOWN

    dmarc_takeover = None
    dkim_takeover = None
    if not nxdomain:
        # _dmarc CNAME dangling: attacker restores the record from their registrar.
        if not dmarc.record:
            dmarc_takeover = safe_check_cname_takeover(f"_dmarc.{domain}", resolver)
        # wildcard CNAME under _domainkey dangling: attacker signs valid DKIM.
        dkim_takeover = safe_check_cname_takeover(f"takeover-probe._domainkey.{domain}", resolver)

    archive_selectors = []
    if with_dkim and use_archive and not nxdomain:
        archive_selectors = dkim_archive_selectors(domain)
    effective_selectors = selectors
    if archive_selectors and with_dkim:
        selectors = list(selectors or []) + [s for s in archive_selectors if s not in (selectors or [])]
        effective_selectors = selectors

    dkim = check_dkim(domain, resolver, effective_selectors) if with_dkim else None
    if dkim is not None:
        dkim["archive_selectors"] = archive_selectors
    if dkim is not None:
        dkim["status"] = dkim_status(dkim)
    mx = check_mx(domain, resolver)
    risk, factors = risk_score(spf, dmarc, nxdomain, bypass, dkim_takeover, dmarc_takeover)

    if VERDICTS[code] == "UNKNOWN":
        risk, factors = None, []  # DNS errors: a numeric risk would be a guess

    bypass_message = None
    if bypass:
        bypass_message = (
            f"SPF authorizes arbitrary senders via {', '.join(bypass_sources)} - "
            f"with aligned mail that is a DMARC pass, so p={dmarc.policy or 'none'} never applies"
        )

    checklist = build_checklist(domain, spf, dmarc, dkim, mx, nxdomain, code, sub_code, domain_status,
                                bypass=bypass_message, dmarc_takeover=dmarc_takeover, dkim_takeover=dkim_takeover)

    verdict = "SPOOFABLE" if bypass else VERDICTS[code]
    message = bypass_message or MESSAGES[code]
    if bypass and VERDICTS[code] in ("not_spoofable", "unknown"):
        message += f" (matrix verdict: {MESSAGES[code].lower()})"

    return {
        "domain": domain,
        "nxdomain": nxdomain,
        "domain_status": domain_status,
        "verdict": verdict,
        "code": code,
        "message": message,
        "subdomain_verdict": VERDICTS[sub_code],
        "subdomain_code": sub_code,
        "subdomain_message": MESSAGES[sub_code],
        "spf_bypass": bypass_sources if bypass else [],
        "risk": risk,
        "risk_factors": factors,
        "spf": {
            "record": spf.record,
            "state": spf.state,
            "all_mechanism": spf.all_mechanism,
            "dns_lookups": spf.dns_lookups,
            "void_lookups": spf.void_lookups,
            "errors": spf.errors,
            "warnings": spf.warnings,
            "dangling_includes": spf.dangling_includes,
            "permissive_includes": spf.permissive_includes,
            "broad_ip_ranges": spf.broad_ip_ranges,
            "lookup_error": spf.lookup_error,
            "validation": spf.validation,
        },
        "dmarc": {
            "record": dmarc.record,
            "record_domain": dmarc.record_domain,
            "inherited": dmarc.inherited,
            "policy": dmarc.policy,
            "sp": dmarc.sp,
            "pct": dmarc.pct,
            "aspf": dmarc.aspf,
            "adkim": dmarc.adkim,
            "t": dmarc.t,
            "rua": dmarc.rua,
            "ruf": dmarc.ruf,
            "warnings": dmarc.warnings,
            "lookup_error": dmarc.lookup_error,
            "validation": dmarc.validation,
        },
        "dkim": dkim,
        "mx": mx,
        "checklist": checklist,
        "fail_count": sum(1 for i in checklist if i["status"] == "FAIL"),
        "warn_count": sum(1 for i in checklist if i["status"] == "WARN"),
        "error": None,
    }


def safe_analyze(domain, resolver, selectors, with_dkim, use_archive=False):
    try:
        return analyze_domain(domain, resolver, selectors=selectors, with_dkim=with_dkim, use_archive=use_archive)
    except Exception as exc:  # noqa: BLE001 - one bad domain must not stall a scope run
        return {
            "domain": domain,
            "nxdomain": None,
            "domain_status": "unknown",
            "verdict": "UNKNOWN",
            "code": 9,
            "message": f"Unable to determine ({type(exc).__name__}: {exc})",
            "subdomain_verdict": "UNKNOWN",
            "subdomain_code": 9,
            "subdomain_message": MESSAGES[9],
            "risk": None,
            "risk_factors": [],
            "spf_bypass": [],
            "spf": {}, "dmarc": {}, "dkim": None, "mx": {},
            "checklist": [{"section": "DOMAIN", "status": "FAIL", "text": f"{type(exc).__name__}: {exc}"}],
            "fail_count": 1,
            "warn_count": 0,
            "error": f"{type(exc).__name__}: {exc}",
        }


def rank_results(results):
    return sorted(
        results,
        key=lambda r: (
            VERDICT_ORDER.get(r["verdict"], 9),
            -(r["risk"] if r["risk"] is not None else 0),
            0 if r.get("nxdomain") else 1,  # FREE domains first within a group
            r["domain"],
        ),
    )


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

STATUS_STYLE = {"PASS": "32", "FAIL": "31", "WARN": "33", "INFO": "36"}
VERDICT_STYLE = {"SPOOFABLE": "31", "POSSIBLE": "33", "NOT_SPOOFABLE": "32", "UNKNOWN": "33"}


def color(text, code):
    if not USE_COLOR:
        return text
    return f"\x1b[{code}m{text}\x1b[0m"


def status_tag(status):
    return color(f"[{status}]", STATUS_STYLE.get(status, "0"))


def verdict_tag(verdict):
    label = verdict.replace("_", " ")
    return color(label, VERDICT_STYLE.get(verdict, "0"))


def risk_cell(item):
    """'—' when the verdict is UNKNOWN: a numeric risk would be a guess."""
    return "—" if item.get("risk") is None else str(item["risk"])


def dmarc_cell(dmarc):
    """'-' for no record, 'none' for p=none, '?' for a failed lookup: all different."""
    if not dmarc.get("record"):
        return "?" if dmarc.get("lookup_error") else "-"
    policy = dmarc.get("policy") or "?"
    pct = dmarc.get("pct")
    if pct is not None and int(pct) < 100:
        return f"{policy} pct={pct}"
    return policy


def reg_cell(item):
    """DNS status, independent of domain registration."""
    if item.get("domain_status") == "unknown":
        return "?"
    return "NXDOMAIN" if item.get("nxdomain") else "OK"


def print_summary_table(results):
    try:
        from rich import box
        from rich.console import Console
        from rich.table import Table
        has_rich = True
    except ImportError:
        has_rich = False

    if has_rich:
        # when piped, rich defaults to width=80 and silently cuts trailing columns
        console = Console(width=None if sys.stdout.isatty() else 200)
        table = Table(box=box.SIMPLE)
        table.add_column("#", style="dim", no_wrap=True)
        table.add_column("Domain", no_wrap=True)
        table.add_column("DNS", no_wrap=True)
        table.add_column("Verdict", no_wrap=True)
        table.add_column("Risk", justify="right")
        table.add_column("SPF", no_wrap=True)
        table.add_column("DMARC", no_wrap=True)
        table.add_column("DKIM", justify="right")
        table.add_column("Subdomain", no_wrap=True)
        table.add_column("F/W", justify="right")

        styles = {"SPOOFABLE": "red", "POSSIBLE": "yellow", "NOT_SPOOFABLE": "green", "UNKNOWN": "yellow"}
        for index, item in enumerate(results, start=1):
            spf = item.get("spf") or {}
            dmarc = item.get("dmarc") or {}
            dkim = item.get("dkim")
            dkim_cell = dkim_status(dkim)
            table.add_row(
                str(index),
                item["domain"],
                reg_cell(item),
                f"[{styles.get(item['verdict'], 'white')}]{item['verdict'].replace('_', ' ')}[/]",
                risk_cell(item),
                spf.get("state", "?"),
                dmarc_cell(dmarc),
                dkim_cell,
                item["subdomain_verdict"].replace("_", " "),
                f"{item['fail_count']}/{item['warn_count']}",
            )
        console.print(table)
        return

    header = f"{'#':>3}  {'Domain':<30} {'DNS':<4} {'Verdict':<15} {'Risk':>4} {'SPF':<7} {'DMARC':<8} {'DKIM':>4} {'Sub':<15} {'F/W':>5}"
    print(header)
    print("-" * len(header))
    for index, item in enumerate(results, start=1):
        spf = item.get("spf") or {}
        dmarc = item.get("dmarc") or {}
        dkim = item.get("dkim")
        dkim_cell = dkim_status(dkim)
        print(
            f"{index:>3}  {item['domain']:<30} {reg_cell(item):<4} {item['verdict'].replace('_', ' '):<15} "
            f"{risk_cell(item):>4} {spf.get('state', '?'):<7} "
            f"{dmarc_cell(dmarc):<8} {dkim_cell:>4} "
            f"{item['subdomain_verdict'].replace('_', ' '):<15} "
            f"{item['fail_count']}/{item['warn_count']:>3}"
        )


def print_details(index, item):
    risk_str = f"risk {item['risk']}/100" if item.get("risk") is not None else "risk n/a (DNS errors)"
    header = f"{index}. {item['domain']}  {verdict_tag(item['verdict'])}  {risk_str}"
    print(header)
    spf = item.get("spf") or {}
    dmarc = item.get("dmarc") or {}
    dkim = item.get("dkim")
    mx = item.get("mx") or {}

    print(f"   verdict   : {item['message']} (code {item['code']})")
    print(f"   subdomain : {item['subdomain_message']} (code {item['subdomain_code']})")
    print(f"   reg       : {'NXDOMAIN' if item.get('nxdomain') else ('unknown (DNS error)' if item.get('domain_status') == 'unknown' else 'DNS OK')}")
    spf_txt = spf.get("record") or ("(lookup failed)" if spf.get("lookup_error") else "(none)")
    print(f"   SPF       : {spf_txt}")
    dmarc_line = dmarc.get("record") or ("(lookup failed)" if dmarc.get("lookup_error") else "(none)")
    if dmarc.get("record_domain") and dmarc["record_domain"] != item["domain"]:
        dmarc_line += f" @ _dmarc.{dmarc['record_domain']}"
    print(f"   DMARC     : {dmarc_line}")
    if dkim is not None:
        names = ", ".join(f["selector"] for f in dkim.get("found", []))
        if not names:
            names = f"none of {dkim.get('checked', 0)} selectors"
        print(f"   DKIM      : {names}")
    if mx.get("hosts"):
        print(f"   MX        : {', '.join(mx['hosts'])}")

    if item["risk_factors"]:
        print("   risk      : " + " | ".join(f"+{f['delta']} {f['reason']}" for f in item["risk_factors"]))

    print("   checklist :")
    current_section = None
    for check in item["checklist"]:
        if check["section"] != current_section:
            current_section = check["section"]
            print(f"     -- {current_section} " + "-" * max(1, 50 - len(current_section)))
        print(f"     {status_tag(check['status'])} {check['text']}")


def print_counts(results):
    counts = {"SPOOFABLE": 0, "POSSIBLE": 0, "NOT_SPOOFABLE": 0, "UNKNOWN": 0}
    for item in results:
        counts[item["verdict"]] = counts.get(item["verdict"], 0) + 1
    print(f"Scope: {len(results)} domains")
    free_count = sum(1 for item in results if item.get("nxdomain"))
    print(
        f"  SPOOFABLE                   : {color(str(counts['SPOOFABLE']), '31')}\n"
        f"  POSSIBLE                    : {color(str(counts['POSSIBLE']), '33')}\n"
        f"  NOT SPOOFABLE               : {color(str(counts['NOT_SPOOFABLE']), '32')}\n"
        f"  UNKNOWN         : {counts['UNKNOWN']}\n"
        f"  NXDOMAIN       : {color(str(free_count), '35') if free_count else 0}"
    )


def print_grouped(results, brief=False):
    print_counts(results)
    print()
    print_summary_table(results)
    if brief:
        return
    current = None
    for index, item in enumerate(results, start=1):
        if item["verdict"] != current:
            current = item["verdict"]
            print()
            print(color(f"=== {VERDICT_LABELS[current]} " + "=" * max(0, 60 - len(VERDICT_LABELS[current])), "1"))
        print()
        print_details(index, item)


def export_csv(results, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "domain", "dns_status", "verdict", "risk", "code", "subdomain_verdict", "subdomain_code",
            "spf_record", "spf_state", "spf_dns_lookups", "spf_dangling_includes",
            "dmarc_record", "dmarc_policy", "dmarc_pct", "dmarc_sp", "dmarc_location",
            "dkim_selectors", "mx_hosts", "fails", "warns", "dkim_status",
        ])
        for item in results:
            spf = item.get("spf") or {}
            dmarc = item.get("dmarc") or {}
            dkim = item.get("dkim")
            mx = item.get("mx") or {}
            writer.writerow([
                item["domain"],
                "NXDOMAIN" if item.get("nxdomain") else ("UNKNOWN" if item.get("domain_status") == "unknown" else "OK"),
                item["verdict"],
                item["risk"],
                item["code"],
                item["subdomain_verdict"],
                item["subdomain_code"],
                spf.get("record") or "",
                spf.get("state") or "",
                spf.get("dns_lookups", ""),
                "; ".join(spf.get("dangling_includes") or []),
                dmarc.get("record") or "",
                dmarc.get("policy") or "",
                dmarc.get("pct") if dmarc.get("pct") is not None else "",
                dmarc.get("sp") or "",
                dmarc.get("record_domain") or "",
                "; ".join(f["selector"] for f in (dkim or {}).get("found", [])),
                "; ".join(mx.get("hosts") or []),
                item["fail_count"],
                item["warn_count"],
                dkim_status(dkim),
            ])


def markdown_text(value):
    """Escape untrusted DNS text, including table separators and inline HTML."""
    value = html.escape(str(value), quote=False).replace("\r\n", "\n").replace("\r", "\n")
    value = re.sub(r"([\\`*_\[\]{}()|#!~])", r"\\\1", value)
    return value.replace("\n", "<br>")


def export_markdown(report, path):
    """Readable UTF-8 report; uses the same results as JSON/CSV, without new queries."""
    labels = {
        "SPOOFABLE": "SPOOFABLE",
        "POSSIBLE": "POSSIBLE",
        "NOT_SPOOFABLE": "NOT_SPOOFABLE",
        "UNKNOWN": "UNKNOWN",
    }
    statuses = {"FAIL": "FAIL", "WARN": "WARN", "PASS": "PASS", "INFO": "INFO"}
    esc = markdown_text
    lines = [
        "# SPOOFCALYPSE", "",
        f"**Checked (UTC):** {esc(report['checked_at'])}  ",
        f"**Domains:** {report['scope']}  ",
        f"**DNS:** {esc(', '.join(report.get('nameservers', [])))}", "",
        "## Summary", "",
        "| Verdict | Domains |", "| --- | ---: |",
    ]
    for verdict, label in labels.items():
        lines.append(f"| {label} | {report['counts'].get(verdict, 0)} |")
    lines += ["", "## Domains", "",
              "| Domain | Verdict | Risk | SPF | DMARC | DKIM | FAIL / WARN |",
              "| --- | --- | ---: | --- | --- | ---: | ---: |"]
    for index, item in enumerate(report['results'], 1):
        spf, dmarc, dkim = item.get('spf') or {}, item.get('dmarc') or {}, item.get('dkim')
        dkim_text = dkim_status(dkim)
        risk = "N/A" if item.get('risk') is None else str(item['risk'])
        lines.append(
            f"| [{esc(item['domain'])}](#domain-{index}) | {labels.get(item['verdict'], esc(item['verdict']))} "
            f"| {risk} | {esc('DNS ERROR' if spf.get('lookup_error') else spf.get('state', '—'))} "
            f"| {esc(dmarc_cell(dmarc))} | {dkim_text} | {item.get('fail_count', 0)} / {item.get('warn_count', 0)} |")
    lines += ["", "## Details", ""]
    for index, item in enumerate(report['results'], 1):
        lines += [f'<a id="domain-{index}"></a>', "", f"### {index}. {esc(item['domain'])}", "",
                  f"**Verdict:** {labels.get(item['verdict'], esc(item['verdict']))}  ",
                  f"**Risk:** {'N/A' if item.get('risk') is None else str(item['risk']) + '/100'}  ",
                  f"**Subdomains:** {labels.get(item.get('subdomain_verdict'), 'UNKNOWN')}", ""]
        if item.get('error'):
            lines += [f"**Error:** {esc(item['error'])}", ""]
        lines += ["#### DNS Records", ""]
        for title, key in (("SPF", "spf"), ("DMARC", "dmarc")):
            data = item.get(key) or {}
            record = data.get('record')
            lines += [f"**{title}**", ""]
            if record:
                # Escape via a fence longer than any backtick sequence in DNS data.
                fence = '`' * max(3, max((len(m.group()) + 1 for m in re.finditer(r'`+', record)), default=3))
                lines += [fence + "text", record, fence, ""]
            else:
                lines += ["DNS ERROR" if data.get('lookup_error') else "NONE", ""]
            if key == 'dmarc' and data.get('record_domain'):
                lines += [f"DMARC source: {esc('_dmarc.' + data['record_domain'])}", ""]
        mx = item.get('mx') or {}
        lines += [f"**MX:** {esc(', '.join(mx.get('hosts', [])) or 'NONE')}", ""]
        if mx.get('error'):
            lines += [f"MX status: {esc(mx['error'])}", ""]
        dkim = item.get('dkim')
        lines += [f"**DKIM:** {dkim_status(dkim)}", ""]
        if dkim is None:
            lines += ["SKIPPED", ""]
        else:
            lines += [f"Selectors: {len(dkim.get('found', []))}/{dkim.get('checked', 0)}. "
                      f"DNS errors: {dkim.get('query_errors', 0)}.", ""]
            for key in dkim.get('found', []):
                key_info = key.get('key_status', 'UNKNOWN')
                if key.get('bits'):
                    key_info += f" {key.get('key_type', '')} {key['bits']}"
                lines += [f"- {esc(key['selector'])}: {esc(key_info)}. {esc(key.get('value', ''))} (excerpt)"]
            lines += [""]
        lines += ["#### Risk Factors", ""]
        if item.get('risk') is None:
            lines += ["N/A", ""]
        elif not item.get('risk_factors'):
            lines += ["None", ""]
        else:
            lines += ["| Score | Reason |", "| ---: | --- |"]
            for factor in item['risk_factors']:
                lines += [f"| +{factor['delta']} | {esc(factor['reason'])} |"]
            lines += [""]
        lines += ["#### Checks", "",
                  "| Section | Status | Verdict |", "| --- | --- | --- |"]
        for check in item.get('checklist', []):
            lines += [f"| {esc(check['section'])} | {statuses.get(check['status'], esc(check['status']))} | {esc(check['text'])} |"]
        lines += [""]
    if report.get('emails'):
        lines += ["## Email DKIM", "", "| File | Status | Domain | Selector |", "| --- | --- | --- | --- |"]
        for message in report['emails']:
            for sig in message['signatures'] or [{'status': message['status'], 'domain': '', 'selector': ''}]:
                lines += [f"| {esc(message['file'])} | {esc(sig['status'])} | {esc(sig['domain'])} | {esc(sig['selector'])} |"]
        lines += [""]
    if report.get('skipped_lines'):
        lines += ["## Skipped", "", "| Input | Reason |", "| --- | --- |"]
        for skipped in report['skipped_lines']:
            lines += [f"| {esc(skipped['line'])} | {esc(skipped['reason'])} |"]
        lines += [""]
    with open(path, 'w', encoding='utf-8', newline='\n') as stream:
        stream.write('\n'.join(lines))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

class Progress:
    def __init__(self, enabled):
        self.enabled = enabled
        self.total = 0
        self.done = 0
        self._lock = threading.Lock()

    def update(self, message=None):
        if not self.enabled:
            return
        with self._lock:
            self.done += 1
            text = f"checking {self.done}/{self.total}" + (f" - {message}" if message else "")
            sys.stderr.write("\r" + text + " " * 20)
            sys.stderr.flush()

    def finish(self):
        if not self.enabled:
            return
        sys.stderr.write("\r" + " " * 60 + "\r")
        sys.stderr.flush()


def read_scope(args_domains, path):
    raw = list(args_domains)
    if path:
        if not os.path.isfile(path):
            raise SystemExit(f"scope file not found: {path}")
        with open(path, "r", encoding="utf-8") as f:
            raw.extend(f.read().splitlines())
    domains = []
    skipped = []
    seen = set()
    for line in raw:
        domain, error = normalize_scope_line(line)
        if error:
            skipped.append((line.strip()[:60], error))
        elif domain and domain not in seen:
            seen.add(domain)
            domains.append(domain)
    return domains, skipped


def main():
    parser = argparse.ArgumentParser(
        prog="spoofcalypse",
        description="Check a scope of domains for email spoofability (SPF / DKIM / DMARC analytics)"
    )
    parser.add_argument("--version", action="version", version=f"SPOOFCALYPSE {__version__}")
    parser.add_argument("domains", nargs="*", help="Domains to check")
    parser.add_argument("-f", "--file", metavar="FILE", help="File with a list of domains (one per line)")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help=f"Parallel workers (default: {DEFAULT_WORKERS})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help=f"DNS timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("--dns", dest="dns_server", help="Use a specific DNS resolver (IP address)")
    parser.add_argument("--no-dkim", action="store_true", help="Skip DKIM selector enumeration (faster)")
    parser.add_argument("--selectors", help="Extra comma-separated DKIM selectors to check")
    parser.add_argument("--dkim-api", action="store_true", help="Also fetch selectors seen for each domain in the DKIM key archive (archive.prove.email) and DNS-verify them")
    parser.add_argument("--selftest", action="store_true", help="Validate the test matrix (anchors + complete combo coverage) and exit")
    parser.add_argument("--brief", action="store_true", help="Only the summary table, no per-domain checklists")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--csv", metavar="FILE", help="Export results to CSV file")
    parser.add_argument("--md", "--markdown", dest="markdown", metavar="FILE", help="Export a readable Markdown report")
    parser.add_argument("--eml", action="append", default=[], metavar="FILE", help="Verify DKIM signatures in a local .eml file (repeatable)")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    args = parser.parse_args()

    if args.selftest:
        raise SystemExit(selftest())

    domains, skipped = read_scope(args.domains, args.file)
    if not domains and not args.eml:
        parser.error("no domains to check (pass domains or --file)")
    if skipped and not args.json:
        for line, reason in skipped[:10]:
            print(f"skipped {reason}: {line!r}", file=sys.stderr)
        if len(skipped) > 10:
            print(f"... and {len(skipped) - 10} more skipped lines", file=sys.stderr)

    global USE_COLOR
    if args.no_color or not sys.stdout.isatty() or os.getenv("NO_COLOR"):
        USE_COLOR = False

    selectors = list(DKIM_SELECTORS)
    if args.selectors:
        selectors.extend(s.strip() for s in args.selectors.split(",") if s.strip())
        selectors = list(dict.fromkeys(selectors))

    for eml_path in args.eml:
        if not os.path.isfile(eml_path):
            parser.error(f"Email file not found: {eml_path}")
    resolver = Resolver(args.dns_server, timeout=args.timeout)

    email_results = [verify_eml(path, resolver) for path in args.eml]

    progress = Progress(sys.stderr.isatty() and not args.json)
    progress.total = len(domains)

    results = []
    workers = max(1, args.workers)
    if args.dkim_api:
        workers = min(workers, 8)  # the archive is a shared service: keep the pull polite
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(safe_analyze, domain, resolver, selectors, not args.no_dkim, args.dkim_api): domain
            for domain in domains
        }
        for future in as_completed(futures):
            results.append(future.result())
            progress.update(futures[future])
    progress.finish()

    # DNS errors are transient (UDP drops under load): re-check UNKNOWN once,
    # with fewer workers so the retry pass does not hammer the resolver again
    unknown = [r["domain"] for r in results if r["verdict"] == "UNKNOWN"]
    if unknown:
        if sys.stderr.isatty() and not args.json:
            sys.stderr.write(f"re-checking {len(unknown)} UNKNOWN domain(s)...\n")
        rechecked = []
        with ThreadPoolExecutor(max_workers=min(4, len(unknown))) as executor:
            futures = [
                executor.submit(safe_analyze, domain, resolver, selectors, not args.no_dkim, args.dkim_api)
                for domain in unknown
            ]
            for future in as_completed(futures):
                rechecked.append(future.result())
        resolved = {r["domain"]: r for r in rechecked if r["verdict"] != "UNKNOWN"}
        results = [resolved.get(r["domain"], r) for r in results]

    ranked = rank_results(results)
    report = {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "scope": len(domains),
        "emails": email_results,
        "engine": "checkdmarc 6.0.4",
        "nameservers": resolver.nameservers,
        "counts": {
            v: sum(1 for r in ranked if r["verdict"] == v)
            for v in ("SPOOFABLE", "POSSIBLE", "NOT_SPOOFABLE", "UNKNOWN")
        },
        "nxdomain_domains": sum(1 for r in ranked if r.get("nxdomain")),
        "skipped_lines": [{"line": line, "reason": reason} for line, reason in skipped],
        "results": ranked,
    }

    if args.json:
        print(json.dumps(report, ensure_ascii=True, indent=2, default=str))
    else:
        if ranked:
            print_grouped(ranked, brief=args.brief)
        for email_result in email_results:
            print(f"DKIM {email_result['status']}: {email_result['file']}")
            for sig in email_result['signatures']:
                print(f"  {sig['status']} d={sig['domain']} s={sig['selector']}")

    if args.csv:
        export_csv(ranked, args.csv)
        print(f"\nCSV exported to {args.csv}", file=sys.stderr)
    if args.markdown:
        export_markdown(report, args.markdown)
        print(f"\nMarkdown exported to {args.markdown}", file=sys.stderr)


if __name__ == "__main__":
    main()
