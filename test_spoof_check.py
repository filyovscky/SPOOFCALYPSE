"""Offline regression tests: python -m unittest discover -s domainCheck -v."""
import unittest
import contextlib
import csv
import io
import json
import os
import tempfile
from unittest.mock import patch

import spoof_check as s


class FakeResolver:
    nameservers = ["offline-test"]
    def __init__(self, records):
        self.records = records

    def txt(self, name):
        return self.query(name, "TXT")

    def query(self, name, kind):
        value = self.records.get((name, kind))
        if isinstance(value, s.DNSResult):
            return value
        return s.DNSResult("ok", value) if value is not None else s.DNSResult("nodata")


class RegressionTests(unittest.TestCase):
    def test_dkim_statuses(self):
        cases = [
            (None, "SKIPPED"),
            ({"found": [], "query_errors": 0}, "NOT_FOUND"),
            ({"found": [], "query_errors": 1}, "ERROR"),
            ({"found": [{"selector": "s1"}], "query_errors": 0}, "FOUND"),
            ({"found": [{"selector": "s1"}], "query_errors": 1}, "PARTIAL"),
        ]
        for result, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(s.dkim_status(result), expected)

    def analyze(self, spf, extra=None, domain="example.com", dmarc="v=DMARC1; p=reject"):
        from checkdmarc.utils import DNS_CACHE
        DNS_CACHE.clear()
        records = {(domain, "TXT"): spf,
                   ("_dmarc.example.com", "TXT"): [dmarc]}
        records.update(extra or {})
        return s.analyze_domain(domain, FakeResolver(records), with_dkim=False)

    def test_negative_include_does_not_authorize(self):
        for qualifier in ("-", "~", "?"):
            with self.subTest(qualifier=qualifier):
                r = self.analyze([f"v=spf1 {qualifier}include:provider.test -all"],
                                 {("provider.test", "TXT"): ["v=spf1 +all"]})
                self.assertEqual(r["verdict"], "NOT_SPOOFABLE")
                self.assertEqual(r["spf_bypass"], [])

    def test_positive_include_authorizes(self):
        r = self.analyze(["v=spf1 include:provider.test -all"],
                         {("provider.test", "TXT"): ["v=spf1 +all"]})
        self.assertEqual(r["verdict"], "SPOOFABLE")
        self.assertEqual(s.VERDICTS[r["code"]], r["verdict"])

    def test_nested_negative_include(self):
        r = self.analyze(["v=spf1 -include:provider.test -all"], {
            ("provider.test", "TXT"): ["v=spf1 include:nested.test -all"],
            ("nested.test", "TXT"): ["v=spf1 +all"]})
        self.assertEqual(r["spf_bypass"], [])

    def test_child_spf_with_strict_inherited_dmarc(self):
        r = self.analyze(["v=spf1 +all"],
                         {("example.com", "TXT"): ["v=spf1 -all"]},
                         domain="child.example.com", dmarc="v=DMARC1; p=reject; aspf=s")
        self.assertEqual(r["verdict"], "SPOOFABLE")
        self.assertEqual(r["subdomain_verdict"], "UNKNOWN")

    def test_parent_spf_not_substituted(self):
        r = self.analyze(["v=spf1 -all"],
                         {("example.com", "TXT"): ["v=spf1 +all"]},
                         domain="child.example.com", dmarc="v=DMARC1; p=reject; aspf=s")
        self.assertEqual(r["verdict"], "NOT_SPOOFABLE")

    def test_duplicate_spf_not_confirmed_bypass(self):
        r = self.analyze(["v=spf1 include:provider.test -all", "v=spf1 -all"],
                         {("provider.test", "TXT"): ["v=spf1 +all"]})
        self.assertEqual(r["verdict"], "UNKNOWN")
        self.assertEqual(r["spf_bypass"], [])
        self.assertIsNone(r["risk"])

    def test_universal_ip_networks(self):
        for network in ("ip4:0.0.0.0/0", "ip6:::/0"):
            with self.subTest(network=network):
                self.assertEqual(self.analyze([f"v=spf1 {network} -all"])["verdict"], "SPOOFABLE")

    def test_negative_ip_and_unreachable_include(self):
        r = self.analyze(["v=spf1 -ip4:0.0.0.0/0 -all include:provider.test"],
                         {("provider.test", "TXT"): ["v=spf1 +all"]})
        self.assertEqual(r["verdict"], "NOT_SPOOFABLE")
        self.assertEqual(r["spf"]["broad_ip_ranges"], [])

    def test_dns_error_risk_unknown(self):
        r = self.analyze(s.DNSResult("error", error="Timeout"))
        self.assertEqual(r["verdict"], "UNKNOWN")
        self.assertIsNone(r["risk"])

    def test_include_timeout_not_protected(self):
        r = self.analyze(["v=spf1 include:provider.test -all"],
                         {("provider.test", "TXT"): s.DNSResult("error", error="Timeout")})
        self.assertEqual(r["verdict"], "UNKNOWN")

    def test_scope_cli_json_and_csv(self):
        from checkdmarc.utils import DNS_CACHE
        DNS_CACHE.clear()
        resolver = FakeResolver({("example.com", "TXT"): ["v=spf1 -all"],
                                 ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject"]})
        with tempfile.TemporaryDirectory() as directory:
            scope = os.path.join(directory, "scope.txt")
            output = os.path.join(directory, "report.csv")
            markdown = os.path.join(directory, "report.md")
            with open(scope, "w", encoding="utf-8") as stream:
                stream.write("https://example.com/path\nexample.com\n")
            stdout, stderr = io.StringIO(), io.StringIO()
            argv = ["spoof_check.py", "-f", scope, "--no-dkim", "--json", "--csv", output, "--md", markdown]
            with patch("sys.argv", argv), patch.object(s, "Resolver", return_value=resolver), \
                    contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                s.main()
            report = json.loads(stdout.getvalue())
            self.assertEqual(len(report["results"]), 1)
            self.assertEqual(report["results"][0]["verdict"], "NOT_SPOOFABLE")
            with open(output, encoding="utf-8-sig", newline="") as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(len(rows), 1)
            self.assertIn("CSV exported", stderr.getvalue())
            with open(markdown, encoding="utf-8") as stream:
                text = stream.read()
            self.assertIn("# SPOOFCALYPSE", text)
            self.assertIn("[example.com](#domain-1)", text)
            self.assertIn('<a id="domain-1"></a>', text)
            self.assertIn("v=spf1 -all", text)
            self.assertIn("SKIPPED", text)
            self.assertNotIn("\x1b", text)
            self.assertNotIn("Проверены настройки DNS", text)
            self.assertNotIn("доставка", text)
            self.assertIn("NOT_SPOOFABLE", text)
            self.assertIn("Markdown exported", stderr.getvalue())

    def test_markdown_unknown_and_untrusted_dns(self):
        item = self.analyze(s.DNSResult("error", error="Timeout"))
        item['error'] = 'DNS | error\n<script>alert(1)</script>'
        item['spf']['record'] = 'v=spf1 ```\n# injected heading'
        item['dkim'] = {'checked': 1, 'found': [{'selector': 's1', 'value': '<img src=x>|key'}],
                        'query_errors': 1}
        report = {'checked_at': '2026-11-13T00:00:00+00:00', 'scope': 1,
                  'counts': {'UNKNOWN': 1}, 'results': [item],
                  'skipped_lines': [{'line': 'bad|scope', 'reason': 'invalid'}]}
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'report.md')
            s.export_markdown(report, path)
            with open(path, encoding='utf-8') as stream:
                text = stream.read()
        self.assertIn('N/A', text)
        self.assertNotIn('<script>', text)
        self.assertNotIn('<img', text)
        self.assertIn(r'DNS \| error<br>&lt;script&gt;', text)
        self.assertIn('````text\nv=spf1 ```\n# injected heading\n````', text)
        self.assertIn(r'bad\|scope', text)


if __name__ == "__main__":
    unittest.main()
