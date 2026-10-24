"""Offline unit tests (no network needed). Run: python -m unittest discover -s tests -v"""
import sys
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:  # allow the offline tests to run even where dnspython is not installed
    import dns.resolver  # noqa: F401
except ImportError:
    for name in ("dns", "dns.exception", "dns.resolver", "dns.query"):
        sys.modules[name] = types.ModuleType(name)
    sys.modules["dns.exception"].DNSException = Exception
    sys.modules["dns"].exception = sys.modules["dns.exception"]
    sys.modules["dns"].resolver = sys.modules["dns.resolver"]
    sys.modules["dns"].query = sys.modules["dns.query"]
    sys.modules["dns.resolver"].Resolver = object

from reconforge.analysis import build_findings
from reconforge.fingerprint import detect_technologies, grade_security_headers
from reconforge.report import render_html
from reconforge.subdomains import clean_name, summarize_certs
from reconforge.utils import is_valid_domain, normalize_domain
from reconforge.whoisinfo import parse_whois

SAMPLE_WHOIS = """Domain Name: EXAMPLE.COM
Registrar: Example Registrar, Inc.
Creation Date: 2015-03-01T10:00:00Z
Registry Expiry Date: 2999-03-01T10:00:00Z
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM
Registrant Email: owner@example.com
"""


class TestUtils(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(normalize_domain("https://Example.COM/path?x=1"), "example.com")
        self.assertEqual(normalize_domain("example.com."), "example.com")

    def test_valid(self):
        self.assertTrue(is_valid_domain("sub.example.co.uk"))
        self.assertFalse(is_valid_domain("localhost"))
        self.assertFalse(is_valid_domain("bad_domain.com"))
        self.assertFalse(is_valid_domain("-bad.com"))


class TestWhois(unittest.TestCase):
    def test_parse(self):
        d = parse_whois(SAMPLE_WHOIS)
        self.assertEqual(d["registrar"], "Example Registrar, Inc.")
        self.assertEqual(d["nameservers"], ["ns1.example.com", "ns2.example.com"])
        self.assertGreater(d["days_to_expiry"], 1000)
        self.assertIn("owner@example.com", d["emails"])


class TestSubdomains(unittest.TestCase):
    def test_clean_name(self):
        self.assertEqual(clean_name("*.API.example.com", "example.com"), "api.example.com")
        self.assertIsNone(clean_name("evil.com", "example.com"))
        self.assertIsNone(clean_name("notexample.com", "example.com"))
        self.assertIsNone(clean_name("user@example.com", "example.com"))

    def test_cert_summary(self):
        certs = [{"issuer": "C=US, O=Let's Encrypt, CN=R3", "common_name": "*.example.com", "not_before": "2024-01-02T00:00:00"},
                 {"issuer": "C=US, O=DigiCert Inc, CN=X", "common_name": "a.example.com", "not_before": "2023-05-05T00:00:00"}]
        s = summarize_certs(certs)
        self.assertEqual(s["total"], 2)
        self.assertEqual(s["wildcards"], 1)
        self.assertEqual(s["first_seen"], "2023-05-05")


class TestFingerprint(unittest.TestCase):
    def test_detect(self):
        headers = {"Server": "nginx/1.24.0", "X-Powered-By": "PHP/8.2.1", "CF-Ray": "abc"}
        html = '<meta name="generator" content="WordPress 6.4.2"><script src="/wp-content/x.js"></script>'
        found = {t["name"]: t for t in detect_technologies(headers, ["PHPSESSID"], html)}
        self.assertEqual(found["nginx"]["version"], "1.24.0")
        self.assertEqual(found["PHP"]["version"], "8.2.1")
        self.assertEqual(found["WordPress"]["version"], "6.4.2")
        self.assertIn("Cloudflare", found)

    def test_no_false_positive(self):
        self.assertEqual(detect_technologies({"Server": "weird"}, [], "<html></html>"), [])

    def test_security_headers(self):
        g = grade_security_headers({"Strict-Transport-Security": "x", "Content-Security-Policy": "frame-ancestors 'none'",
                                    "X-Content-Type-Options": "nosniff", "Referrer-Policy": "x",
                                    "Permissions-Policy": "x"}, "https")
        self.assertEqual(g["grade"], "A")
        self.assertEqual(grade_security_headers({}, "http")["grade"], "F")


def sample_result():
    return {
        "meta": {"domain": "example.com", "mode": "full", "started": "2026-01-01 10:00:00",
                 "version": "1.0.0", "duration_s": 12.3},
        "whois": parse_whois(SAMPLE_WHOIS), "dns": {"A": ["93.184.216.34"], "NS": ["ns1.example.com"]},
        "email_security": {"has_mx": True, "spf": None, "spf_all": None, "dmarc": None, "dmarc_policy": None},
        "axfr": [{"ns": "ns1.example.com", "vulnerable": True, "names": ["a.example.com"]}],
        "certificates": {"total": 2, "wildcards": 1, "issuers": [("Let's Encrypt", 2)], "first_seen": "2023-01-01", "last_seen": "2024-01-01"},
        "wildcard_ips": [],
        "subdomains": [
            {"name": "example.com", "sources": ["target"], "ips": ["93.184.216.34"], "cnames": [], "resolves": True,
             "http": {"error": None, "scheme": "https", "https_available": True, "status": 200, "title": "<b>Example</b>",
                      "server": "nginx/1.24.0", "tech": [{"name": "nginx", "category": "Web server", "version": "1.24.0", "evidence": "header"}],
                      "security_headers": {"present": [], "missing": ["content-security-policy"], "grade": "F"}},
             "tls": {"valid": True, "expires_in_days": 5}},
            {"name": "staging.example.com", "sources": ["crt.sh"], "ips": [], "cnames": ["x.github.io"], "resolves": False,
             "http": None, "tls": None},
        ],
        "findings": [],
    }


class TestAnalysisAndReport(unittest.TestCase):
    def test_findings(self):
        r = sample_result()
        titles = {f["title"] for f in build_findings(r)}
        self.assertIn("DNS zone transfer allowed (AXFR)", titles)
        self.assertIn("Possible subdomain takeover", titles)
        self.assertIn("No SPF record", titles)
        self.assertIn("TLS certificate expires soon", titles)
        self.assertIn("Potentially sensitive hostname", titles)

    def test_report_escapes_html(self):
        r = sample_result()
        r["findings"] = build_findings(r)
        page = render_html(r)
        self.assertIn("Recon report: example.com", page)
        self.assertNotIn("<b>Example</b>", page)       # page title must be escaped
        self.assertIn("&lt;b&gt;Example&lt;/b&gt;", page)


if __name__ == "__main__":
    unittest.main()
