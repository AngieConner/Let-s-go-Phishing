"""
Automated tests - run them with:   python -m unittest -v

Each test feeds the detector something with a known correct answer and
checks that the detector agrees. If you change a rule and a test fails,
you've learned your change had a side effect.
"""

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from phishing_detector import analyze_bytes, analyze_email  # noqa: E402
from phishing_detector.domain_tools import (  # noqa: E402
    defang,
    host_from_url,
    impersonated_brand,
    registered_domain,
)

SAMPLES = PROJECT_ROOT / "samples"


class SampleEmailTests(unittest.TestCase):
    def test_lookalike_phish_is_red(self):
        result = analyze_email(SAMPLES / "phishing_lookalike_paypal.eml")
        self.assertTrue(result.verdict.is_malicious)
        self.assertGreaterEqual(result.verdict.score, 70)

    def test_gift_card_scam_is_red_even_though_authentication_passed(self):
        result = analyze_email(SAMPLES / "bec_gift_card_scam.eml")
        self.assertTrue(result.verdict.is_malicious)
        self.assertEqual(len(result.good_signs), 3)  # SPF, DKIM, DMARC all passed

    def test_library_notice_is_green(self):
        result = analyze_email(SAMPLES / "legit_library_notice.eml")
        self.assertFalse(result.verdict.is_malicious)
        self.assertEqual(result.verdict.score, 0)


class LinkTrickTests(unittest.TestCase):
    def _titles(self, html_body: str) -> set[str]:
        raw = (
            "From: Example Shop <news@shop.example.com>\n"
            "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n"
            "Subject: Hello\nContent-Type: text/html\n\n" + html_body
        ).encode()
        return {f.title for f in analyze_bytes(raw).findings}

    def test_ip_address_link(self):
        self.assertIn("Link points to a raw IP address",
                      self._titles('<a href="http://203.0.113.9/login">Log in</a>'))

    def test_at_sign_trick(self):
        self.assertIn("Link uses the '@' trick",
                      self._titles('<a href="https://paypal.com@203.0.113.9/">Pay</a>'))

    def test_matching_link_text_is_not_flagged(self):
        titles = self._titles('<a href="https://shop.example.com/sale">shop.example.com/sale</a>')
        self.assertNotIn("Link text shows one address but goes to another", titles)

    def test_disguised_attachment_name(self):
        raw = (
            "From: a@b.example.com\nSubject: Invoice\nMIME-Version: 1.0\n"
            'Content-Type: multipart/mixed; boundary="b"\n\n'
            "--b\nContent-Type: text/plain\n\nSee attached.\n"
            '--b\nContent-Type: application/octet-stream\n'
            'Content-Disposition: attachment; filename="invoice.pdf.exe"\n\nxx\n--b--\n'
        ).encode()
        titles = {f.title for f in analyze_bytes(raw).findings}
        self.assertIn("Disguised file: invoice.pdf.exe", titles)


class DomainToolTests(unittest.TestCase):
    def test_registered_domain(self):
        self.assertEqual(registered_domain("login.paypal.com"), "paypal.com")
        self.assertEqual(registered_domain("paypal.com.account-verify.top"), "account-verify.top")
        self.assertEqual(registered_domain("www.bbc.co.uk"), "bbc.co.uk")

    def test_lookalike_detection(self):
        self.assertEqual(impersonated_brand("paypa1.com"), ("PayPal", True))
        self.assertEqual(impersonated_brand("arnazon-orders.com"), ("Amazon", True))
        self.assertEqual(impersonated_brand("paypal.com.secure-login.xyz"), ("PayPal", False))

    def test_real_brand_domains_are_not_flagged(self):
        self.assertIsNone(impersonated_brand("www.paypal.com"))
        self.assertIsNone(impersonated_brand("login.microsoftonline.com"))

    def test_no_false_alarm_on_similar_words(self):
        self.assertIsNone(impersonated_brand("purchase-orders.com"))  # contains "chase"
        self.assertIsNone(impersonated_brand("startups.io"))          # contains "ups"

    def test_at_sign_reveals_real_host(self):
        self.assertEqual(host_from_url("http://paypal.com@203.0.113.9/login"), "203.0.113.9")

    def test_defang(self):
        self.assertEqual(defang("http://evil.com/a"), "hxxp://evil[.]com/a")


if __name__ == "__main__":
    unittest.main()
