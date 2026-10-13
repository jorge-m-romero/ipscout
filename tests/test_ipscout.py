import io
import ipaddress
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import ipscout  # noqa: E402


class LoadIpsTests(unittest.TestCase):
    def test_parses_comments_blanks_duplicates_and_invalid(self):
        lines = ["# header\n", "\n", "8.8.8.8  # google\n", "2001:db8::1\n",
                 "8.8.8.8\n", "not-an-ip\n", "  1.1.1.1  \n"]
        ips, invalid = ipscout.load_ips(lines)
        self.assertEqual([str(i) for i in ips], ["8.8.8.8", "2001:db8::1", "1.1.1.1"])
        self.assertEqual(invalid, [(6, "not-an-ip")])

    def test_ipv6_duplicates_in_different_notation(self):
        ips, _ = ipscout.load_ips(["2001:db8::1", "2001:0db8:0:0:0:0:0:1"])
        self.assertEqual(len(ips), 1)


class ParsingTests(unittest.TestCase):
    def test_parse_org(self):
        self.assertEqual(ipscout.parse_org("AS15169 Google LLC"), ("AS15169", "Google LLC"))
        self.assertEqual(ipscout.parse_org("Some Org"), ("", "Some Org"))
        self.assertEqual(ipscout.parse_org(""), ("", ""))

    def test_vt_verdict(self):
        self.assertEqual(ipscout.vt_verdict({"malicious": 2, "suspicious": 1}), "MALICIOUS")
        self.assertEqual(ipscout.vt_verdict({"malicious": 0, "suspicious": 1}), "SUSPICIOUS")
        self.assertEqual(ipscout.vt_verdict({"malicious": 0, "harmless": 60}), "clean")
        self.assertEqual(ipscout.vt_verdict({"harmless": 0, "undetected": 92}), "unrated")
        self.assertEqual(ipscout.vt_verdict({}), "")


class LookupTests(unittest.TestCase):
    def test_private_ip_makes_no_external_call(self):
        with mock.patch.object(ipscout, "http_get_json") as http, \
             mock.patch.object(ipscout, "reverse_dns", return_value=""):
            row = ipscout.enrich(ipaddress.ip_address("192.168.1.10"))
        http.assert_not_called()
        self.assertEqual(row["scope"], "private/reserved")

    def test_ipinfo_response_mapped(self):
        data = {"country": "US", "region": "California", "city": "Mountain View",
                "org": "AS15169 Google LLC"}
        with mock.patch.object(ipscout, "http_get_json", return_value=(200, data)):
            row = ipscout.ipinfo_lookup("8.8.8.8")
        self.assertEqual(row["asn"], "AS15169")
        self.assertEqual(row["org"], "Google LLC")
        self.assertEqual(row["country"], "US")

    def test_virustotal_response_mapped(self):
        data = {"data": {"attributes": {
            "reputation": -12,
            "last_analysis_stats": {"malicious": 5, "suspicious": 1,
                                    "harmless": 50, "undetected": 30}}}}
        with mock.patch.object(ipscout, "http_get_json", return_value=(200, data)):
            row = ipscout.virustotal_lookup("203.0.113.5", "key")
        self.assertEqual(row["vt_verdict"], "MALICIOUS")
        self.assertEqual(row["vt_malicious"], 5)
        self.assertEqual(row["vt_reputation"], -12)

    def test_virustotal_not_found(self):
        with mock.patch.object(ipscout, "http_get_json", return_value=(404, None)):
            self.assertEqual(ipscout.virustotal_lookup("203.0.113.5", "key"),
                             {"vt_verdict": "not found"})

    def test_rate_limit_retries_once(self):
        calls = []

        def flaky(ip):
            calls.append(ip)
            if len(calls) == 1:
                raise ipscout.RateLimited(ip)
            return {"ok": True}

        with mock.patch.object(ipscout.time, "sleep"):
            self.assertEqual(ipscout.with_retry(flaky, "x", log=lambda *a: None), {"ok": True})
        self.assertEqual(len(calls), 2)


class SecurityTests(unittest.TestCase):
    def test_csv_formula_injection_neutralised(self):
        import csv, tempfile
        row = {"ip": "203.0.113.5", "scope": "public",
               "rdns": '=HYPERLINK("http://evil","x")', "org": "@SUM(1)", "vt_reputation": -5}
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "out.csv")
            ipscout.write_csv([row], path)
            with open(path, newline="") as f:
                out = next(csv.DictReader(f))
        self.assertTrue(out["rdns"].startswith("'="))
        self.assertTrue(out["org"].startswith("'@"))
        self.assertEqual(out["vt_reputation"], "-5")  # numbers left alone

    def test_control_characters_stripped(self):
        data = {"country": "US", "org": "AS1 Evil\x1b[31mCorp\x07", "city": "a\x1b]0;x\x07b"}
        with mock.patch.object(ipscout, "http_get_json", return_value=(200, data)):
            row = ipscout.ipinfo_lookup("8.8.8.8")
        self.assertNotIn("\x1b", row["org"] + row["city"])
        self.assertNotIn("\x07", row["org"] + row["city"])

    def test_unexpected_errors_do_not_crash(self):
        import http.client

        def boom():
            raise http.client.RemoteDisconnected("gone")

        self.assertIn("error", ipscout.with_retry(boom))

    def test_api_key_with_control_characters_rejected(self):
        with mock.patch.dict(os.environ, {"VT_API_KEY": "abc\ndef"}), \
             mock.patch.object(ipscout, "http_get_json") as http, \
             mock.patch.object(sys, "stdin", io.StringIO("8.8.8.8\n")):
            with self.assertRaises(SystemExit) as cm:
                ipscout.main(["-", "--vt"])
        http.assert_not_called()
        self.assertNotIn("abc", str(cm.exception))

    def test_rate_limited_error_has_no_url(self):
        self.assertEqual(str(ipscout.RateLimited()), "")


class OutputTests(unittest.TestCase):
    def test_table_does_not_change_rows(self):
        rows = [{"ip": "10.0.0.1", "scope": "private/reserved", "rdns": ""}]
        out = io.StringIO()
        ipscout.print_table(rows, show_vt=True, out=out)
        self.assertIn("(private/reserved)", out.getvalue())
        self.assertNotIn("org", rows[0])


if __name__ == "__main__":
    unittest.main()
