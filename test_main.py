"""Offline unit tests for proxy_fetcher.py: python -m unittest -v test_proxy_fetcher.py"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import main as p


class ParsingTests(unittest.TestCase):
    def test_source_url_protocols(self):
        examples = {
            "https://api.openproxylist.xyz/http.txt": "http",
            "https://api.openproxylist.xyz/https.txt": "https",
            "https://api.openproxylist.xyz/socks4.txt": "socks4",
            "https://api.openproxylist.xyz/socks5.txt": "socks5",
            "https://api.proxyscrape.com/?request=displayproxies&proxytype=socks4&timeout=10000": "socks4",
            "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt": "socks5",
            "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt": "https",
            "https://raw.githubusercontent.com/MrMarble/proxy-list/main/all.txt": "mixed",
            "https://spys.me/proxy.txt": "http",
            "https://spys.me/socks.txt": "socks5",
            "https://www.socks-proxy.net/": "socks",
            "https://rcloak.com/api/proxies/raw?protocol=all": "mixed",
            "https://raw.githubusercontent.com/berkay-digital/Proxy-Scraper/main/proxies.txt": "unknown",
        }
        for url, expected in examples.items():
            with self.subTest(url=url):
                self.assertEqual(p.get_protocol(url), expected)

    def test_proxy_lines(self):
        cases = [
            ("1.1.1.1:8080", "http", ("http", "1.1.1.1", 8080)),
            ("1.1.1.1:8080", "unknown", None),
            ("1.1.1.1:8080", "mixed", None),
            ("socks5://1.1.1.1:1080", "mixed", ("socks5", "1.1.1.1", 1080)),
            ("HTTPS://1.1.1.1:443", "unknown", ("https", "1.1.1.1", 443)),
            ("SOCKS4 8.8.8.8:1080", "unknown", ("socks4", "8.8.8.8", 1080)),
            ("8.8.8.8:1080 US SOCKS5 2026", "socks", ("socks5", "8.8.8.8", 1080)),
            ("8.8.8.8:1080 US-A HIA", "unknown", None),
            ("[2606:4700:4700::1111]:8080", "https", ("https", "2606:4700:4700::1111", 8080)),
            ("10.0.0.1:8080", "http", None),
            ("127.0.0.1:8080", "http", None),
            ("1.1.1.1:99999", "http", None),
            ("user:pass@1.1.1.1:80", "http", None),
            ("1.1.1.1:80 # comment", "http", ("http", "1.1.1.1", 80)),
            ("<div>1.1.1.1:80</div>", "http", None),
            ("garbage", "http", None),
        ]
        for line, protocol, expected in cases:
            with self.subTest(line=line, protocol=protocol):
                self.assertEqual(p.parse_proxy_line(line, protocol), expected)

    def test_html_table(self):
        parser = p.ProxyTableParser()
        parser.feed('''<html><table><tr><th>IP Address</th><th>Port</th><th>Version</th></tr>
            <tr><td>1.1.1.1</td><td>1080</td><td>SOCKS5</td></tr>
            <tr><td>8.8.8.8</td><td>8080</td><td>SOCKS4</td></tr></table></html>''')
        self.assertEqual(parser.entries, [("1.1.1.1", "1080", "SOCKS5"), ("8.8.8.8", "8080", "SOCKS4")])
        self.assertEqual(p.parse_proxy_line("1.1.1.1:1080 SOCKS5", "socks"), ("socks5", "1.1.1.1", 1080))


class WorkflowTests(unittest.TestCase):
    def test_save_files_and_nonempty_policy(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            a = {("http", "1.1.1.1", 8080), ("socks5", "8.8.8.8", 1080)}
            p.save_results(base, a)
            self.assertEqual((base / "http.txt").read_text(), "1.1.1.1:8080\n")
            self.assertEqual((base / "socks5.txt").read_text(), "8.8.8.8:1080\n")
            self.assertEqual((base / "https.txt").read_text(), "")
            with self.assertRaises(ValueError):
                p.save_results(base, set())
            self.assertEqual((base / "http.txt").read_text(), "1.1.1.1:8080\n")
            p.save_results(base / "dead", set(), allow_empty=True)
            self.assertEqual((base / "dead" / "http.txt").read_text(), "")
            p.save_previous_snapshot(base, base / "previous")
            self.assertEqual((base / "previous" / "http.txt").read_text(), "1.1.1.1:8080\n")

    def test_txt_fetch_spys_and_probe_unknown(self):
        source_text = """https://spys.me/proxy.txt
https://spys.me/socks.txt
https://example.org/all.txt
"""
        def rows_for(url):
            if "proxy.txt" in url:
                yield "1.1.1.1:8080 US-H-S +"
                yield "8.8.8.8:3128 US-N -"
            elif "socks.txt" in url:
                yield "9.9.9.9:1080 FR-H +"
            else:
                yield "1.0.0.1:9000"
        with tempfile.TemporaryDirectory() as d:
            source_file = Path(d) / "source.txt"
            source_file.write_text(source_text)
            results = set()
            with patch.object(p, "fetch_text", side_effect=rows_for):
                p.fetch_txt_sources(results, source_file, probe_unknown=False)
            self.assertIn(("http", "1.1.1.1", 8080), results)
            self.assertIn(("https", "1.1.1.1", 8080), results)
            self.assertIn(("socks5", "9.9.9.9", 1080), results)
            self.assertFalse(any(row[1] == "1.0.0.1" for row in results))
            results = set()
            with patch.object(p, "fetch_text", side_effect=rows_for):
                p.fetch_txt_sources(results, source_file, probe_unknown=True)
            self.assertEqual({row[0] for row in results if row[1] == "1.0.0.1"}, set(p.PROTOCOLS))

    def test_pagination_and_dedup(self):
        def fake_fetch_rows(url, key, **kwargs):
            page = kwargs["params"]["page"]
            if page == 1:
                return {"proxies": [{"address": "1.1.1.1:8080"}, "8.8.8.8:1080"], "has_next": True}
            return {"proxies": [{"address": "1.1.1.1:8080"}], "has_next": False}

        result = set()
        with patch.object(p, "fetch_rows", side_effect=fake_fetch_rows):
            p.fetch_paginated(result, "https://example.com/", "true")
        self.assertEqual(len(result), 8)  # 2 addresses x 4 protocols

    def test_bounded_scanning_and_splitting(self):
        candidates = {("http", "1.1.1.1", 80), ("https", "8.8.8.8", 443), ("socks4", "9.9.9.9", 1080)}
        with patch.object(p, "check", side_effect=lambda proto, ip, port, timeout: proto != "socks4"):
            live, dead = p.scan_candidates(candidates, workers=2, timeout=0.2)
        self.assertEqual(len(live), 2)
        self.assertEqual(len(dead), 1)


if __name__ == "__main__":
    unittest.main()
