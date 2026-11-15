import contextlib
import io
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import requests

import main


@contextlib.contextmanager
def proxy_server(status):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(status)
            self.end_headers()

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def response(data=None, status=200):
    result = requests.Response()
    result.status_code = status
    result._content = b""
    result._content_consumed = True
    result.json = lambda: data
    return result


class CheckerTests(unittest.TestCase):
    def test_only_exact_204_is_live(self):
        for status in (200, 204, 301, 407, 500):
            with self.subTest(status=status):
                with patch.object(requests.Session, "get", return_value=response(status=status)), \
                        patch.object(requests, "get", return_value=response(status=status)):
                    self.assertEqual(main.check("http", "192.0.2.1", 8080), status == 204)

    def test_https_list_checks_connect_through_http_proxy(self):
        with patch.object(requests.Session, "get", return_value=response(status=204)) as get:
            self.assertTrue(main.check("https", "192.0.2.1", 8080, timeout=2))
        self.assertTrue(get.call_args.args[0].startswith("https://"))
        self.assertEqual(get.call_args.kwargs["proxies"]["https"], "http://192.0.2.1:8080")
        self.assertFalse(get.call_args.kwargs["allow_redirects"])

    def test_connection_error_is_dead(self):
        with patch.object(requests.Session, "get", side_effect=requests.ConnectionError), \
                patch.object(requests, "get", side_effect=requests.ConnectionError):
            self.assertFalse(main.check("socks5", "192.0.2.1", 1080))


class SourceTests(unittest.TestCase):
    def test_both_sources_are_normalized_deduplicated_and_paginated(self):
        replies = [
            response({"rows": [
                {"ip": "192.0.2.1", "port": "8080", "protos": ["HTTP", "SOCKS5"]},
                {"ip": "invalid", "port": 80, "protos": ["http"]},
                {"ip": "192.0.2.9", "port": 70000, "protos": ["http"]},
                {"ip": "192.0.2.9", "port": "bad", "protos": "http"},
                {"ip": "192.0.2.9", "port": 80, "protos": ["ftp"]},
            ]}),
            response({"proxies": [{"address": "192.0.2.1:8080"}], "has_next": True, "limit": 1, "offset": 0}),
            response({"proxies": [{"address": "192.0.2.2:80"}], "has_next": False}),
            response({"proxies": [{"address": "192.0.2.3:3128"}]}),
            response({"proxies": [{"address": "[2001:db8::1]:1080"}]}),
            response({"proxies": [{"address": "192.0.2.4:1080"}]}),
        ]
        with patch.object(requests, "get", side_effect=replies):
            proxies = main.fetch_proxies()
        self.assertEqual(proxies, {
            ("http", "192.0.2.1", 8080), ("socks5", "192.0.2.1", 8080),
            ("http", "192.0.2.2", 80), ("https", "192.0.2.3", 3128),
            ("socks4", "2001:db8::1", 1080), ("socks5", "192.0.2.4", 1080),
        })

    def test_failed_or_malformed_source_aborts_instead_of_publishing_partial_data(self):
        for first in (response(status=503), response({}), response({"rows": {}})):
            with self.subTest(first=first.status_code):
                with patch.object(requests, "get", return_value=first):
                    with self.assertRaises((RuntimeError, requests.RequestException, ValueError)):
                        main.fetch_proxies()


class OutputTests(unittest.TestCase):
    def test_failed_replacement_restores_all_previous_outputs(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for filename in ("http.txt", "https.txt", "socks4.txt", "socks5.txt"):
                (root / filename).write_text("previous:80\n", encoding="utf-8")
            replace = main.os.replace
            count = 0

            def fail_second(source, target):
                nonlocal count
                count += 1
                if count == 2:
                    raise PermissionError("file in use")
                return replace(source, target)

            with patch.object(main.os, "replace", side_effect=fail_second):
                with self.assertRaises(PermissionError):
                    main.save_results(root, {("http", "192.0.2.1", 80)})
            self.assertEqual({path.name: path.read_text() for path in root.iterdir()}, {
                "http.txt": "previous:80\n", "https.txt": "previous:80\n",
                "socks4.txt": "previous:80\n", "socks5.txt": "previous:80\n",
            })

    def test_second_run_cannot_replace_snapshot_while_first_run_holds_lock(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "http.txt").write_text("previous:80\n", encoding="utf-8")
            with main.scan_lock(root):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(main.run(root, push=False), 1)
            self.assertEqual((root / "http.txt").read_text(), "previous:80\n")
            # Closing the first process's handle must release the lock.
            with main.scan_lock(root):
                pass

    def test_snapshot_removes_dead_entries_sorts_and_writes_all_protocols(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "http.txt").write_text("old:80\n", encoding="utf-8")
            main.save_results(root, {
                ("http", "192.0.2.2", 8080), ("http", "192.0.2.1", 80),
                ("socks5", "2001:db8::1", 1080),
            })
            self.assertEqual((root / "http.txt").read_text(), "192.0.2.1:80\n192.0.2.2:8080\n")
            self.assertEqual((root / "https.txt").read_text(), "")
            self.assertEqual((root / "socks4.txt").read_text(), "")
            self.assertEqual((root / "socks5.txt").read_text(), "[2001:db8::1]:1080\n")

    def test_no_live_proxies_preserves_previous_snapshot(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target = root / "http.txt"
            target.write_text("previous:80\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                main.save_results(root, set())
            self.assertEqual(target.read_text(), "previous:80\n")

    def test_failed_scan_does_not_save_or_push(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target = root / "http.txt"
            target.write_text("previous:80\n", encoding="utf-8")
            with patch.object(main, "fetch_proxies", create=True, side_effect=ValueError("source failed")):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(main.run(root, push=False), 1)
            self.assertEqual(target.read_text(), "previous:80\n")


class GitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "work"
        self.remote = Path(self.temp.name) / "remote.git"
        self.root.mkdir()
        self.git("init", "--initial-branch=main")
        self.git("config", "user.name", "Proxy Test")
        self.git("config", "user.email", "proxy-test@example.invalid")
        (self.root / ".gitignore").write_text(".proxy-update.lock\n", encoding="utf-8")
        for name in ("http.txt", "https.txt", "socks4.txt", "socks5.txt", "owner.txt"):
            (self.root / name).write_text("before\n", encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "-m", "initial")
        self.git("init", "--bare", str(self.remote))
        self.git("remote", "add", "origin", str(self.remote))
        self.git("push", "--set-upstream", "origin", "main")

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.root, check=True,
                              capture_output=True, text=True).stdout.strip()

    def test_commit_and_push_only_proxy_files_preserves_other_staged_work(self):
        (self.root / "http.txt").write_text("192.0.2.1:80\n", encoding="utf-8")
        (self.root / "owner.txt").write_text("owner work\n", encoding="utf-8")
        self.git("add", "owner.txt")
        main.publish_results(self.root)
        self.assertEqual(self.git("show", "--format=", "--name-only", "HEAD"), "http.txt")
        self.assertEqual(self.git("diff", "--cached", "--name-only"), "owner.txt")
        self.assertEqual(self.git("rev-parse", "HEAD"), self.git("--git-dir", str(self.remote), "rev-parse", "refs/heads/main"))
        commit = self.git("rev-parse", "HEAD")
        main.publish_results(self.root)
        self.assertEqual(self.git("rev-parse", "HEAD"), commit)

    def test_push_failure_can_be_retried_without_new_commit(self):
        (self.root / "http.txt").write_text("192.0.2.1:80\n", encoding="utf-8")
        self.git("config", "remote.origin.pushurl", str(self.remote / "missing"))
        with self.assertRaises(RuntimeError):
            main.publish_results(self.root)
        commit = self.git("rev-parse", "HEAD")
        self.git("config", "--unset", "remote.origin.pushurl")
        main.publish_results(self.root)
        self.assertEqual(self.git("rev-parse", "HEAD"), commit)
        self.assertEqual(commit, self.git("--git-dir", str(self.remote), "rev-parse", "refs/heads/main"))

    def test_missing_upstream_fails_before_staging_outputs(self):
        self.git("branch", "--unset-upstream")
        (self.root / "http.txt").write_text("192.0.2.1:80\n", encoding="utf-8")
        with self.assertRaises(RuntimeError):
            main.publish_results(self.root)
        self.assertEqual(self.git("diff", "--cached", "--name-only"), "")

    def test_full_run_checks_proxies_then_saves_commits_and_pushes(self):
        with proxy_server(204) as live_port, proxy_server(200) as dead_port:
            replies = [
                response({"rows": [{"ip": "127.0.0.1", "port": live_port, "protos": ["http"]}]}),
                response({"proxies": [{"address": f"127.0.0.1:{live_port}"},
                                      {"address": f"127.0.0.1:{dead_port}"}]}),
                response({"proxies": []}), response({"proxies": []}), response({"proxies": []}),
            ]
            with patch.object(requests, "get", side_effect=replies):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(main.run(self.root, workers=2, timeout=1), 0)
            self.assertEqual((self.root / "http.txt").read_text(), f"127.0.0.1:{live_port}\n")
            self.assertEqual((self.root / "https.txt").read_text(), "")
            self.assertEqual(self.git("status", "--porcelain"), "")
            remote_snapshot = self.git("--git-dir", str(self.remote), "show", "refs/heads/main:http.txt")
            self.assertEqual(remote_snapshot, f"127.0.0.1:{live_port}")

    def test_scan_with_no_live_proxy_preserves_files_and_remote(self):
        commit = self.git("rev-parse", "HEAD")
        with proxy_server(200) as dead_port:
            with patch.object(main, "fetch_proxies", return_value={("http", "127.0.0.1", dead_port)}):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(main.run(self.root, workers=1, timeout=1), 1)
        self.assertEqual((self.root / "http.txt").read_text(), "before\n")
        self.assertEqual(self.git("rev-parse", "HEAD"), commit)
        self.assertEqual(commit, self.git("--git-dir", str(self.remote), "rev-parse", "refs/heads/main"))

    def test_interrupted_scan_preserves_files_and_remote(self):
        commit = self.git("rev-parse", "HEAD")
        with patch.object(main, "fetch_proxies", return_value={("http", "127.0.0.1", 80)}), \
                patch.object(main, "check", side_effect=KeyboardInterrupt):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main.run(self.root), 130)
        self.assertEqual((self.root / "http.txt").read_text(), "before\n")
        self.assertEqual(self.git("rev-parse", "HEAD"), commit)


if __name__ == "__main__":
    unittest.main()
