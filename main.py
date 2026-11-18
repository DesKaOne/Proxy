"""Fetch public proxy sources, validate candidates, and optionally publish live lists.

Requires: pip install 'requests[socks]'
Run: python proxy_fetcher.py --no-push --workers 300 --timeout 10
"""

from __future__ import annotations

import argparse
import importlib.util
import ipaddress
import math
import os
import re
import shutil
import subprocess
import tempfile
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextlib import contextmanager
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Iterator
from urllib.parse import parse_qs, unquote, urlsplit

import requests

ROOT = Path(__file__).resolve().parent
SOURCE_FILE = ROOT / "backup" / "source.txt"
FINEPROXY_URL = "https://fineproxy.org/data/free-proxies/all.json"
TRIUMPACTUM_URL = "https://triumpactum.com/ops/proxy/"
PROXYHUB_URL = "https://proxyhub.decosystem.my.id/proxy/"
PROTOCOLS = ("http", "https", "socks4", "socks5")
OUTPUT_FILES = tuple(f"{p}.txt" for p in PROTOCOLS)
CHECK_URL = "http://connectivitycheck.gstatic.com/generate_204"
SOURCE_TIMEOUT = (10, 35)
MAX_SOURCE_BYTES = 150 * 1024 * 1024
MAX_API_PAGES = 1000
HEADER = {"User-Agent": "DesKaOne-ProxyFetcher/1.0", "Accept": "text/plain, application/json, text/html;q=0.8, */*;q=0.5"}
Proxy = tuple[str, str, int]

PROTO_PATTERN = re.compile(r"(?<![a-z0-9])(socks5|socks4|https|http)(?![a-z0-9])", re.I)
SCHEME_PATTERN = re.compile(r"^(https?|socks[45])://", re.I)
IP_PORT_PATTERN = re.compile(r"^((?:\d{1,3}\.){3}\d{1,3}|\[[0-9a-fA-F:.]+\]):([0-9]{1,5})$")


def address(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def normalize_proxy(protocol: object, host: object, port: object) -> Proxy | None:
    try:
        protocol = str(protocol).strip().lower()
        if protocol not in PROTOCOLS or host is None or isinstance(port, bool):
            return None
        ip = ipaddress.ip_address(str(host).strip())
        # Daftar public proxy tidak boleh mengarah ke localhost/LAN/link-local.
        if not ip.is_global:
            return None
        port_string = str(port).strip()
        if not port_string.isascii() or not port_string.isdecimal():
            return None
        number = int(port_string)
        if 1 <= number <= 65535:
            return protocol, str(ip), number
    except (ValueError, TypeError):
        pass
    return None


def get_protocol(url: str) -> str:
    """Infer only from URL query/path, never from its http(s) transport scheme."""
    parsed = urlsplit(url)
    params = parse_qs(parsed.query, keep_blank_values=False)
    for name, values in params.items():
        if name.lower() not in {"proxytype", "protocol", "type"}:
            continue
        for value in values:
            value = value.strip().lower()
            if value in PROTOCOLS:
                return value
            if value in {"mixed", "all"}:
                return "mixed"
            if value in {"socks", "socks4/5"}:
                return "socks"

    path = unquote(parsed.path).lower()
    # spys.me exposes protocol information in its file contents/footer.
    if (parsed.hostname or "").lower() in {"spys.me", "www.spys.me"}:
        if path == "/socks.txt":
            return "socks5"
        if path == "/proxy.txt":
            return "http"
    protocols = set(PROTO_PATTERN.findall(path))
    if len(protocols) == 1:
        return protocols.pop().lower()
    if len(protocols) > 1 or re.search(r"(?<![a-z0-9])(?:all|mixed)(?![a-z0-9])", path):
        return "mixed"
    if re.search(r"(?<![a-z0-9])socks(?![a-z0-9])", path + " " + parsed.netloc.lower()):
        return "socks"
    return "unknown"


def parse_address(raw: str, protocol: str) -> Proxy | None:
    raw = raw.strip()
    # urlsplit rejects portless and extra path/query; also allows bracketed IPv6.
    try:
        parsed = urlsplit(raw if "://" in raw else "//" + raw)
        if parsed.username is not None or parsed.password is not None:
            return None
        if parsed.path or parsed.query or parsed.fragment:
            return None
        if parsed.scheme and parsed.scheme.lower() not in PROTOCOLS:
            return None
        resolved = parsed.scheme.lower() if parsed.scheme else protocol
        return normalize_proxy(resolved, parsed.hostname, parsed.port)
    except ValueError:
        return None


def parse_proxy_line(line: str, source_protocol: str) -> Proxy | None:
    """Accept ip:port, scheme://ip:port, ip:port PROTOCOL, PROTOCOL ip:port."""
    line = line.strip().lstrip("\ufeff")
    if not line or line.startswith(("#", "//", "<", "{", "IP address", "IP Address")):
        return None
    # Format prefix: SOCKS5 1.2.3.4:1080
    prefix = re.match(r"^(socks5|socks4|https|http)\s+", line, re.I)
    prefixed_protocol = prefix.group(1).lower() if prefix else None
    if prefix:
        line = line[prefix.end():]
    fields = line.split(None, 1)
    if not fields:
        return None
    token = fields[0].strip(",;|")
    metadata = fields[1] if len(fields) > 1 else ""

    # Fixed-prefix check: do not extract an IP embedded in HTML, URLs or unrelated text.
    raw_address = SCHEME_PATTERN.sub("", token)
    if not IP_PORT_PATTERN.fullmatch(raw_address):
        return None
    explicit_scheme = SCHEME_PATTERN.match(token)
    if explicit_scheme:
        protocol = explicit_scheme.group(1).lower()
    elif prefixed_protocol:
        protocol = prefixed_protocol
    else:
        # Example spys.me SOCKS rows include a version in their metadata.
        tags = {p.lower() for p in PROTO_PATTERN.findall(metadata)}
        for version in ("4", "5"):
            if re.search(r"(?<![a-z0-9])socks\s+" + version + r"(?![a-z0-9])", metadata, re.I):
                tags.add("socks" + version)
        if len(tags) > 1:
            return None
        protocol = next(iter(tags)) if tags else source_protocol
        # Unknown and mixed sources require an explicit per-row protocol.
        if protocol not in PROTOCOLS:
            return None
    return parse_address(token, protocol)


class ProxyTableParser(HTMLParser):
    """Extract simple table rows (IP Address, Port, Version/HTTPS)."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.table_depth = 0
        self.in_row = False
        self.cell_kind: str | None = None
        self.cell_text: list[str] = []
        self.cells: list[str] = []
        self.row_headers: list[bool] = []
        self.headers: list[str] = []
        self.entries: list[tuple[str, str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "table":
            self.table_depth += 1
            if self.table_depth == 1:
                self.headers = []
        elif tag == "tr" and self.table_depth:
            self.in_row = True
            self.cells = []
            self.row_headers = []
        elif tag in {"td", "th"} and self.in_row:
            self.cell_kind = tag
            self.cell_text = []

    def handle_data(self, data: str) -> None:
        if self.cell_kind:
            self.cell_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag in {"td", "th"} and self.cell_kind == tag:
            self.cells.append(" ".join("".join(self.cell_text).split()))
            self.row_headers.append(tag == "th")
            self.cell_kind = None
        elif tag == "tr" and self.in_row:
            self.in_row = False
            if any(self.row_headers):
                self.headers = [x.lower() for x in self.cells]
            elif self.headers and len(self.cells) >= len(self.headers):
                self._extract()
        elif tag == "table" and self.table_depth:
            self.table_depth -= 1

    def _extract(self) -> None:
        def idx(names: tuple[str, ...]) -> int | None:
            return next((i for i, h in enumerate(self.headers) if any(n in h for n in names)), None)

        ip_idx, port_idx = idx(("ip address", "ip", "host")), idx(("port",))
        if ip_idx is None or port_idx is None:
            return
        host, port = self.cells[ip_idx], self.cells[port_idx]
        version_idx = idx(("version", "protocol", "type"))
        https_idx = idx(("https", "ssl"))
        version = self.cells[version_idx] if version_idx is not None else ""
        if not version and https_idx is not None:
            version = "https" if self.cells[https_idx].lower() in {"yes", "true", "1"} else "http"
        self.entries.append((host, port, version))


def fetch_text(url: str) -> Iterator[str]:
    """Stream plain text. HTML table sources are decoded separately."""
    with requests.get(url, headers=HEADER, timeout=SOURCE_TIMEOUT, stream=True) as response:
        response.raise_for_status()
        ctype = response.headers.get("Content-Type", "").lower()
        if "text/html" in ctype:
            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_content(chunk_size=65536):
                total += len(chunk)
                if total > MAX_SOURCE_BYTES:
                    raise ValueError("source HTML terlalu besar")
                chunks.append(chunk)
            table = ProxyTableParser()
            table.feed(b"".join(chunks).decode(response.encoding or "utf-8", errors="replace"))
            for host, port, version in table.entries:
                yield f"{host}:{port} {version}"
            return
        total = 0
        for line in response.iter_lines(chunk_size=16384):
            total += len(line) + 1
            if total > MAX_SOURCE_BYTES:
                raise ValueError(f"source melebihi {MAX_SOURCE_BYTES // 1048576} MiB")
            yield line.decode("utf-8", errors="replace")


def fetch_rows(url: str, key: str, **kwargs: object) -> dict:
    with requests.get(url, headers=HEADER, timeout=SOURCE_TIMEOUT, **kwargs) as response:
        response.raise_for_status()
        data = response.json()
    if not isinstance(data, dict) or not isinstance(data.get(key), list):
        raise ValueError(f"Format sumber proxy tidak valid: {url}")
    return data


def fetch_txt_sources(proxies: set[Proxy], file: Path, probe_unknown: bool = False) -> None:
    if not file.is_file():
        print(f"[WARN] File source tidak ditemukan: {file}", flush=True)
        return
    with file.open("r", encoding="utf-8-sig") as source_list:
        for line in source_list:
            url = line.strip()
            if not url or url.startswith("#"):
                continue
            if urlsplit(url).scheme not in {"https", "http"}:
                print(f"[SKIP] URL source tidak valid: {url}", flush=True)
                continue
            inferred = get_protocol(url)
            parsed_url = urlsplit(url)
            is_spys_http = (parsed_url.hostname or "").lower() in {"spys.me", "www.spys.me"} and parsed_url.path == "/proxy.txt"
            added, skipped = 0, 0
            try:
                for row in fetch_text(url):
                    proxy = parse_proxy_line(row, inferred)
                    if proxy is None:
                        if probe_unknown and inferred in {"unknown", "mixed", "socks"}:
                            # Explicit opt-in: test unlabelled IP:port with several protocols.
                            guesses = ("socks4", "socks5") if inferred == "socks" else PROTOCOLS
                            found = False
                            for guess in guesses:
                                possible = parse_proxy_line(row, guess)
                                if possible:
                                    found = True
                                    if possible not in proxies:
                                        proxies.add(possible)
                                        added += 1
                            if found:
                                continue
                        skipped += 1
                        continue
                    if proxy not in proxies:
                        proxies.add(proxy)
                        added += 1
                    # In spys.me/proxy.txt, "-S" means SSL/HTTPS support.
                    # Keep the HTTP entry and additionally check it as HTTPS.
                    fields = row.split()
                    if (is_spys_http and len(fields) > 1 and
                            re.fullmatch(r"[A-Za-z]{2}-[NAHnah]!?-S!?", fields[1])):
                        https_proxy = ("https", proxy[1], proxy[2])
                        if https_proxy not in proxies:
                            proxies.add(https_proxy)
                            added += 1
                print(f"[SOURCE] {inferred:7} +{added:,} | baris diabaikan={skipped:,} | {url}", flush=True)
            except (requests.RequestException, UnicodeError, ValueError, OSError) as exc:
                print(f"[WARN] Source gagal: {url} ({type(exc).__name__}: {exc})", flush=True)


def fetch_fineproxy(proxies: set[Proxy]) -> None:
    try:
        rows = fetch_rows(FINEPROXY_URL, "rows")["rows"]
        added = 0
        for row in rows:
            if not isinstance(row, dict):
                continue
            protocols = row.get("protos") or row.get("protocols") or []
            if isinstance(protocols, str):
                protocols = [protocols]
            if not isinstance(protocols, list):
                continue
            for protocol in protocols:
                proxy = normalize_proxy(protocol, row.get("ip"), row.get("port"))
                if proxy and proxy not in proxies:
                    proxies.add(proxy)
                    added += 1
        print(f"[FINEPROXY] +{added:,} proxy", flush=True)
    except (requests.RequestException, ValueError, OSError) as exc:
        print(f"[WARN] FineProxy gagal: {exc}", flush=True)


def fetch_paginated(proxies: set[Proxy], base_url: str, alive: str) -> None:
    for protocol in PROTOCOLS:
        added = 0
        seen: set[str] = set()
        for page in range(1, MAX_API_PAGES + 1):
            try:
                data = fetch_rows(base_url.rstrip("/") + "/" + protocol, "proxies", params={
                    "alive": alive, "limit": 10000, "page": page,
                })
            except (requests.RequestException, ValueError, OSError) as exc:
                print(f"[WARN] API gagal: {base_url}{protocol} page={page}: {exc}", flush=True)
                break
            rows = data["proxies"]
            if not rows:
                break
            # Protect against buggy API pagination repeating the same page forever.
            signature = f"{len(rows)}:{str(rows[0])[:150]}:{str(rows[-1])[:150]}"
            if signature in seen:
                print(f"[WARN] Page API terulang: {base_url}{protocol} page={page}", flush=True)
                break
            seen.add(signature)
            for row in rows:
                raw = row.get("address") if isinstance(row, dict) else row
                if not isinstance(raw, str):
                    continue
                proxy = parse_address(raw, protocol)
                if proxy and proxy not in proxies:
                    proxies.add(proxy)
                    added += 1
            if not data.get("has_next"):
                break
        else:
            print(f"[WARN] API melewati batas {MAX_API_PAGES} halaman: {base_url}{protocol}", flush=True)
        print(f"[API] {base_url} {protocol} alive={alive}: +{added:,}", flush=True)


def fetch_proxies(source_file: Path, probe_unknown: bool = False) -> set[Proxy]:
    proxies: set[Proxy] = set()
    fetch_txt_sources(proxies, source_file, probe_unknown=probe_unknown)
    fetch_fineproxy(proxies)
    fetch_paginated(proxies, TRIUMPACTUM_URL, "true")
    fetch_paginated(proxies, PROXYHUB_URL, "true")
    fetch_paginated(proxies, PROXYHUB_URL, "false")
    if not proxies:
        raise ValueError("Tidak ada kandidat valid; daftar lama tidak diubah")
    return proxies


def check(protocol: str, host: str, port: int, timeout: float = 10) -> bool:
    # HTTPS means an HTTP proxy that supports CONNECT to HTTPS destinations.
    scheme = "http" if protocol == "https" else ("socks5h" if protocol == "socks5" else protocol)
    proxy_url = f"{scheme}://{address(host, port)}"
    test_url = CHECK_URL.replace("http://", "https://", 1) if protocol == "https" else CHECK_URL
    try:
        with requests.Session() as session:
            session.trust_env = False
            with session.get(
                test_url,
                proxies={"http": proxy_url, "https": proxy_url},
                timeout=timeout, allow_redirects=False, stream=True,
            ) as response:
                return response.status_code == 204
    except (requests.RequestException, ValueError):
        return False


def save_results(directory: Path, entries: set[Proxy], *, allow_empty: bool = False) -> None:
    """Write the 4 output files with per-file atomic replacement and rollback."""
    if not entries and not allow_empty:
        raise ValueError("Daftar kosong: snapshot lama dipertahankan")
    directory.mkdir(parents=True, exist_ok=True)
    prepared: list[tuple[Path, Path, Path | None]] = []
    temporaries: list[Path] = []
    replaced: list[tuple[Path, Path | None]] = []
    keep_old_temp = False
    try:
        for protocol in PROTOCOLS:
            target = directory / f"{protocol}.txt"
            # Stream-copy old file instead of reading it all into RAM.
            backup: Path | None = None
            if target.exists():
                fd, name = tempfile.mkstemp(prefix=".proxy-old-", suffix=".tmp", dir=directory)
                os.close(fd)
                backup = Path(name)
                temporaries.append(backup)
                shutil.copyfile(target, backup)
            fd, name = tempfile.mkstemp(prefix=".proxy-new-", suffix=".tmp", dir=directory)
            source = Path(name)
            temporaries.append(source)
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as output:
                for hostport in sorted({address(h, p) for kind, h, p in entries if kind == protocol}):
                    output.write(hostport + "\n")
            prepared.append((source, target, backup))
        for source, target, backup in prepared:
            os.replace(source, target)
            replaced.append((target, backup))
    except BaseException:
        keep_old_temp = True
        try:
            for target, backup in reversed(replaced):
                if backup is None:
                    target.unlink(missing_ok=True)
                else:
                    os.replace(backup, target)
        except OSError as exc:
            raise RuntimeError(f"Rollback gagal; periksa .proxy-old-*.tmp dalam {directory}") from exc
        keep_old_temp = False
        raise
    finally:
        for path in temporaries:
            if not keep_old_temp or path.name.startswith(".proxy-new-"):
                path.unlink(missing_ok=True)


def save_previous_snapshot(directory: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for filename in OUTPUT_FILES:
        source = directory / filename
        if source.is_file():
            shutil.copy2(source, destination / filename)


@contextmanager
def scan_lock(directory: Path) -> Iterator[None]:
    with (directory / ".proxy-update-v2.lock").open("a+b") as lock:
        if os.name == "nt":
            import msvcrt

            lock.seek(0)
            if not lock.read(1):
                lock.write(b"\0")
                lock.flush()
            lock.seek(0)
            try:
                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise RuntimeError("Scan lain sedang berjalan di repo ini") from exc
        else:
            import fcntl

            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise RuntimeError("Scan lain sedang berjalan di repo ini") from exc
        try:
            yield
        finally:
            if os.name == "nt":
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(lock, fcntl.LOCK_UN)


def git(directory: Path, *args: str, allowed: tuple[int, ...] = (0,)) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never"}
    try:
        result = subprocess.run(
            ["git", *args], cwd=directory, env=env,
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"Git {args[0]} gagal dijalankan") from exc
    if result.returncode not in allowed:
        message = result.stderr.strip()[:500] or "Periksa konfigurasi Git dan koneksi"
        raise RuntimeError(f"Git {args[0]} gagal (exit {result.returncode}): {message}")
    return result


def git_target(directory: Path) -> tuple[str, str]:
    top = git(directory, "rev-parse", "--show-toplevel").stdout.strip()
    if Path(top).resolve() != directory.resolve():
        raise RuntimeError("Script harus berada di root repo Git")
    branch = git(directory, "symbolic-ref", "--quiet", "--short", "HEAD").stdout.strip()
    remote = git(directory, "config", "--get", f"branch.{branch}.remote", allowed=(0, 1)).stdout.strip()
    ref = git(directory, "config", "--get", f"branch.{branch}.merge", allowed=(0, 1)).stdout.strip()
    if not remote or remote == "." or not ref.startswith("refs/heads/"):
        raise RuntimeError("Git upstream belum diatur (git push -u origin <branch>)")
    if git(directory, "ls-files", "--unmerged").stdout.strip():
        raise RuntimeError("Selesaikan konflik Git lebih dulu")
    return remote, ref


def publish_results(directory: Path) -> None:
    remote, ref = git_target(directory)
    git(directory, "add", "--", *OUTPUT_FILES)
    changed = git(directory, "diff", "--cached", "--quiet", "--", *OUTPUT_FILES, allowed=(0, 1))
    if changed.returncode == 1:
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        git(directory, "commit", "--only", "-m", f"chore: update live proxies ({stamp})", "--", *OUTPUT_FILES)
        print("[GIT] Commit hasil scan berhasil", flush=True)
    else:
        print("[GIT] Tidak ada perubahan file", flush=True)
    git(directory, "push", "--", remote, f"HEAD:{ref}")
    print("[GIT] Push ke upstream berhasil", flush=True)


def scan_candidates(candidates: set[Proxy], workers: int, timeout: float) -> tuple[set[Proxy], set[Proxy]]:
    """Limit outstanding futures to 2*workers, even for millions of proxies."""
    live: set[Proxy] = set()
    dead: set[Proxy] = set()
    iterator = iter(candidates)
    completed = 0
    pending = {}
    with ThreadPoolExecutor(max_workers=workers) as executor:
        def enqueue_one() -> bool:
            try:
                proxy = next(iterator)
            except StopIteration:
                return False
            pending[executor.submit(check, *proxy, timeout=timeout)] = proxy
            return True

        for _ in range(min(workers * 2, len(candidates))):
            enqueue_one()
        try:
            while pending:
                finished, _ = wait(pending, return_when=FIRST_COMPLETED)
                for future in finished:
                    proxy = pending.pop(future)
                    if future.result():
                        live.add(proxy)
                    else:
                        dead.add(proxy)
                    completed += 1
                    if completed % 1000 == 0 or completed == len(candidates):
                        print(f"[CHECK] {completed:,}/{len(candidates):,} | hidup={len(live):,} | mati={len(dead):,}", flush=True)
                    enqueue_one()
        except KeyboardInterrupt:
            for future in pending:
                future.cancel()
            # Wait for running tasks to finish before this function raises.
            raise
    return live, dead


def _run(directory: Path, source_file: Path, workers: int, timeout: float,
         push: bool, probe_unknown: bool) -> int:
    try:
        if push:
            git_target(directory)
        if importlib.util.find_spec("socks") is None:
            raise RuntimeError('PySocks belum terpasang. Install: python -m pip install "requests[socks]"')

        candidates = fetch_proxies(source_file, probe_unknown=probe_unknown)
        print(f"[INFO] Kandidat unik: {len(candidates):,} | workers={workers} | timeout={timeout}s", flush=True)

        snapshot = directory / ("backup-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%fZ"))
        save_results(snapshot / "raw", candidates)
        live, dead = scan_candidates(candidates, workers, timeout)
        if not live:
            raise ValueError("Semua proxy gagal dites; output lama tetap dipertahankan")

        save_previous_snapshot(directory, snapshot / "previous")
        save_results(directory / "dead", dead, allow_empty=True)
        save_results(directory, live)
        for protocol in PROTOCOLS:
            count = sum(p[0] == protocol for p in live)
            print(f"[SAVED] {protocol}.txt: {count:,} hidup", flush=True)
        print(f"[BACKUP] {snapshot}", flush=True)
        if push:
            publish_results(directory)
        else:
            print("[INFO] --no-push: hasil lokal saja", flush=True)
        return 0
    except KeyboardInterrupt:
        print("\n[STOP] Dihentikan; hasil parsial tidak dipublikasikan", flush=True)
        return 130
    except (requests.RequestException, ValueError, OSError, RuntimeError) as exc:
        print(f"[ERROR] {exc}", flush=True)
        return 1


def run(directory: Path = ROOT, source_file: Path = SOURCE_FILE, workers: int = 300,
        timeout: float = 15, push: bool = True, probe_unknown: bool = False) -> int:
    directory = Path(directory).resolve()
    try:
        with scan_lock(directory):
            return _run(directory, Path(source_file), workers, timeout, push, probe_unknown)
    except (OSError, RuntimeError) as exc:
        print(f"[ERROR] {exc}", flush=True)
        return 1


def cli() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workers", type=int, default=300, help="1..1000, default 300")
    parser.add_argument("--timeout", type=float, default=15, help="Timeout per proxy, default 15s")
    parser.add_argument("--source-file", type=Path, default=SOURCE_FILE, help="Daftar URL TXT")
    parser.add_argument("--no-push", action="store_true", help="Tidak commit/push ke Git")
    parser.add_argument("--probe-unknown", action="store_true",
                        help="Uji semua protokol untuk IP:port tanpa label pada source mixed/unknown")
    args = parser.parse_args()
    if not 1 <= args.workers <= 1000 or not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--workers harus 1..1000 dan --timeout harus positif serta finite")
    return run(source_file=args.source_file, workers=args.workers, timeout=args.timeout,
               push=not args.no_push, probe_unknown=args.probe_unknown)


if __name__ == "__main__":
    raise SystemExit(cli())
