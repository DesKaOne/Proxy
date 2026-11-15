"""Fetch, check, and publish the repository's live proxy lists."""

import argparse
import importlib.util
import ipaddress
import math
import os
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import requests

SOURCE_URL = "https://fineproxy.org/data/free-proxies/all.json"
TRIUMPACTUM_URL = "https://triumpactum.com/ops/proxy/"
PROTOCOLS = ("http", "https", "socks4", "socks5")
OUTPUT_FILES = tuple(f"{protocol}.txt" for protocol in PROTOCOLS)
CHECK_URL = "http://connectivitycheck.gstatic.com/generate_204"
ROOT = Path(__file__).resolve().parent


def normalize_proxy(protocol, host, port):
    """Discard malformed source entries before they reach the checker."""
    try:
        protocol = str(protocol).strip().lower()
        host = str(ipaddress.ip_address(str(host).strip()))
        if isinstance(port, bool) or not str(port).isdigit():
            return None
        port = int(port)
        if protocol in PROTOCOLS and 1 <= port <= 65535:
            return protocol, host, port
    except ValueError:
        pass
    return None


def address(host, port):
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def fetch_rows(url, key, **kwargs):
    with requests.get(url, timeout=30, **kwargs) as response:
        response.raise_for_status()
        data = response.json()
    if not isinstance(data, dict) or not isinstance(data.get(key), list):
        raise ValueError(f"Format sumber proxy tidak valid: {url}")
    return data


def fetch_proxies():
    """Merge both sources, including every page, without duplicate checks."""
    proxies = set()
    rows = fetch_rows(SOURCE_URL, "rows")["rows"]
    for row in rows:
        if not isinstance(row, dict):
            continue
        protocols = row.get("protos") or ["http"]
        if isinstance(protocols, str):
            protocols = [protocols]
        if not isinstance(protocols, list):
            continue
        for protocol in protocols:
            proxy = normalize_proxy(protocol, row.get("ip"), row.get("port"))
            if proxy:
                proxies.add(proxy)

    for protocol in PROTOCOLS:
        offset = 0
        while True:
            data = fetch_rows(
                TRIUMPACTUM_URL + protocol, "proxies",
                params={"alive": "true", "limit": 10000, "offset": offset},
            )
            for row in data["proxies"]:
                if not isinstance(row, dict) or not isinstance(row.get("address"), str):
                    continue
                try:
                    parsed = urlsplit("//" + row["address"].strip())
                    if parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
                        continue
                    proxy = normalize_proxy(protocol, parsed.hostname, parsed.port)
                except ValueError:
                    continue
                if proxy:
                    proxies.add(proxy)
            if not data.get("has_next"):
                break
            limit = data.get("limit")
            if (not data["proxies"] or type(limit) is not int or limit <= 0
                    or data.get("offset") != offset):
                raise ValueError(f"Pagination sumber {protocol} tidak valid")
            offset += limit
    if not proxies:
        raise ValueError("Sumber tidak mengembalikan kandidat proxy yang valid")
    return proxies


def check(protocol, host, port, timeout=10):
    # HTTPS lists describe HTTP proxies supporting CONNECT, not TLS to the proxy.
    scheme = "http" if protocol == "https" else protocol
    proxy_url = f"{scheme}://{address(host, port)}"
    test_url = CHECK_URL.replace("http://", "https://", 1) if protocol == "https" else CHECK_URL
    try:
        with requests.Session() as session:
            session.trust_env = False
            with session.get(
                test_url, proxies={"http": proxy_url, "https": proxy_url},
                timeout=timeout, allow_redirects=False, stream=True,
            ) as response:
                return response.status_code == 204
    except (requests.RequestException, ValueError):
        return False


def save_results(directory, live):
    """Replace old snapshots only after the entire scan has succeeded."""
    if not live:
        raise ValueError("Tidak ada proxy hidup; file lama dipertahankan dan tidak di-push")
    temporary = []
    replacements = []
    replaced = []
    keep_backups = False

    def prepare(content):
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=directory, prefix=".proxy-", suffix=".tmp", delete=False,
        ) as output:
            path = Path(output.name)
            temporary.append(path)
            output.write(content)
        return path

    try:
        for protocol in PROTOCOLS:
            entries = sorted({address(host, port) for kind, host, port in live if kind == protocol})
            target = Path(directory) / f"{protocol}.txt"
            backup = prepare(target.read_bytes()) if target.exists() else None
            source = prepare("".join(entry + "\n" for entry in entries).encode("utf-8"))
            replacements.append((source, target, backup))
        for source, target, backup in replacements:
            os.replace(source, target)
            replaced.append((target, backup))
    except BaseException:
        keep_backups = True
        try:
            for target, backup in reversed(replaced):
                if backup is None:
                    target.unlink(missing_ok=True)
                else:
                    os.replace(backup, target)
        except OSError as exc:
            raise RuntimeError(f"Pemulihan file gagal; salinan lama dipertahankan di {directory}/.proxy-*.tmp") from exc
        keep_backups = False
        raise
    finally:
        backups = {backup for _, _, backup in replacements}
        for path in temporary:
            if not keep_backups or path not in backups:
                path.unlink(missing_ok=True)


@contextmanager
def scan_lock(directory):
    """Hold an OS lock through scanning, snapshot replacement, and Git push."""
    with (Path(directory) / ".proxy-update.lock").open("a+b") as lock:
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
                raise RuntimeError("Pemeriksaan lain sedang berjalan di repo ini") from exc
        else:
            import fcntl

            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise RuntimeError("Pemeriksaan lain sedang berjalan di repo ini") from exc
        try:
            yield
        finally:
            if os.name == "nt":
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(lock, fcntl.LOCK_UN)


def git(directory, *args, allowed=(0,)):
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never"}
    try:
        result = subprocess.run(
            ["git", *args], cwd=directory, env=env, capture_output=True,
            text=True, encoding="utf-8", errors="replace", timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"Git {args[0]} tidak dapat diselesaikan") from exc
    if result.returncode not in allowed:
        hint = "Periksa konfigurasi Git dan akses repo."
        if args[0] == "push":
            hint = "Hasil lokal tersimpan. Periksa login/akses dan perubahan remote, lalu ulangi; tidak memakai force push."
        raise RuntimeError(f"Git {args[0]} gagal (exit {result.returncode}). {hint}")
    return result


def git_target(directory):
    top = git(directory, "rev-parse", "--show-toplevel").stdout.strip()
    if Path(top).resolve() != Path(directory).resolve():
        raise RuntimeError("main.py harus berada di root repo proxy")
    branch = git(directory, "symbolic-ref", "--quiet", "--short", "HEAD").stdout.strip()
    remote = git(directory, "config", "--get", f"branch.{branch}.remote", allowed=(0, 1)).stdout.strip()
    ref = git(directory, "config", "--get", f"branch.{branch}.merge", allowed=(0, 1)).stdout.strip()
    if not remote or remote == "." or not ref.startswith("refs/heads/"):
        raise RuntimeError("Upstream belum diatur. Jalankan git push -u origin <branch> terlebih dahulu")
    if git(directory, "ls-files", "--unmerged").stdout.strip():
        raise RuntimeError("Selesaikan konflik Git sebelum memperbarui proxy")
    return remote, ref


def publish_results(directory):
    """Commit only generated files, leaving other staged owner work intact."""
    remote, ref = git_target(directory)
    git(directory, "add", "--", *OUTPUT_FILES)
    changed = git(directory, "diff", "--cached", "--quiet", "--", *OUTPUT_FILES, allowed=(0, 1))
    if changed.returncode == 1:
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        git(directory, "commit", "--only", "-m", f"chore: update live proxies ({stamp})", "--", *OUTPUT_FILES)
        print("[GIT] Hasil proxy di-commit")
    else:
        print("[GIT] Hasil tidak berubah; tidak membuat commit kosong")
    # Retry an earlier failed push even when this scan has identical results.
    git(directory, "push", "--", remote, f"HEAD:{ref}")
    print("[GIT] Push berhasil ke upstream branch saat ini")


def _run(directory, workers, timeout, push):
    try:
        if push:
            git_target(directory)
        if importlib.util.find_spec("socks") is None:
            raise RuntimeError('Dukungan SOCKS belum terpasang. Jalankan python -m pip install "requests[socks]"')
        candidates = fetch_proxies()
        print(f"[INFO] Memeriksa {len(candidates)} proxy unik dengan {workers} worker", flush=True)
        live = set()
        executor = ThreadPoolExecutor(max_workers=workers)
        try:
            futures = {executor.submit(check, *proxy, timeout=timeout): proxy for proxy in sorted(candidates)}
            for completed, future in enumerate(as_completed(futures), 1):
                proxy = futures[future]
                if future.result():
                    live.add(proxy)
                    print(f"[SUCCESS] {proxy[0]}://{address(proxy[1], proxy[2])}", flush=True)
                if completed % 100 == 0 or completed == len(candidates):
                    print(f"[INFO] Selesai {completed}/{len(candidates)}, hidup {len(live)}", flush=True)
        finally:
            executor.shutdown(wait=True, cancel_futures=True)
        save_results(directory, live)
        for protocol in PROTOCOLS:
            count = sum(kind == protocol for kind, _, _ in live)
            print(f"[SAVED] {protocol}.txt: {count} proxy hidup")
        if push:
            publish_results(directory)
        else:
            print("[INFO] --no-push: hasil disimpan tanpa commit/push")
        return 0
    except KeyboardInterrupt:
        print("\n[STOP] Pemeriksaan dihentikan; hasil parsial tidak dipublikasikan")
        return 130
    except (requests.RequestException, ValueError, OSError, RuntimeError) as exc:
        print(f"[ERROR] {exc}")
        return 1


def run(directory=ROOT, workers=100, timeout=10, push=True):
    try:
        with scan_lock(directory):
            return _run(directory, workers, timeout, push)
    except (OSError, RuntimeError) as exc:
        print(f"[ERROR] {exc}")
        return 1


def cli():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workers", type=int, default=100, help="Jumlah pemeriksaan paralel (default: 100)")
    parser.add_argument("--timeout", type=float, default=10, help="Timeout koneksi/baca per proxy dalam detik (default: 10)")
    parser.add_argument("--no-push", action="store_true", help="Simpan hasil tanpa commit/push")
    args = parser.parse_args()
    if not 1 <= args.workers <= 512 or not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--workers harus 1..512 dan --timeout harus positif serta terbatas")
    return run(workers=args.workers, timeout=args.timeout, push=not args.no_push)


if __name__ == "__main__":
    raise SystemExit(cli())
