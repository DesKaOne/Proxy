#!/usr/bin/env python3
"""Proxy discovery checkpointed (hanya untuk jaringan yang Anda kelola/diizinkan).

Baca seed 1 per 1, ambil prefix, scan, simpan hasil dan checkpoint,
lalu lanjut ke seed berikutnya. Progres tersimpan di new/checkpoint.sqlite3.
Jalankan: python proxy_discovery_checkpoint.py (tanpa argumen CLI).
"""
from __future__ import annotations

from bisect import bisect_right
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from contextlib import ExitStack
import hashlib
import ipaddress
import json
import sqlite3
import time
from pathlib import Path
import socket
import threading
from typing import Iterator, NamedTuple
from urllib.parse import urlsplit

import requests

# ========================= SETTINGS =========================
ROOT = Path(__file__).resolve().parent
INPUT_FILES = ["backup/ips.txt"]
OUTPUT_DIR = ROOT / "new"
CHECKPOINT_DB = OUTPUT_DIR / "checkpoint.sqlite3"
PORTS = (
    80, 81, 443, 8000, 8001, 8002, 8003, 8008, 8010,
    8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090,
    8443, 8880, 8881, 8888, 8889,
    3127, 3128, 3129, 3130, 3131, 8118, 8123,
    1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088,
    10808, 10809, 9050, 9150,
    1111, 2080, 2081, 4145, 4153, 5555, 7080,
    7890, 7891, 7892, 9000, 9001, 9090, 9091, 9999, 10000,
)
WORKERS = 1000
TCP_TIMEOUT = 5
HTTP_TIMEOUT = 5
PROGRESS_EVERY = 1000
CHECKPOINT_BATCH = 5000           # Simpan progres setelah N IP:port selesai
RESET_CHECKPOINT = False         # True = ulang semua seed dan CIDR dari awal
ASK_BEFORE_SCAN = True
SHOW_RIR_METADATA = True       # File delegated-*-latest hanya untuk informasi alokasi
# ============================================================

RIPE_URL = "https://stat.ripe.net/data/network-info/data.json"
IPINFO_URL = "https://ipinfo.decosystem.my.id/"
PROTOCOLS = {"http": "http", "https": "https", "socks4": "socks4", "socks5": "socks5h"}
_tls = threading.local()


def http_session() -> requests.Session:
    """Session Requests per worker (tidak berbagi state mutable)."""
    session = getattr(_tls, "session", None)
    if session is None:
        session = requests.Session()
        session.trust_env = False
        session.headers.update({"User-Agent": "subnet-proxy-experiment/1.1"})
        _tls.session = session
    return session


class SeedEntry(NamedTuple):
    source: str
    line_no: int
    ip: ipaddress.IPv4Address | None
    start_offset: int
    end_offset: int
    digest: str


def parse_seed(raw: str) -> ipaddress.IPv4Address | None:
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return None
    try:
        url = raw if "://" in raw else "//" + raw
        host = urlsplit(url).hostname
        if host is None:
            return None
        result = ipaddress.ip_address(host)
        return result if isinstance(result, ipaddress.IPv4Address) else None
    except ValueError:
        return None


def iter_seed_entries(checkpoint: "Checkpoint") -> Iterator[SeedEntry]:
    """Streaming per file, dimulai dari byte offset checkpoint masing-masing."""
    seen_in_run: set[ipaddress.IPv4Address] = set()
    for filename in INPUT_FILES:
        path = ROOT / filename
        if not path.is_file():
            print(f"[SKIP] File tidak ditemukan: {filename}", flush=True)
            continue
        position, lineno = checkpoint.resume_file(filename, path)
        print(f"[INPUT] {filename} | resume baris={lineno + 1} offset={position:,}", flush=True)
        with path.open("rb") as stream:
            stream.seek(position)
            while True:
                start = stream.tell()
                raw_bytes = stream.readline()
                if not raw_bytes:
                    break
                end = stream.tell()
                lineno += 1
                ip = parse_seed(raw_bytes.decode("utf-8-sig", errors="replace"))
                if ip in seen_in_run:
                    ip = None
                elif ip is not None:
                    seen_in_run.add(ip)
                yield SeedEntry(
                    filename, lineno, ip, start, end,
                    hashlib.sha256(raw_bytes).hexdigest(),
                )


class Checkpoint:
    """Checkpoint durable: posisi seed, CIDR selesai, dan indeks target per CIDR."""

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS meta (
                name TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS seed_cursors (
                source TEXT PRIMARY KEY,
                next_offset INTEGER NOT NULL,
                next_line INTEGER NOT NULL,
                last_start INTEGER NOT NULL,
                last_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS completed_prefixes (
                prefix TEXT PRIMARY KEY
            );
            CREATE TABLE IF NOT EXISTS prefix_progress (
                prefix TEXT PRIMARY KEY,
                next_index INTEGER NOT NULL,
                target_count INTEGER NOT NULL
            );
        """)
        config = json.dumps({"ports": PORTS, "protocols": PROTOCOLS, "ipinfo_url": IPINFO_URL},
                            sort_keys=True)
        config_hash = hashlib.sha256(config.encode()).hexdigest()
        previous = self.db.execute(
            "SELECT value FROM meta WHERE name = 'scan_signature'"
        ).fetchone()
        if RESET_CHECKPOINT:
            with self.db:
                for table in ("seed_cursors", "completed_prefixes", "prefix_progress"):
                    self.db.execute(f"DELETE FROM {table}")
                self.db.execute("DELETE FROM meta WHERE name = 'scan_signature'")
            print("[RESET] Checkpoint direset. File hasil proxy tidak dihapus.", flush=True)
            previous = None
        if previous and previous[0] != config_hash:
            self.db.close()
            raise RuntimeError(
                "PORTS/PROTOCOLS/IPINFO_URL berubah sejak checkpoint dibuat. "
                "Ubah RESET_CHECKPOINT=True sekali untuk scan ulang secara sadar "
                "(atau kembalikan pengaturan lama)."
            )
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO meta(name,value) VALUES(?,?)",
                            ("scan_signature", config_hash))

    def resume_file(self, source: str, path: Path) -> tuple[int, int]:
        found = self.db.execute(
            "SELECT next_offset, next_line, last_start, last_hash "
            "FROM seed_cursors WHERE source=?", (source,)
        ).fetchone()
        if not found:
            return 0, 0
        offset, line, last_start, last_hash = found
        # Tidak membandingkan mtime: append di akhir file boleh dilanjutkan.
        # Verifikasi baris terakhir yang sudah selesai belum bergeser.
        if not 0 <= last_start < offset <= path.stat().st_size:
            print(f"[WARN] {source} berubah/dipotong, reset kursor input.", flush=True)
            return 0, 0
        with path.open("rb") as stream:
            stream.seek(last_start)
            content = stream.read(offset - last_start)
        if hashlib.sha256(content).hexdigest() != last_hash:
            print(f"[WARN] {source} berubah dekat checkpoint, reset kursor input.", flush=True)
            return 0, 0
        return offset, line

    def complete_line(self, entry: SeedEntry) -> None:
        with self.db:
            self.db.execute(
                "INSERT INTO seed_cursors(source,next_offset,next_line,last_start,last_hash) "
                "VALUES(?,?,?,?,?) ON CONFLICT(source) DO UPDATE SET "
                "next_offset=excluded.next_offset,next_line=excluded.next_line," 
                "last_start=excluded.last_start,last_hash=excluded.last_hash",
                (entry.source, entry.end_offset, entry.line_no, entry.start_offset, entry.digest),
            )

    def completed(self) -> list[ipaddress.IPv4Network]:
        networks = [ipaddress.IPv4Network(row[0]) for row in self.db.execute(
            "SELECT prefix FROM completed_prefixes")]
        return list(ipaddress.collapse_addresses(networks))

    def next_target(self, prefix: ipaddress.IPv4Network, total: int) -> int:
        found = self.db.execute(
            "SELECT next_index,target_count FROM prefix_progress WHERE prefix=?",
            (str(prefix),),
        ).fetchone()
        if not found:
            return 0
        offset, previous_total = found
        if previous_total != total or not 0 <= offset <= total:
            raise RuntimeError(f"Checkpoint bagian {prefix} tidak cocok dengan jumlah target.")
        return offset

    def advance(self, prefix: ipaddress.IPv4Network, next_index: int, total: int) -> None:
        with self.db:
            self.db.execute(
                "INSERT INTO prefix_progress(prefix,next_index,target_count) VALUES(?,?,?) "
                "ON CONFLICT(prefix) DO UPDATE SET "
                "next_index=excluded.next_index,target_count=excluded.target_count",
                (str(prefix), next_index, total),
            )

    def complete_prefix(self, prefix: ipaddress.IPv4Network) -> None:
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO completed_prefixes(prefix) VALUES(?)",
                            (str(prefix),))
            self.db.execute("DELETE FROM prefix_progress WHERE prefix=?", (str(prefix),))

    def close(self) -> None:
        self.db.close()


def bgp_prefix(ip: ipaddress.IPv4Address) -> tuple[ipaddress.IPv4Network, list]:
    """Ambil BGP prefix. Jika API gagal, jangan tandai seed sudah selesai."""
    if ip.is_private:
        # Untuk eksperimen LAN, prefix /24 hanyalah default lokal (bukan BGP).
        return ipaddress.IPv4Network(f"{ip}/24", strict=False), []
    if not ip.is_global:
        return ipaddress.IPv4Network(f"{ip}/32"), []
    last_error: Exception | None = None
    for attempt in range(1, 4):
        try:
            response = http_session().get(RIPE_URL, params={"resource": str(ip)},
                                          timeout=(4, 10))
            response.raise_for_status()
            data = response.json().get("data") or {}
            raw = data.get("prefix")
            if not raw:  # IP yang tidak diumumkan boleh memakai /32
                print(f"[BGP TIDAK ADA] {ip}, hanya IP seed (/32)", flush=True)
                return ipaddress.IPv4Network(f"{ip}/32"), []
            network = ipaddress.ip_network(raw, strict=False)
            if not isinstance(network, ipaddress.IPv4Network) or ip not in network:
                raise ValueError(f"prefix tidak sesuai: {raw}")
            return network, data.get("asns") or []
        except (requests.RequestException, ValueError, TypeError, AttributeError) as exc:
            last_error = exc
            print(f"[WARN] RIPEstat {ip} percobaan {attempt}/3: {exc}", flush=True)
            if attempt < 3:
                time.sleep(attempt)
    raise RuntimeError(f"RIPEstat gagal untuk {ip}; seed belum di-checkpoint") from last_error


def build_rir_index() -> tuple[list[int], list[tuple]]:
    """Indeks metadata RIR sekali saja; tidak memperluas target scan."""
    if not SHOW_RIR_METADATA:
        return [], []
    rows: list[tuple] = []
    for path in sorted(ROOT.glob("delegated-*-latest")):
        if not path.is_file():
            continue
        print(f"[RIR] Membaca metadata: {path.name}", flush=True)
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            for line in stream:
                if "|ipv4|" not in line or line.startswith("#"):
                    continue
                cols = line.rstrip("\n").split("|")
                if len(cols) < 7 or cols[2] != "ipv4":
                    continue
                try:
                    first = int(ipaddress.IPv4Address(cols[3]))
                    count = int(cols[4])
                    if count < 1 or first + count > 2**32:
                        continue
                except ValueError:
                    continue
                rows.append((first, first + count - 1, cols[0], cols[1], count, cols[6]))
    rows.sort(key=lambda entry: entry[0])
    return [entry[0] for entry in rows], rows


def rir_metadata(ip: ipaddress.IPv4Address, starts: list[int], rows: list[tuple]):
    if not rows:
        return None
    pos = bisect_right(starts, int(ip)) - 1
    if pos < 0:
        return None
    entry = rows[pos]
    return entry if int(ip) <= entry[1] else None


def uncovered_parts(
    prefix: ipaddress.IPv4Network,
    covered: list[ipaddress.IPv4Network],
) -> list[ipaddress.IPv4Network]:
    """Kembalikan hanya bagian prefix yang belum diproses.

    Jika /24 sudah diproses lalu muncul /23 yang meliputinya,
    hasilnya hanya bagian /24 yang belum diproses.
    """
    pending = [prefix]
    for done in covered:
        next_pending: list[ipaddress.IPv4Network] = []
        for part in pending:
            if part.subnet_of(done):
                continue
            if done.subnet_of(part):
                next_pending.extend(part.address_exclude(done))
            else:
                next_pending.append(part)
        pending = next_pending
        if not pending:
            break
    return pending


def tcp_open(ip: str, port: int) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=TCP_TIMEOUT):
            return True
    except OSError:
        return False


def validate_target(ip: str, port: int) -> tuple[str, list[tuple[str, str]], str]:
    """Periksa SEMUA protokol dan simpan setiap protokol yang valid.

    Hasil: (status, [(nama_protokol, detail), ...], endpoint).
    """
    endpoint = f"{ip}:{port}"
    if not tcp_open(ip, port):
        return "CLOSED", [], endpoint

    valid_protocols: list[tuple[str, str]] = []
    for name, scheme in PROTOCOLS.items():
        proxy = f"{scheme}://{endpoint}"
        try:
            response = http_session().get(
                IPINFO_URL,
                proxies={"http": proxy, "https": proxy},
                timeout=(TCP_TIMEOUT, HTTP_TIMEOUT),
                allow_redirects=False,
            )
            if response.status_code != 200:
                continue
            data = response.json()
            if not isinstance(data, dict):
                continue
            egress = data.get("ip")
            if not egress:
                continue
            ipaddress.ip_address(egress)  # Pastikan IP egress valid.
            details = (
                f"egress={egress} ASN={data.get('asn_name', '-')} "
                f"lokasi={data.get('city', '-')}/{data.get('country_code', '-')}"
            )
            valid_protocols.append((name, details))
            # Tidak return di sini: lanjut uji protokol berikutnya.
        except (requests.RequestException, ValueError, TypeError):
            continue

    if valid_protocols:
        return "OK", valid_protocols, endpoint
    return "OPEN", [], endpoint


class ScanRecorder:
    def __init__(self, stack: ExitStack):
        active_dir = OUTPUT_DIR / "active"
        active_dir.mkdir(parents=True, exist_ok=True)
        self.files = {
            name: stack.enter_context((active_dir / f"{name}.txt").open("a", encoding="utf-8"))
            for name in PROTOCOLS
        }
        self.open_file = stack.enter_context((OUTPUT_DIR / "open.txt").open("a", encoding="utf-8"))
        self.known_active = {
            name: set((active_dir / f"{name}.txt").read_text(encoding="utf-8").splitlines())
            for name in PROTOCOLS
        }
        self.known_open = set((OUTPUT_DIR / "open.txt").read_text(encoding="utf-8").splitlines())
        self.checked = 0
        self.active = 0  # jumlah endpoint unik yang valid pada run ini
        self.active_protocols = 0  # jumlah pasangan endpoint+protokol
        self.opened = 0

    def record(self, task: Future) -> None:
        self.checked += 1
        # Error worker harus menggagalkan batch; jangan tandai target sudah selesai.
        status, matches, endpoint = task.result()
        if status == "OK" and matches:
            self.active += 1
            for proto, details in matches:
                self.active_protocols += 1
                print(f"[AKTIF] {proto}://{endpoint} | {details}", flush=True)
                if endpoint not in self.known_active[proto]:
                    self.files[proto].write(endpoint + "\n")
                    self.files[proto].flush()
                    self.known_active[proto].add(endpoint)
        elif status == "OPEN":
            self.opened += 1
            print(f"[PORT TERBUKA - BELUM VALID PROXY] {endpoint}", flush=True)
            if endpoint not in self.known_open:
                self.open_file.write(endpoint + "\n")
                self.open_file.flush()
                self.known_open.add(endpoint)
        if self.checked % PROGRESS_EVERY == 0:
            print(f"[PROGRES TOTAL] checked={self.checked:,} proxy={self.active} "
                  f"protokol={self.active_protocols} open={self.opened}", flush=True)

    def durable_flush(self) -> None:
        """Hasil ditulis sebelum checkpoint dipindahkan ke batch berikutnya."""
        import os
        for handle in (*self.files.values(), self.open_file):
            handle.flush()
            os.fsync(handle.fileno())


def scan_prefix(prefix: ipaddress.IPv4Network, pool: ThreadPoolExecutor,
                recorder: ScanRecorder, checkpoint: Checkpoint) -> None:
    """Resume per indeks IP:port; simpan checkpoint tiap batch yang tuntas.

    Urutan target deterministik: IP menaik, lalu PORTS sesuai urutan tuple.
    Batch baru ditandai selesai setelah SEMUA future dalam batch berhasil dicatat.
    Jika proses mati mendadak, maksimum satu batch dapat diuji ulang.
    """
    total = prefix.num_addresses * len(PORTS)
    start = checkpoint.next_target(prefix, total)
    if start:
        ip_offset, port_offset = divmod(start, len(PORTS))
        resumed_ip = ipaddress.IPv4Address(int(prefix.network_address) + ip_offset)
        print(f"[RESUME CIDR] {prefix} mulai target={start:,}/{total:,} "
              f"({resumed_ip}, indeks port={port_offset})", flush=True)

    for batch_start in range(start, total, CHECKPOINT_BATCH):
        batch_end = min(batch_start + CHECKPOINT_BATCH, total)
        futures: list[Future] = []
        for idx in range(batch_start, batch_end):
            ip_offset, port_offset = divmod(idx, len(PORTS))
            ip = str(ipaddress.IPv4Address(int(prefix.network_address) + ip_offset))
            futures.append(pool.submit(validate_target, ip, PORTS[port_offset]))
        for task in as_completed(futures):
            recorder.record(task)
        # Penting: simpan hasil dulu, baru commit posisi batch.
        recorder.durable_flush()
        checkpoint.advance(prefix, batch_end, total)
        if batch_end % (CHECKPOINT_BATCH * 10) == 0 or batch_end == total:
            print(f"[CHECKPOINT CIDR] {prefix} {batch_end:,}/{total:,}", flush=True)


def main() -> None:
    if not (1 <= WORKERS <= 1001 and PROGRESS_EVERY >= 1 and CHECKPOINT_BATCH >= WORKERS):
        raise ValueError("Periksa WORKERS / PROGRESS_EVERY / CHECKPOINT_BATCH")
    if len(set(PORTS)) != len(PORTS) or any(not 1 <= port <= 65535 for port in PORTS):
        raise ValueError("PORTS harus unik, 1..65535")

    if ASK_BEFORE_SCAN:
        answer = input("Scan hanya subnet yang Anda kelola/diizinkan? [y/N]: ").strip().lower()
        if answer not in ("y", "yes"):
            print("[BATAL] Tidak ada koneksi ke target.")
            return

    starts, rows = build_rir_index()
    reported_allocs: set[tuple] = set()
    seeds_seen = prefix_count = skipped = 0
    try:
        with ExitStack() as stack:
            cp = Checkpoint(CHECKPOINT_DB)
            stack.callback(cp.close)
            covered = cp.completed()
            print(f"[CHECKPOINT] {CHECKPOINT_DB.name} | "
                  f"CIDR selesai sebelumnya={len(covered)}", flush=True)
            recorder = ScanRecorder(stack)
            pool = stack.enter_context(ThreadPoolExecutor(max_workers=WORKERS))
            for entry in iter_seed_entries(cp):
                # Termasuk baris kosong, invalid, dan IP duplikat: kursor tetap bergerak.
                if entry.ip is None:
                    cp.complete_line(entry)
                    continue
                seed = entry.ip
                seeds_seen += 1
                print(f"[SEED] {entry.source}:{entry.line_no} -> {seed}", flush=True)
                allocation = rir_metadata(seed, starts, rows)
                if allocation and allocation not in reported_allocs:
                    reported_allocs.add(allocation)
                    first, _end, rir, country, count, status = allocation
                    print(f"[ALLOC] {rir} {country} "
                          f"{ipaddress.IPv4Address(first)} +{count} IP ({status})", flush=True)

                prefix, asns = bgp_prefix(seed)
                print(f"[BGP] {seed} -> {prefix} | ASNs={asns}", flush=True)
                remaining = uncovered_parts(prefix, covered)
                if not remaining:
                    skipped += 1
                    print(f"[SKIP CIDR] {prefix} sudah selesai", flush=True)
                    cp.complete_line(entry)
                    continue
                count = sum(part.num_addresses for part in remaining)
                print(f"[TARGET] {prefix} | bagian baru={len(remaining)} "
                      f"| IP={count:,} | IP:Port={count * len(PORTS):,}", flush=True)
                if count * len(PORTS) >= 1_000_000:
                    print("[PERINGATAN] Prefix besar: lakukan hanya jika diizinkan.",
                          flush=True)
                for part in remaining:
                    scan_prefix(part, pool, recorder, cp)
                    # Simpan sebagai selesai secara atomik dan permanen.
                    cp.complete_prefix(part)
                    covered = list(ipaddress.collapse_addresses([*covered, part]))
                    print(f"[PART SELESAI] {part}", flush=True)
                prefix_count += 1
                cp.complete_line(entry)  # Jangan maju sebelum CIDR seed ini selesai.
                print(f"[CIDR SELESAI] {prefix} -> lanjut seed berikutnya", flush=True)

            print(f"[SELESAI] seed-pada-run={seeds_seen} CIDR-baru={prefix_count} "
                  f"skip={skipped} checked={recorder.checked:,} "
                  f"proxy={recorder.active} protokol={recorder.active_protocols} "
                  f"open={recorder.opened}", flush=True)
    except KeyboardInterrupt:
        print("\n[STOP] Dihentikan. Mulai lagi dengan perintah yang sama; "
              "maksimum satu batch per CIDR dapat terulang.", flush=True)
    except (RuntimeError, OSError, sqlite3.Error) as exc:
        print(f"[ERROR] {exc} | checkpoint sebelumnya tetap dipertahankan.", flush=True)
        raise


if __name__ == "__main__":
    main()
