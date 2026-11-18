from bisect import bisect_right
import ipaddress
import json
from pathlib import Path
import socket
import time
from typing import Optional, Tuple
from urllib.parse import urlsplit

from proxy_discovery_v2 import RIPE_URL, http_session


import socket
import requests
from urllib.parse import urlsplit

URLS = [
    "http://ipinfo.decosystem.my.id/",
    "https://ipinfo.decosystem.my.id/",
]

def tcp_open(host, port, timeout=5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, "CONNECTED"
    except OSError as e:
        return False, f"{type(e).__name__}: {e}"

def test():
    session = requests.Session()
    session.trust_env = False

    with open("socks5.txt", encoding="utf-8") as f:
        for line in f:
            raw = line.strip()

            if not raw or raw.startswith("#"):
                continue
            raw = "1.0.251.37:8080"

            proxy_url = (
                raw if "://" in raw else f"http://{raw}"
            )

            try:
                parsed = urlsplit(proxy_url)
                host = parsed.hostname
                port = parsed.port

                if not host or not port:
                    continue

            except ValueError:
                continue

            # Diagnostik TCP, bukan filter.
            alive, reason = tcp_open(host, port)

            print(f"\n[PROXY] {host}:{port}")
            print(f"[TCP] {alive} | {reason}")

            proxies = {
                "http": proxy_url,
                "https": proxy_url,
            }

            for url in URLS:
                try:
                    response = session.get(
                        url,
                        proxies=proxies,
                        timeout=(5, 10),
                        allow_redirects=False,
                    )
                    print(response.text)

                    print(
                        f"[HTTP] {response.status_code} "
                        f"| {url}"
                    )

                except requests.RequestException as e:
                    print(f"\n[ERROR] {url}")
                    print(f"TYPE   : {type(e).__name__}")
                    print(f"DETAIL : {repr(e)}")
            break

def parse_seed(raw: str) -> Tuple[ipaddress.IPv4Address, Optional[int]] | Tuple[None, None]:
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return None
    try:
        url = raw if "://" in raw else "//" + raw
        splt = urlsplit(url)
        host = splt.hostname
        if host is None:
            return None
        result = ipaddress.ip_address(host)
        if isinstance(result, ipaddress.IPv4Address):
            return result, splt.port 
        return None, None
    except ValueError:
        return None, None

def parse_seed_port(raw: str) -> int | None:
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return None
    try:
        url = raw if "://" in raw else "//" + raw
        port = urlsplit(url).port
        if port is None:
            return None        
        return port if isinstance(port, int) else None
    except ValueError:
        return None


def bgp_prefix(ip: ipaddress.IPv4Address) -> tuple[ipaddress.IPv4Network, list]:
    """Ambil BGP prefix. Jika API gagal, jangan tandai seed sudah selesai."""
    if ip.is_private:
        # Untuk eksperimen LAN, prefix /24 hanyalah default lokal (bukan BGP).
        return ipaddress.IPv4Network(f"{ip}/24", strict=False), []
    if not ip.is_global:
        return ipaddress.IPv4Network(f"{ip}/32"), []
    last_error: Exception | None = None
    for attempt in range(1, 11):
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
            print(f"[WARN] RIPEstat {ip} percobaan {attempt}/10: {exc}", flush=True)
            if attempt < 3:
                time.sleep(attempt)
    raise RuntimeError(f"RIPEstat gagal untuk {ip}; seed belum di-checkpoint") from last_error

def generate_ips():
    ips = set()
    prefixs = set()
    with open("backup/ips_new.txt") as file:
        for line in file:
            ip_address, port = parse_seed(line.strip())
            if ip_address not in ips:
                ips.add(f"{ip_address}:{port}")
                prefix, _ = bgp_prefix(ip_address)
                p = prefix.__str__()
                if p not in prefixs:
                    prefixs.add(p)
                    print(p)
        
        with open("backup/scope.txt", "+a") as save:
            save.write("\n".join(sorted(prefixs)))
        
        with open("backup/ips.txt", "+a") as save:
            save.write("\n".join(sorted(ips)))
            

def get_port():
    ports = set()
    with open("backup/ips_new.txt") as file:
        for line in file:
            port = parse_seed_port(line.strip())
            if port not in ports:
                ports.add(port)
                print(port)
    
    with open("backup/ports.txt", "w") as save:
        save.write(",".join(str(port) for port in sorted(ports)))
        #json.dump(sorted(ports), save)
        
generate_ips()