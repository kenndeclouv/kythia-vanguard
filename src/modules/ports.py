"""
src/modules/ports.py — Module 6: TCP port scan with optional banner grabbing.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from src.models import ScanResult

TOP_PORTS: dict[int, str] = {
    21: "FTP",    22: "SSH",     23: "Telnet",  25: "SMTP",   53: "DNS",
    80: "HTTP",  110: "POP3",   143: "IMAP",   443: "HTTPS", 445: "SMB",
   587: "SMTP-TLS", 993: "IMAPS", 995: "POP3S",
  1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",  3389: "RDP",
  5432: "PostgreSQL", 5900: "VNC",
  6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
  8888: "Jupyter", 9200: "Elasticsearch", 27017: "MongoDB",
}


def _probe_port(host: str, port: int) -> Optional[dict]:
    """TCP connect + optional banner grab on text-based services."""
    try:
        s = socket.create_connection((host, port), timeout=2)
        banner = ""
        if port in (21, 22, 25, 110, 143, 587, 993, 995):
            try:
                s.settimeout(2)
                banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
            except Exception:
                pass
        elif port in (80, 8080, 8888):
            try:
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                s.settimeout(2)
                banner = s.recv(512).decode("utf-8", errors="ignore").strip()
            except Exception:
                pass
        s.close()
        return {
            "port":    port,
            "service": TOP_PORTS.get(port, "?"),
            "state":   "open",
            "banner":  banner,
        }
    except Exception:
        return None


def run_port_scan(hostname: str, result: ScanResult, progress, task) -> None:
    open_ports: list[dict] = []
    banners:    dict       = {}
    total = len(TOP_PORTS)
    done  = 0

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(_probe_port, hostname, port): port for port in TOP_PORTS}
        for future in as_completed(futures):
            done += 1
            progress.update(
                task,
                description=f"[cyan]Ports:[/cyan] Scanning {done}/{total}…",
                completed=int((done / total) * 50),
            )
            res = future.result()
            if res:
                open_ports.append(res)
                if res["banner"]:
                    banners[res["port"]] = res["banner"]

    result.open_ports = sorted(open_ports, key=lambda p: p["port"])
    result.banners    = banners   # consumed by CVE module
