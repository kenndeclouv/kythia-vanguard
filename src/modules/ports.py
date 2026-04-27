"""
src/modules/ports.py — Module 6: TCP port scan with optional banner grabbing.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from rich import box
from rich.markup import escape
from rich.rule import Rule
from rich.table import Table

from src.config import console, C
from src.models import ScanResult

TOP_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    587: "SMTP-TLS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "Jupyter",
    9200: "Elasticsearch",
    27017: "MongoDB",
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
            "port": port,
            "service": TOP_PORTS.get(port, "?"),
            "state": "open",
            "banner": banner,
        }
    except Exception:
        return None


def run_port_scan(hostname: str, result: ScanResult, progress, task) -> None:
    open_ports: list[dict] = []
    banners: dict = {}
    total = len(TOP_PORTS)
    done = 0

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {
            executor.submit(_probe_port, hostname, port): port for port in TOP_PORTS
        }
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
    result.banners = banners  # consumed by CVE module


def display_ports(result: ScanResult) -> None:
    console.print(
        Rule(f"[{C['accent']}]🔌  PORT SCAN RESULTS[/{C['accent']}]", style="magenta")
    )
    if not result.open_ports:
        console.print("  [dim]No open ports found among the top 25 common ports.[/dim]")
        console.print()
        return

    dangerous_ports = {21, 23, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 27017}
    t = Table(box=box.ROUNDED, border_style="yellow", header_style=C["head"])
    t.add_column("Port", width=8, justify="right", style=C["accent"])
    t.add_column("Service", width=16, style="white")
    t.add_column("State", width=10, justify="center")
    t.add_column("Banner", style=C["dim"], width=40)
    t.add_column("Risk", width=30)

    for p in result.open_ports:
        is_risky = p["port"] in dangerous_ports
        risk_str = (
            f"[{C['bad']}]⚠ Potentially dangerous[/{C['bad']}]"
            if is_risky
            else f"[{C['ok']}]Expected[/{C['ok']}]"
        )
        banner_str = escape(p.get("banner", "")[:40]) or "[dim]—[/dim]"
        t.add_row(
            str(p["port"]),
            p["service"],
            f"[{C['ok']}]OPEN[/{C['ok']}]",
            banner_str,
            risk_str,
        )
    console.print(t)
    console.print()
