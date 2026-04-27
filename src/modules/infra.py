"""
src/modules/infra.py — Docker & Infrastructure Exposure Scanner.

Scans for dangerously misconfigured infrastructure:
  - Docker Remote API exposed on port 2375 (unauthenticated)
  - Redis without auth (raw socket probe)
  - MongoDB without auth (HTTP API / management port)
  - Portainer dashboard without authentication
  - Kubernetes Dashboard / etcd / Consul exposed
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from rich import box
from rich.markup import escape
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

from src.config import SESSION, rate_limiter, TIMEOUT, console, C
from src.models import ScanResult

# ─────────────────────────────────────────────────────────────────
# Target definitions
# ─────────────────────────────────────────────────────────────────

_HTTP_CHECKS: list[dict] = [
    # ── Docker
    {
        "name": "Docker Remote API",
        "severity": "critical",
        "port": 2375,
        "path": "/version",
        "match": "Docker",
        "note": "Unauthenticated Docker API — full container control (RCE)",
    },
    {
        "name": "Docker Remote API (TLS off)",
        "severity": "critical",
        "port": 2376,
        "path": "/version",
        "match": "Docker",
        "note": "Docker API accessible — verify TLS enforcement",
    },
    {
        "name": "Portainer Dashboard",
        "severity": "high",
        "port": 9000,
        "path": "/api/status",
        "match": "Portainer",
        "note": "Portainer UI exposed — may allow unauthenticated container management",
    },
    {
        "name": "Portainer Dashboard (HTTPS)",
        "severity": "high",
        "port": 9443,
        "path": "/api/status",
        "match": "Portainer",
        "note": "Portainer UI exposed — verify authentication is enforced",
    },
    # ── MongoDB REST API
    {
        "name": "MongoDB REST API",
        "severity": "critical",
        "port": 28017,
        "path": "/",
        "match": "MongoDB",
        "note": "MongoDB HTTP interface exposed — read/write data without credentials",
    },
    # ── Kubernetes
    {
        "name": "Kubernetes Dashboard",
        "severity": "critical",
        "port": 8001,
        "path": "/api/v1/namespaces",
        "match": "namespaces",
        "note": "K8s API exposed — cluster-wide resource access",
    },
    {
        "name": "Kubernetes Dashboard UI",
        "severity": "critical",
        "port": 30000,
        "path": "/",
        "match": "kubernetes-dashboard",
        "note": "Kubernetes Dashboard UI exposed without token",
    },
    # ── etcd
    {
        "name": "etcd Key-Value Store",
        "severity": "critical",
        "port": 2379,
        "path": "/v2/keys",
        "match": "action",
        "note": "etcd exposed — may contain K8s secrets and cluster configs",
    },
    # ── Consul
    {
        "name": "Consul Service Mesh",
        "severity": "high",
        "port": 8500,
        "path": "/v1/agent/self",
        "match": "Config",
        "note": "Consul agent API exposed — service mesh topology and secrets visible",
    },
    # ── Elasticsearch
    {
        "name": "Elasticsearch",
        "severity": "high",
        "port": 9200,
        "path": "/",
        "match": "cluster_name",
        "note": "Elasticsearch node exposed — full index read/write without credentials",
    },
    # ── CouchDB
    {
        "name": "CouchDB Admin",
        "severity": "high",
        "port": 5984,
        "path": "/_all_dbs",
        "match": "[",
        "note": "CouchDB exposed — databases accessible without authentication",
    },
    # ── RabbitMQ Management
    {
        "name": "RabbitMQ Management",
        "severity": "medium",
        "port": 15672,
        "path": "/api/overview",
        "match": "rabbitmq_version",
        "note": "RabbitMQ management UI exposed",
    },
]

# Ports we probe via raw TCP for plaintext protocols
_TCP_CHECKS: list[dict] = [
    {
        "name": "Redis (No Auth)",
        "severity": "critical",
        "port": 6379,
        "send": b"PING\r\n",
        "expect": b"+PONG",
        "note": "Redis without authentication — arbitrary key read/write, potential RCE via SLAVEOF",
    },
    {
        "name": "Memcached",
        "severity": "medium",
        "port": 11211,
        "send": b"stats\r\n",
        "expect": b"STAT",
        "note": "Memcached exposed — cache poisoning / data leakage",
    },
]


# ─────────────────────────────────────────────────────────────────
# Probe helpers
# ─────────────────────────────────────────────────────────────────


def _http_probe(host: str, check: dict) -> dict | None:
    """Try HTTP probe for a given check definition."""
    scheme = "https" if check["port"] in (9443, 2376) else "http"
    url = f"{scheme}://{host}:{check['port']}{check['path']}"
    rate_limiter.wait()
    try:
        resp = SESSION.get(url, timeout=TIMEOUT, verify=False, allow_redirects=True)
    except Exception:
        return None

    body = resp.text[:20_000]
    if resp.status_code < 500 and check["match"].lower() in body.lower():
        return {
            "name": check["name"],
            "severity": check["severity"],
            "url": url,
            "status": resp.status_code,
            "note": check["note"],
            "proto": "http",
            "snippet": body[:400],
        }
    return None


def _tcp_probe(host: str, check: dict) -> dict | None:
    """Send a raw TCP command and check for an expected response."""
    try:
        with socket.create_connection((host, check["port"]), timeout=TIMEOUT) as sock:
            sock.sendall(check["send"])
            data = sock.recv(256)
        if check["expect"] in data:
            return {
                "name": check["name"],
                "severity": check["severity"],
                "url": f"tcp://{host}:{check['port']}",
                "note": check["note"],
                "proto": "tcp",
                "response_preview": data[:100].decode("utf-8", errors="replace"),
            }
    except Exception:
        return None
    return None


# ─────────────────────────────────────────────────────────────────
# Module entry point
# ─────────────────────────────────────────────────────────────────


def run_infra(
    target_url: str, hostname: str, result: ScanResult, progress, task
) -> None:
    """Scan for exposed Docker, Redis, MongoDB, Kubernetes, and other infra endpoints."""
    findings: list[dict] = []
    total = len(_HTTP_CHECKS) + len(_TCP_CHECKS)
    done = 0

    # Resolve bare hostname (strip port if present)
    parsed = urlparse(target_url)
    host = parsed.hostname or hostname

    progress.update(
        task, description="[cyan]Infra Scanner:[/cyan] Probing exposed services…"
    )

    def _run_http(check: dict):
        nonlocal done
        finding = _http_probe(host, check)
        done += 1
        progress.update(
            task,
            description=f"[cyan]Infra:[/cyan] {done}/{total} checks…",
            completed=int((done / total) * 50),
        )
        return finding

    def _run_tcp(check: dict):
        nonlocal done
        finding = _tcp_probe(host, check)
        done += 1
        progress.update(
            task,
            description=f"[cyan]Infra:[/cyan] {done}/{total} checks…",
            completed=int((done / total) * 50),
        )
        return finding

    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = [pool.submit(_run_http, c) for c in _HTTP_CHECKS]
        futures += [pool.submit(_run_tcp, c) for c in _TCP_CHECKS]

        for future in as_completed(futures):
            finding = future.result()
            if finding:
                findings.append(finding)
                sev_style = (
                    "red" if finding["severity"] in ("critical", "high") else "yellow"
                )
                progress.console.print(
                    Panel(
                        f"[bold]Service  :[/bold] {finding['name']}\n"
                        f"[bold]Target   :[/bold] [cyan]{escape(finding['url'])}[/cyan]\n"
                        f"[bold]Severity :[/bold] [{sev_style}]{finding['severity'].upper()}[/{sev_style}]\n"
                        f"[bold]Impact   :[/bold] [yellow]{escape(finding['note'])}[/yellow]",
                        title="[bold red]🐳 EXPOSED INFRA SERVICE[/bold red]",
                        border_style=sev_style,
                    )
                )

    result.infra_findings = findings
    progress.update(task, completed=50)


# ─────────────────────────────────────────────────────────────────
# Display function
# ─────────────────────────────────────────────────────────────────


def display_infra(result: ScanResult) -> None:
    console.print(
        Rule(f"[{C['bad']}]🐳   DOCKER & INFRA EXPOSURE[/{C['bad']}]", style="red")
    )

    findings = getattr(result, "infra_findings", [])
    if not findings:
        console.print("  [dim]No exposed infrastructure services detected.[/dim]\n")
        return

    console.print(
        f"  [{C['bad']}]⚠  {len(findings)} misconfigured service(s) found![/{C['bad']}]\n"
    )

    tbl = Table(
        box=box.ROUNDED,
        border_style="red",
        header_style=C["head"],
        show_lines=True,
    )
    tbl.add_column("Service", style=C["warn"], min_width=26)
    tbl.add_column("URL / Endpoint", style=C["accent"], min_width=36)
    tbl.add_column("Severity", justify="center", min_width=10)
    tbl.add_column("Proto", justify="center", min_width=6)

    for f in findings:
        sev = f["severity"].upper()
        sev_col = "bold red" if f["severity"] in ("critical", "high") else "bold yellow"
        tbl.add_row(
            escape(f["name"]),
            escape(f["url"]),
            f"[{sev_col}]{sev}[/{sev_col}]",
            f["proto"].upper(),
        )

    console.print(tbl)
    console.print()

    # Detail panels for critical findings
    for f in findings:
        if f["severity"] == "critical":
            detail = f"[bold]Impact:[/bold] {escape(f['note'])}"
            if f.get("snippet"):
                detail += (
                    f"\n\n[dim]Response Snippet:[/dim]\n{escape(f['snippet'][:300])}"
                )
            elif f.get("response_preview"):
                detail += (
                    f"\n\n[dim]TCP Response:[/dim] {escape(f['response_preview'])}"
                )
            console.print(
                Panel(
                    detail,
                    title=f"[bold red]CRITICAL — {escape(f['name'])}[/bold red]",
                    border_style="red",
                )
            )
    console.print()
