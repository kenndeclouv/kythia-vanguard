"""
src/modules/cors.py — CORS Misconfiguration Hijacker.

Tests every endpoint in result.sitemap + result.js_endpoints for CORS
misconfigurations by injecting three attacker-controlled Origin values
and evaluating the Access-Control-Allow-Origin / Allow-Credentials response.

Vulnerability classes detected:
  - Wildcard (*) with credentials
  - Reflected Origin (server echoes back whatever Origin you send)
  - Null Origin allowed with credentials
  - Trusted subdomain regex bypass (evil.target.com)
  - Trusted suffix bypass (eviltarget.com)
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from rich import box
from rich.markup import escape
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

from src.config import SESSION, RateLimiter, TIMEOUT, console, C
from src.models import ScanResult

_rl = RateLimiter(rps=15.0, use_jitter=False)

# ─────────────────────────────────────────────────────────────────
# Attack vectors
# ─────────────────────────────────────────────────────────────────


def _build_origins(hostname: str) -> list[tuple[str, str]]:
    """Return (label, origin) pairs to inject as Origin header."""
    return [
        ("Arbitrary evil origin", "https://evil-hacker.com"),
        ("Null origin", "null"),
        ("Subdomain prefix bypass", f"https://evil.{hostname}"),
        ("Suffix bypass (pre-dot missing)", f"https://evil{hostname}"),
        ("Trusted+evil combo", f"https://{hostname}.evil-hacker.com"),
    ]


# ─────────────────────────────────────────────────────────────────
# Single URL probe
# ─────────────────────────────────────────────────────────────────


def _probe_url(url: str, hostname: str) -> list[dict]:
    findings: list[dict] = []

    for label, origin in _build_origins(hostname):
        _rl.wait()
        try:
            resp = SESSION.options(
                url,
                headers={"Origin": origin, "Access-Control-Request-Method": "GET"},
                timeout=TIMEOUT,
                allow_redirects=False,
            )
        except Exception:
            continue

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
        acam = resp.headers.get("Access-Control-Allow-Methods", "")
        vary = resp.headers.get("Vary", "")

        with_creds = acac == "true"

        # ── Classify vulnerability
        vuln_type: str | None = None
        severity: str = "low"

        if acao == "*" and with_creds:
            vuln_type = "Wildcard + Credentials"
            severity = "critical"
        elif acao == origin and with_creds:
            vuln_type = "Reflected Origin + Credentials"
            severity = "critical"
        elif acao == origin and not with_creds:
            vuln_type = "Reflected Origin (no credentials)"
            severity = "medium"
        elif acao == "null" and with_creds:
            vuln_type = "Null Origin + Credentials"
            severity = "critical"
        elif acao == "null":
            vuln_type = "Null Origin allowed"
            severity = "low"
        elif acao == "*":
            vuln_type = "Wildcard (no credentials)"
            severity = "low"

        if vuln_type is None:
            continue

        findings.append(
            {
                "url": url,
                "origin_sent": origin,
                "origin_label": label,
                "acao": acao,
                "credentials": with_creds,
                "methods": acam,
                "vary": vary,
                "vuln_type": vuln_type,
                "severity": severity,
            }
        )

    return findings


# ─────────────────────────────────────────────────────────────────
# Module entry point
# ─────────────────────────────────────────────────────────────────


def run_cors(
    target_url: str, hostname: str, result: ScanResult, progress, task
) -> None:
    """Probe all Spider-discovered endpoints for CORS misconfigurations."""

    endpoints = list(
        dict.fromkeys(
            getattr(result, "sitemap", [])
            + getattr(result, "js_endpoints", [])
            + [target_url]
        )
    )[:80]  # cap: 80 endpoints × 5 origins = 400 requests max

    total = len(endpoints)
    done = 0
    findings: list[dict] = []

    progress.update(task, description=f"[cyan]CORS:[/cyan] Probing {total} endpoints…")

    def _check(url: str) -> list[dict]:
        nonlocal done
        hits = _probe_url(url, hostname)
        done += 1
        progress.update(
            task,
            description=f"[cyan]CORS:[/cyan] {done}/{total} endpoints…",
            completed=int((done / total) * 50),
        )
        return hits

    with ThreadPoolExecutor(max_workers=12) as pool:
        for future in as_completed({pool.submit(_check, u): u for u in endpoints}):
            for f in future.result():
                findings.append(f)
                if f["severity"] in ("critical", "high"):
                    style = "red"
                    progress.console.print(
                        Panel(
                            f"[bold]URL      :[/bold] [cyan]{escape(f['url'])}[/cyan]\n"
                            f"[bold]Origin   :[/bold] [yellow]{escape(f['origin_sent'])}[/yellow]  "
                            f"({escape(f['origin_label'])})\n"
                            f"[bold]ACAO     :[/bold] {escape(f['acao'])}\n"
                            f"[bold]With Creds:[/bold] {'[red]YES[/red]' if f['credentials'] else 'no'}\n"
                            f"[bold]Vuln     :[/bold] [{style}]{escape(f['vuln_type'])}[/{style}]",
                            title="[bold red]🏴‍☠️ CORS MISCONFIGURATION[/bold red]",
                            border_style=style,
                        )
                    )

    # Deduplicate: keep worst severity per (url, vuln_type)
    seen: set[str] = set()
    unique: list[dict] = []
    for f in sorted(
        findings,
        key=lambda x: ["critical", "high", "medium", "low"].index(x["severity"]),
    ):
        key = f"{f['url']}:{f['vuln_type']}"
        if key not in seen:
            seen.add(key)
            unique.append(f)

    result.cors_findings = unique
    progress.update(task, completed=50)


# ─────────────────────────────────────────────────────────────────
# Display function
# ─────────────────────────────────────────────────────────────────


def display_cors(result: ScanResult) -> None:
    console.print(Rule(f"[{C['bad']}]🏴‍☠️   CORS HIJACKER[/{C['bad']}]", style="red"))

    findings = getattr(result, "cors_findings", [])
    if not findings:
        console.print("  [dim]No CORS misconfigurations detected.[/dim]\n")
        return

    critical = [f for f in findings if f["severity"] == "critical"]
    console.print(
        f"  [{C['bad']}]⚠  {len(findings)} misconfiguration(s)[/{C['bad']}] — "
        f"[bold red]{len(critical)} critical[/bold red]\n"
    )

    tbl = Table(
        box=box.ROUNDED, border_style="red", header_style=C["head"], show_lines=True
    )
    tbl.add_column("URL", style=C["warn"], min_width=35)
    tbl.add_column("Vulnerability", style=C["accent"], min_width=30)
    tbl.add_column("Origin Sent", style="dim", min_width=28)
    tbl.add_column("Creds", justify="center", min_width=6)
    tbl.add_column("Severity", justify="center", min_width=10)

    for f in findings:
        sev_col = "bold red" if f["severity"] in ("critical", "high") else "bold yellow"
        cred_icon = "[red]YES[/red]" if f["credentials"] else "[dim]no[/dim]"
        tbl.add_row(
            escape(f["url"][-50:]),
            escape(f["vuln_type"]),
            escape(f["origin_sent"]),
            cred_icon,
            f"[{sev_col}]{f['severity'].upper()}[/{sev_col}]",
        )

    console.print(tbl)
    console.print()
