"""
src/modules/takeover.py — Subdomain Takeover Sniper.

For every subdomain in result.subdomains (populated by recon.py):
  1. Resolve CNAME chain via dig
  2. Match against 25+ known-vulnerable third-party service patterns
  3. Confirm takeover window via HTTP body fingerprint
  4. Save to result.takeover_findings
"""

from __future__ import annotations
from src.export import md_table

import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import re

from rich import box
from rich.markup import escape
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

from src.config import SESSION, RateLimiter, TIMEOUT, console, C
from src.models import ScanResult
from src.scoring import score_and_report

_rl = RateLimiter(rps=20.0, use_jitter=False)

_SERVICES: list[tuple[str, re.Pattern, re.Pattern, str]] = [
    (
        "GitHub Pages",
        re.compile(r"github\.io$", re.I),
        re.compile(r"There isn't a GitHub Pages site here", re.I),
        "critical",
    ),
    (
        "Heroku",
        re.compile(r"herokuapp?\.com$", re.I),
        re.compile(r"no such app|There is no app configured", re.I),
        "critical",
    ),
    (
        "AWS S3",
        re.compile(r"s3[.-][a-z0-9-]+\.amazonaws\.com$|s3\.amazonaws\.com$", re.I),
        re.compile(r"NoSuchBucket|The specified bucket does not exist", re.I),
        "critical",
    ),
    (
        "Azure",
        re.compile(r"azurewebsites\.net$|cloudapp\.net$|azurestaticapps\.net$", re.I),
        re.compile(r"404 Web Site not found|App Service.*Unavailable", re.I),
        "critical",
    ),
    (
        "Netlify",
        re.compile(r"netlify\.(?:app|com)$", re.I),
        re.compile(r"Not Found - Request ID|page not found", re.I),
        "critical",
    ),
    (
        "Vercel",
        re.compile(r"vercel\.app$|now\.sh$", re.I),
        re.compile(r"deployment.*does not exist|404.*vercel", re.I),
        "critical",
    ),
    (
        "Shopify",
        re.compile(r"myshopify\.com$", re.I),
        re.compile(r"Sorry, this shop is currently unavailable", re.I),
        "critical",
    ),
    (
        "Firebase",
        re.compile(r"web\.app$|firebaseapp\.com$", re.I),
        re.compile(r"404.*firebase|URL.*not configured", re.I),
        "critical",
    ),
    (
        "Surge.sh",
        re.compile(r"surge\.sh$", re.I),
        re.compile(r"project not found", re.I),
        "critical",
    ),
    (
        "Render",
        re.compile(r"onrender\.com$", re.I),
        re.compile(r"not deployed|Service not found", re.I),
        "critical",
    ),
    (
        "Fly.io",
        re.compile(r"fly\.dev$", re.I),
        re.compile(r"This app doesn't exist", re.I),
        "critical",
    ),
    (
        "Fastly",
        re.compile(r"fastly\.net$", re.I),
        re.compile(r"Fastly error: unknown domain", re.I),
        "high",
    ),
    (
        "Pantheon",
        re.compile(r"pantheonsite\.io$", re.I),
        re.compile(r"404 error unknown site", re.I),
        "high",
    ),
    (
        "HubSpot",
        re.compile(r"hubspot\.net$|hs-sites\.com$", re.I),
        re.compile(r"does not exist in our system", re.I),
        "high",
    ),
    (
        "Zendesk",
        re.compile(r"zendesk\.com$", re.I),
        re.compile(r"Help Center Closed|Page not found", re.I),
        "high",
    ),
    (
        "Tumblr",
        re.compile(r"tumblr\.com$", re.I),
        re.compile(r"Whatever you were looking for doesn't currently exist", re.I),
        "high",
    ),
    (
        "Webflow",
        re.compile(r"webflow\.io$", re.I),
        re.compile(r"The page you are looking for doesn't exist", re.I),
        "high",
    ),
    (
        "Strikingly",
        re.compile(r"strikingly\.com$", re.I),
        re.compile(r"But if you're looking for your website", re.I),
        "high",
    ),
    (
        "Ghost",
        re.compile(r"ghost\.io$", re.I),
        re.compile(r"Failed to resolve DNS", re.I),
        "high",
    ),
    (
        "WordPress.com",
        re.compile(r"wordpress\.com$", re.I),
        re.compile(r"Do you want to register|doesn't exist", re.I),
        "high",
    ),
    (
        "Bitbucket",
        re.compile(r"bitbucket\.io$", re.I),
        re.compile(r"Repository not found", re.I),
        "high",
    ),
    (
        "ReadMe.io",
        re.compile(r"readme\.io$", re.I),
        re.compile(r"Project doesnt exist", re.I),
        "high",
    ),
    (
        "DigitalOcean Spaces",
        re.compile(r"digitaloceanspaces\.com$", re.I),
        re.compile(r"NoSuchBucket", re.I),
        "critical",
    ),
    (
        "CloudFront",
        re.compile(r"cloudfront\.net$", re.I),
        re.compile(r"Bad request|ERROR: The request could not be satisfied", re.I),
        "high",
    ),
    (
        "Agile CRM",
        re.compile(r"agilecrm\.com$", re.I),
        re.compile(r"Sorry, this page is no longer available", re.I),
        "medium",
    ),
]


def _resolve_cname(hostname: str) -> str | None:
    try:
        out = subprocess.run(
            ["dig", "+short", "CNAME", hostname],
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
        return out.rstrip(".") if out else None
    except Exception:
        return None


def _http_body(url: str) -> str:
    _rl.wait()
    try:
        resp = SESSION.get(url, timeout=TIMEOUT, allow_redirects=True, stream=True)
        body = resp.raw.read(200_000, decode_content=True).decode(
            "utf-8", errors="ignore"
        )
        resp.close()
        return body
    except Exception:
        return ""


def _probe(subdomain: str, base_hostname: str) -> dict | None:
    sub = subdomain.strip()
    if sub.startswith(("http://", "https://")):
        sub = urlparse(sub).hostname or sub
    if sub == base_hostname:
        return None
    cname = _resolve_cname(sub)
    if not cname:
        return None
    for service, cname_pat, body_pat, severity in _SERVICES:
        if not cname_pat.search(cname):
            continue
        body = _http_body(f"http://{sub}") or _http_body(f"https://{sub}")
        confirmed = bool(body_pat.search(body))
        return {
            "subdomain": sub,
            "cname": cname,
            "service": service,
            "severity": severity,
            "confirmed": confirmed,
        }
    return None


def run_takeover(hostname: str, result: ScanResult, progress, task) -> None:
    """Check all discovered subdomains for dangling CNAME takeover windows."""
    subdomains: list[str] = getattr(result, "subdomains", []) or []
    if not subdomains:
        progress.update(
            task,
            description="[cyan]Takeover:[/cyan] No subdomains — run Recon first.",
            completed=50,
        )
        result.takeover_findings = []
        return

    total = len(subdomains)
    done = 0
    findings: list[dict] = []

    progress.update(
        task, description=f"[cyan]Takeover:[/cyan] Probing {total} subdomains…"
    )

    def _check(sub: str) -> dict | None:
        nonlocal done
        f = _probe(sub, hostname)
        done += 1
        progress.update(
            task,
            description=f"[cyan]Takeover:[/cyan] {done}/{total}…",
            completed=int((done / total) * 50),
        )
        return f

    with ThreadPoolExecutor(max_workers=20) as pool:
        for future in as_completed({pool.submit(_check, s): s for s in subdomains}):
            finding = future.result()
            if finding:
                findings.append(finding)
                if finding["confirmed"]:
                    style = (
                        "red"
                        if finding["severity"] in ("critical", "high")
                        else "yellow"
                    )
                    progress.console.print(
                        Panel(
                            f"[bold]Subdomain:[/bold] [cyan]{escape(finding['subdomain'])}[/cyan]\n"
                            f"[bold]CNAME    :[/bold] [yellow]{escape(finding['cname'])}[/yellow]\n"
                            f"[bold]Service  :[/bold] {escape(finding['service'])}\n"
                            f"[bold]Severity :[/bold] [{style}]{finding['severity'].upper()}[/{style}]\n"
                            f"[bold red]✓ HTTP fingerprint confirmed — TAKEOVER POSSIBLE![/bold red]",
                            title="[bold red]👻 SUBDOMAIN TAKEOVER WINDOW[/bold red]",
                            border_style=style,
                        )
                    )

    result.takeover_findings = findings
    progress.update(task, completed=50)
    score_and_report(result, "takeover")


def score_takeover(result):
    if not result.takeover_findings:
        return 100
    return max(0, 100 - min(len(result.takeover_findings) * 30, 90))


def display_takeover(result: ScanResult) -> None:
    console.print(
        Rule(f"[{C['bad']}]👻   SUBDOMAIN TAKEOVER SNIPER[/{C['bad']}]", style="red")
    )
    findings = getattr(result, "takeover_findings", [])
    if not findings:
        console.print("  [dim]No subdomain takeover opportunities detected.[/dim]\n")
        return

    confirmed = [f for f in findings if f["confirmed"]]
    console.print(
        f"  [{C['bad']}]⚠  {len(confirmed)} confirmed[/{C['bad']}] / "
        f"[dim]{len(findings) - len(confirmed)} CNAME-only[/dim]\n"
    )

    tbl = Table(
        box=box.ROUNDED, border_style="red", header_style=C["head"], show_lines=True
    )
    tbl.add_column("Subdomain", style=C["warn"], min_width=28)
    tbl.add_column("CNAME Target", style=C["accent"], min_width=28)
    tbl.add_column("Service", min_width=16)
    tbl.add_column("Severity", justify="center", min_width=10)
    tbl.add_column("Confirmed", justify="center", min_width=10)

    for f in sorted(findings, key=lambda x: (not x["confirmed"], x["severity"])):
        sev_style = (
            "bold red" if f["severity"] in ("critical", "high") else "bold yellow"
        )
        conf_icon = (
            "[bold green]✓ YES[/bold green]" if f["confirmed"] else "[dim]CNAME[/dim]"
        )
        tbl.add_row(
            escape(f["subdomain"]),
            escape(f["cname"]),
            escape(f["service"]),
            f"[{sev_style}]{f['severity'].upper()}[/{sev_style}]",
            conf_icon,
        )

    console.print(tbl)
    console.print()


def export_takeover(result: ScanResult, W: callable) -> None:
    if result.takeover_findings:
        W(f"### 👻 Subdomain Takeover ({len(result.takeover_findings)} vulnerable)\n\n")
        W(
            "> [!CAUTION]\n> These subdomains can be claimed immediately on the listed platforms.\n\n"
        )
        rows = [
            [
                f.get("subdomain", "?"),
                f.get("cname", "?"),
                f.get("platform", "?"),
                f.get("evidence", ""),
            ]
            for f in result.takeover_findings
        ]
        W(md_table(["Subdomain", "CNAME", "Platform", "Evidence"], rows))
        W("\n")
    else:
        W("### 👻 Subdomain Takeover\n\n- ✅ No vulnerable subdomains found.\n\n")
