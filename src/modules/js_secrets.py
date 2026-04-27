"""
src/modules/js_secrets.py — Deep JS API & Secret Hunter.

Consumes result.js_endpoints + result.sitemap (from spider.py) and
scans every JS/HTML file for 20+ categories of leaked credentials:
Stripe, AWS, Twilio, Google Maps, SendGrid, Firebase, Mailchimp, etc.

This is distinct from webhook.py (which focuses on Discord/Telegram/Slack
and also validates live) — js_secrets.py casts a much wider net across
ALL secret types and reports with full context (line number + snippet).
"""

from __future__ import annotations
from src.export import md_table

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from rich import box
from rich.markup import escape
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

from src.config import SESSION, RateLimiter, TIMEOUT, console, C
from src.models import ScanResult
from src.scoring import score_and_report

_rl = RateLimiter(rps=20.0, use_jitter=False)

# ─────────────────────────────────────────────────────────────────
# Secret pattern registry
# ─────────────────────────────────────────────────────────────────

_PATTERNS: list[dict] = [
    {
        "name": "AWS Access Key",
        "severity": "critical",
        "regex": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    },
    {
        "name": "AWS Secret Key",
        "severity": "critical",
        "regex": re.compile(r'(?i)aws.{0,30}secret.{0,30}["\'][0-9a-zA-Z/+=]{40}["\']'),
    },
    {
        "name": "Stripe Secret Key",
        "severity": "critical",
        "regex": re.compile(r"\bsk_live_[0-9a-zA-Z]{24}\b"),
    },
    {
        "name": "Stripe Publishable Key",
        "severity": "medium",
        "regex": re.compile(r"\bpk_live_[0-9a-zA-Z]{24}\b"),
    },
    {
        "name": "Google API Key",
        "severity": "high",
        "regex": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    },
    {
        "name": "Google OAuth Client",
        "severity": "high",
        "regex": re.compile(
            r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b"
        ),
    },
    {
        "name": "Firebase Config",
        "severity": "high",
        "regex": re.compile(r'apiKey\s*:\s*["\']AIza[0-9A-Za-z\-_]{35}["\']'),
    },
    {
        "name": "Twilio Account SID",
        "severity": "high",
        "regex": re.compile(r"\bAC[0-9a-f]{32}\b"),
    },
    {
        "name": "Twilio Auth Token",
        "severity": "critical",
        "regex": re.compile(r'(?i)twilio.{0,30}auth.{0,20}["\'][0-9a-f]{32}["\']'),
    },
    {
        "name": "SendGrid API Key",
        "severity": "critical",
        "regex": re.compile(r"\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b"),
    },
    {
        "name": "Mailgun API Key",
        "severity": "high",
        "regex": re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"),
    },
    {
        "name": "Mailchimp API Key",
        "severity": "high",
        "regex": re.compile(r"\b[0-9a-f]{32}-us[0-9]{1,2}\b"),
    },
    {
        "name": "GitHub Personal Token",
        "severity": "critical",
        "regex": re.compile(r"\bghp_[0-9a-zA-Z]{36}\b"),
    },
    {
        "name": "GitHub OAuth Token",
        "severity": "critical",
        "regex": re.compile(r"\bgho_[0-9a-zA-Z]{36}\b"),
    },
    {
        "name": "Slack API Token",
        "severity": "high",
        "regex": re.compile(r"\bxox[bpoas]-[0-9A-Za-z\-]{10,72}\b"),
    },
    {
        "name": "Slack Webhook",
        "severity": "high",
        "regex": re.compile(
            r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,10}/B[A-Z0-9]{8,10}/[A-Za-z0-9]{24}",
            re.I,
        ),
    },
    {
        "name": "Discord Webhook",
        "severity": "high",
        "regex": re.compile(
            r"https://discord(?:app)?\.com/api/webhooks/\d{17,20}/[A-Za-z0-9_\-]{60,90}",
            re.I,
        ),
    },
    {
        "name": "Telegram Bot Token",
        "severity": "critical",
        "regex": re.compile(r"\b\d{8,12}:[A-Za-z0-9_\-]{35}\b"),
    },
    {
        "name": "RSA Private Key",
        "severity": "critical",
        "regex": re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----"),
    },
    {
        "name": "JWT Token",
        "severity": "medium",
        "regex": re.compile(
            r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"
        ),
    },
    {
        "name": "Heroku API Key",
        "severity": "high",
        "regex": re.compile(
            r"(?i)heroku.{0,30}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
        ),
    },
    {
        "name": "Mapbox Token",
        "severity": "medium",
        "regex": re.compile(r"\bpk\.eyJ1[A-Za-z0-9._\-]{60,}\b"),
    },
    {
        "name": "Square OAuth Token",
        "severity": "critical",
        "regex": re.compile(r"\bEAAA[0-9a-zA-Z]{60,}\b"),
    },
    {
        "name": "Cloudinary URL",
        "severity": "medium",
        "regex": re.compile(r"cloudinary://[0-9a-zA-Z]+:[0-9a-zA-Z]+@[a-z0-9]+", re.I),
    },
    {
        "name": "NPM Token",
        "severity": "high",
        "regex": re.compile(r"\bnpm_[0-9a-zA-Z]{36}\b"),
    },
    {
        "name": "PyPI Token",
        "severity": "high",
        "regex": re.compile(r"\bpypi-AgEI[A-Za-z0-9_\-]{50,}\b"),
    },
    {
        "name": "Basic Auth in URL",
        "severity": "high",
        "regex": re.compile(
            r"https?://[^:@/\s]{3,40}:[^:@/\s]{3,40}@[a-zA-Z0-9\-\.]+", re.I
        ),
    },
    {
        "name": "Generic Secret/Password",
        "severity": "medium",
        "regex": re.compile(
            r'(?i)(?:secret|password|passwd|api_key|apikey|auth_token)\s*[=:]\s*["\'][^\s"\']{8,60}["\']'
        ),
    },
]


def _fetch(url: str) -> Optional[str]:
    _rl.wait()
    try:
        resp = SESSION.get(url, timeout=TIMEOUT, allow_redirects=True, stream=True)
        if not resp.ok:
            return None
        raw = resp.raw.read(2_000_000, decode_content=True)
        resp.close()
        return raw.decode("utf-8", errors="ignore")
    except Exception:
        return None


def _scan(content: str, source_url: str) -> list[dict]:
    hits: list[dict] = []
    seen: set[str] = set()
    lines = content.splitlines()

    for pat in _PATTERNS:
        for m in pat["regex"].finditer(content):
            val = m.group(0)
            key = f"{pat['name']}:{val}"
            if key in seen:
                continue
            seen.add(key)

            # Compute approximate line number
            line_no = content[: m.start()].count("\n") + 1
            ctx_line = lines[line_no - 1].strip()[:200] if line_no <= len(lines) else ""

            hits.append(
                {
                    "type": pat["name"],
                    "severity": pat["severity"],
                    "source": source_url,
                    "value": val,
                    "line": line_no,
                    "context": ctx_line,
                }
            )
    return hits


def run_js_secrets(target_url: str, result: ScanResult, progress, task) -> None:
    """Scan all JS and HTML sources from Spider for leaked API keys and credentials."""

    js_urls = getattr(result, "js_endpoints", [])
    html_urls = getattr(result, "sitemap", []) or [target_url]
    sources = list(dict.fromkeys(js_urls + html_urls))[:120]
    total = len(sources)
    done = 0
    findings: list[dict] = []

    if total == 0:
        result.js_secret_findings = []
        progress.update(task, completed=50)
        return

    progress.update(
        task, description=f"[cyan]JS Secrets:[/cyan] Scanning {total} files…"
    )

    def _process(url: str) -> list[dict]:
        nonlocal done
        content = _fetch(url)
        hits = _scan(content, url) if content else []
        done += 1
        progress.update(
            task,
            description=f"[cyan]JS Secrets:[/cyan] {done}/{total} files…",
            completed=int((done / total) * 50),
        )
        return hits

    with ThreadPoolExecutor(max_workers=15) as pool:
        for future in as_completed({pool.submit(_process, u): u for u in sources}):
            batch = future.result()
            for f in batch:
                findings.append(f)
                sev = f["severity"]
                if sev in ("critical", "high"):
                    style = "red" if sev == "critical" else "yellow"
                    progress.console.print(
                        Panel(
                            f"[bold]Type   :[/bold] {f['type']}\n"
                            f"[bold]Source :[/bold] [cyan]{escape(f['source'])}[/cyan]  "
                            f"(line [yellow]{f['line']}[/yellow])\n"
                            f"[bold]Value  :[/bold] [yellow]{escape(f['value'][:80])}[/yellow]\n"
                            f"[dim]Context: {escape(f['context'][:120])}[/dim]",
                            title=f"[bold red]🕵️ SECRET FOUND — {f['type']}[/bold red]",
                            border_style=style,
                        )
                    )

    # Deduplicate by value
    seen: set[str] = set()
    unique: list[dict] = []
    for f in findings:
        if f["value"] not in seen:
            seen.add(f["value"])
            unique.append(f)

    result.js_secret_findings = unique
    progress.update(task, completed=50)
    score_and_report(result, "js_secrets")


def score_js_secrets(result):
    if not result.js_secret_findings:
        return 100
    return max(0, 100 - min(len(result.js_secret_findings) * 20, 80))


def display_js_secrets(result: ScanResult) -> None:
    console.print(
        Rule(f"[{C['warn']}]🕵️   DEEP JS SECRET HUNTER[/{C['warn']}]", style="yellow")
    )

    findings = getattr(result, "js_secret_findings", [])
    if not findings:
        console.print("  [dim]No API keys or secrets found in JS/HTML sources.[/dim]\n")
        return

    by_sev = {"critical": [], "high": [], "medium": [], "low": []}
    for f in findings:
        by_sev.setdefault(f["severity"], []).append(f)

    console.print(
        f"  Found [bold yellow]{len(findings)}[/bold yellow] secret(s) — "
        + "  ".join(
            f"[{'red' if s == 'critical' else 'yellow' if s == 'high' else 'dim'}]{len(v)} {s}[/{'red' if s == 'critical' else 'yellow' if s == 'high' else 'dim'}]"
            for s, v in by_sev.items()
            if v
        )
        + "\n"
    )

    tbl = Table(
        box=box.ROUNDED, border_style="yellow", header_style=C["head"], show_lines=True
    )
    tbl.add_column("Type", style=C["warn"], min_width=24)
    tbl.add_column("Source", style=C["accent"], min_width=35)
    tbl.add_column("Line", justify="right", min_width=5)
    tbl.add_column("Severity", justify="center", min_width=10)
    tbl.add_column("Value (truncated)", style="dim", min_width=25)

    for f in sorted(
        findings,
        key=lambda x: ["critical", "high", "medium", "low"].index(
            x.get("severity", "low")
        ),
    ):
        sev_col = (
            "bold red"
            if f["severity"] == "critical"
            else "bold yellow"
            if f["severity"] == "high"
            else "dim"
        )
        tbl.add_row(
            escape(f["type"]),
            escape(f["source"][-50:]),
            str(f["line"]),
            f"[{sev_col}]{f['severity'].upper()}[/{sev_col}]",
            escape(f["value"][:40] + ("…" if len(f["value"]) > 40 else "")),
        )

    console.print(tbl)
    console.print()


def export_js_secrets(result: ScanResult, W: callable) -> None:
    if result.js_secret_findings:
        W(f"### 🕵️ JS Secret Hunter ({len(result.js_secret_findings)} secrets)\n\n")
        W("> [!CAUTION]\n> Secrets found hardcoded in JavaScript source files.\n\n")
        rows = [
            [
                f.get("type", "?"),
                f.get("url", "?")[:80],
                f"`{str(f.get('value', ''))[:50]}`",
            ]
            for f in result.js_secret_findings
        ]
        W(md_table(["Secret Type", "Source URL", "Value"], rows))
        W("\n")
    else:
        W("### 🕵️ JS Secret Hunter\n\n- ✅ No secrets found in JS files.\n\n")
