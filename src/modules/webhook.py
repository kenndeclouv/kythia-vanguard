"""
src/modules/webhook.py — Webhook & Bot Hijacker.

Hunts for hardcoded Discord Webhook URLs, Telegram Bot Tokens,
Slack API/Webhook keys, and similar bot credentials buried in
JS and HTML source files. Optionally validates found tokens by
sending a harmless test API call (read-only where possible).
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from rich import box
from rich.markup import escape
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

from src.config import SESSION, rate_limiter, TIMEOUT, console, C
from src.models import ScanResult

# ─────────────────────────────────────────────────────────────────
# Regex patterns — sorted by specificity
# ─────────────────────────────────────────────────────────────────

_PATTERNS: list[dict] = [
    {
        "name": "Discord Webhook",
        "severity": "high",
        "regex": re.compile(
            r"https://discord(?:app)?\.com/api/webhooks/(\d{17,20})/([A-Za-z0-9_\-]{60,90})",
            re.I,
        ),
        "full_match": True,
    },
    {
        "name": "Telegram Bot Token",
        "severity": "critical",
        "regex": re.compile(r"\b(\d{8,12}:[A-Za-z0-9_\-]{35})\b"),
        "full_match": False,
    },
    {
        "name": "Slack Webhook URL",
        "severity": "high",
        "regex": re.compile(
            r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,10}/B[A-Z0-9]{8,10}/[A-Za-z0-9]{24}",
            re.I,
        ),
        "full_match": True,
    },
    {
        "name": "Slack API Token",
        "severity": "high",
        "regex": re.compile(r"xox[bpoa]-[0-9A-Za-z\-]{10,72}"),
        "full_match": False,
    },
    {
        "name": "Slack Bot/User OAuth",
        "severity": "high",
        "regex": re.compile(r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}"),
        "full_match": False,
    },
    {
        "name": "Line Notify Token",
        "severity": "medium",
        "regex": re.compile(
            r"https://notify-api\.line\.me/api/notify.*token=[A-Za-z0-9_\-]{40,50}",
            re.I,
        ),
        "full_match": True,
    },
    {
        "name": "Mattermost Webhook",
        "severity": "medium",
        "regex": re.compile(r"https?://[^/]+/hooks/[a-z0-9]{26}", re.I),
        "full_match": True,
    },
    {
        "name": "Pushover Token",
        "severity": "medium",
        "regex": re.compile(r"[\"']([a-zA-Z0-9]{30})[\"'].*pushover", re.I),
        "full_match": False,
    },
]


def _fetch_source(url: str) -> Optional[str]:
    rate_limiter.wait()
    try:
        resp = SESSION.get(url, timeout=TIMEOUT, allow_redirects=True, stream=True)
        if not resp.ok:
            return None
        raw = resp.raw.read(5_000_000, decode_content=True)
        return raw.decode("utf-8", errors="ignore")
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────
# Validation helpers (read-only / non-destructive)
# ─────────────────────────────────────────────────────────────────


def _validate_discord_webhook(webhook_url: str) -> dict:
    """GET the webhook info endpoint (non-destructive)."""
    try:
        resp = SESSION.get(webhook_url, timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "valid": True,
                "guild": data.get("guild_id", "?"),
                "channel": data.get("channel_id", "?"),
                "name": data.get("name", "?"),
            }
    except Exception:
        pass
    return {"valid": False}


def _validate_telegram_token(token: str) -> dict:
    """Call getMe — read-only Telegram Bot API endpoint."""
    try:
        resp = SESSION.get(
            f"https://api.telegram.org/bot{token}/getMe", timeout=TIMEOUT
        )
        if resp.status_code == 200:
            data = resp.json()
            bot = data.get("result", {})
            return {
                "valid": True,
                "username": bot.get("username", "?"),
                "first_name": bot.get("first_name", "?"),
            }
    except Exception:
        pass
    return {"valid": False}


def _validate_slack_webhook(webhook_url: str) -> dict:
    """Slack webhooks only return 'missing_text_or_fallback_or_attachments' for empty POSTs — safe probe."""
    try:
        resp = SESSION.post(webhook_url, json={}, timeout=TIMEOUT)
        # 400 with "no_text" means the webhook exists and is valid
        if resp.status_code in (200, 400):
            return {"valid": True, "response": resp.text[:80]}
    except Exception:
        pass
    return {"valid": False}


# ─────────────────────────────────────────────────────────────────
# Core scanner
# ─────────────────────────────────────────────────────────────────


def _scan_content(content: str, source_url: str) -> list[dict]:
    """Run all regex patterns against a blob of source text."""
    hits: list[dict] = []
    seen: set[str] = set()

    for pat in _PATTERNS:
        for m in pat["regex"].finditer(content):
            value = m.group(0)
            if value in seen:
                continue
            seen.add(value)

            finding = {
                "type": pat["name"],
                "severity": pat["severity"],
                "source": source_url,
                "value": value,
                "validated": False,
                "validation_info": {},
            }
            hits.append(finding)

    return hits


def _validate_finding(finding: dict) -> dict:
    """Attempt non-destructive validation of a credential."""
    t = finding["type"]
    v = finding["value"]

    if t == "Discord Webhook" and "discord.com" in v:
        info = _validate_discord_webhook(v)
        finding["validated"] = info["valid"]
        finding["validation_info"] = info

    elif t == "Telegram Bot Token":
        info = _validate_telegram_token(v)
        finding["validated"] = info["valid"]
        finding["validation_info"] = info

    elif t == "Slack Webhook URL":
        info = _validate_slack_webhook(v)
        finding["validated"] = info["valid"]
        finding["validation_info"] = info

    return finding


# ─────────────────────────────────────────────────────────────────
# Module entry point
# ─────────────────────────────────────────────────────────────────


def run_webhook(
    target_url: str, hostname: str, result: ScanResult, progress, task
) -> None:
    """Hunt for hardcoded webhook/bot credentials using Spider's harvested URLs."""
    findings: list[dict] = []

    progress.update(
        task, description="[cyan]Webhook Hunter:[/cyan] Loading URLs from Spider…"
    )

    # 🔥 Pakai data Spider — nggak perlu crawl dari nol!
    # js_endpoints = semua file .js yang ketemu waktu Spider jalan
    # sitemap      = semua internal HTML pages yang udah dikunjungi Spider
    js_urls   = getattr(result, "js_endpoints", [])
    html_urls = getattr(result, "sitemap", []) or [target_url]

    # Gabungin, dedup, batasi 100 supaya nggak lemot
    sources = list(dict.fromkeys(js_urls + html_urls))[:100]
    total   = len(sources)
    done    = 0

    if total == 0:
        progress.update(task, completed=50)
        return

    progress.update(
        task,
        description=f"[cyan]Webhook Hunter:[/cyan] Scanning {total} files from Spider…",
    )

    def _process(url: str) -> list[dict]:
        nonlocal done
        content = _fetch_source(url)
        hits: list[dict] = []
        if content:
            hits = _scan_content(content, url)
        done += 1
        progress.update(
            task,
            description=f"[cyan]Webhook Hunter:[/cyan] {done}/{total} files…",
            completed=int((done / total) * 35),
        )
        return hits

    # Phase 1: scan all source files in parallel
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(_process, url): url for url in sources}
        for future in as_completed(futures):
            findings.extend(future.result())

    # Deduplicate
    seen_vals: set[str] = set()
    unique: list[dict] = []
    for f in findings:
        if f["value"] not in seen_vals:
            seen_vals.add(f["value"])
            unique.append(f)
    findings = unique

    # Phase 2: validate each finding
    progress.update(
        task,
        description="[cyan]Webhook Hunter:[/cyan] Validating credentials…",
        completed=35,
    )
    validated: list[dict] = []
    with ThreadPoolExecutor(max_workers=5) as pool:
        v_futures = {pool.submit(_validate_finding, f): f for f in findings}
        for i, future in enumerate(as_completed(v_futures)):
            vf = future.result()
            validated.append(vf)
            if vf["validated"]:
                sev_style = "red" if vf["severity"] == "critical" else "yellow"
                info = vf["validation_info"]
                extra = ""
                if "username" in info:
                    extra = f"\nBot: @{info['username']} ({info.get('first_name', '')})"
                elif "guild" in info:
                    extra = f"\nGuild: {info['guild']} | Channel: {info['channel']} | Name: {info['name']}"
                progress.console.print(
                    Panel(
                        f"[bold]Type  :[/bold] {vf['type']}\n"
                        f"[bold]Source:[/bold] [cyan]{escape(vf['source'])}[/cyan]\n"
                        f"[bold]Value :[/bold] [yellow]{escape(vf['value'][:80])}[/yellow]"
                        f"{extra}",
                        title="[bold red]🤖 LIVE WEBHOOK/BOT CREDENTIAL FOUND[/bold red]",
                        border_style=sev_style,
                    )
                )
            progress.update(
                task, completed=35 + int(((i + 1) / max(len(findings), 1)) * 15)
            )

    result.webhook_findings = validated
    progress.update(task, completed=50)


# ─────────────────────────────────────────────────────────────────
# Display function
# ─────────────────────────────────────────────────────────────────


def display_webhook(result: ScanResult) -> None:
    console.print(
        Rule(f"[{C['warn']}]🤖   WEBHOOK & BOT HIJACKER[/{C['warn']}]", style="yellow")
    )

    findings = getattr(result, "webhook_findings", [])
    if not findings:
        console.print("  [dim]No hardcoded webhook or bot credentials found.[/dim]\n")
        return

    live = [f for f in findings if f["validated"]]
    dead = [f for f in findings if not f["validated"]]

    console.print(
        f"  Found [bold yellow]{len(findings)}[/bold yellow] credential(s) — "
        f"[bold green]{len(live)} live[/bold green] / [dim]{len(dead)} unconfirmed[/dim]\n"
    )

    tbl = Table(
        box=box.ROUNDED,
        border_style="yellow",
        header_style=C["head"],
        show_lines=True,
    )
    tbl.add_column("Type", style=C["warn"], min_width=22)
    tbl.add_column("Source File", style=C["accent"], min_width=38)
    tbl.add_column("Severity", justify="center", min_width=10)
    tbl.add_column("Live?", justify="center", min_width=8)

    for f in sorted(findings, key=lambda x: (not x["validated"], x["severity"])):
        sev = f["severity"].upper()
        sev_col = "bold red" if f["severity"] == "critical" else "bold yellow"
        live_icon = (
            "[bold green]✓ YES[/bold green]" if f["validated"] else "[dim]?[/dim]"
        )
        tbl.add_row(
            escape(f["type"]),
            escape(f["source"][-60:]),
            f"[{sev_col}]{sev}[/{sev_col}]",
            live_icon,
        )

    console.print(tbl)
    console.print()

    # Full credential values for live findings
    for f in live:
        info_lines = f"[bold]Full Value:[/bold] [yellow]{escape(f['value'])}[/yellow]"
        vi = f.get("validation_info", {})
        if "username" in vi:
            info_lines += f"\n[bold]Bot Username:[/bold] @{escape(vi['username'])}"
        if "guild" in vi:
            info_lines += f"\n[bold]Discord Guild:[/bold] {escape(str(vi['guild']))} | Channel: {escape(str(vi.get('channel', '?')))}"

        console.print(
            Panel(
                info_lines,
                title=f"[bold green]LIVE — {escape(f['type'])}[/bold green]",
                border_style="green",
            )
        )
    console.print()
