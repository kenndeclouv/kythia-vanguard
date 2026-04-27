"""
src/modules/debug.py — Framework Debug Sniper.

Deliberately triggers framework error pages to expose Laravel Ignition,
Node.js stack-traces, Spring Boot Actuator endpoints, and similar
debug-mode leaks that reveal environment variables, database credentials,
and internal source code.
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

from rich import box
from rich.markup import escape
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

from src.config import SESSION, rate_limiter, TIMEOUT, console, C
from src.models import ScanResult
from src.scoring import score_and_report

# ─────────────────────────────────────────────────────────────────
# Payloads & Signatures
# ─────────────────────────────────────────────────────────────────

# Endpoints that are likely to reveal debug pages when hit with bad input
_TRIGGER_PATHS = [
    "/__KYTHIA_VANGUARD_TRIGGER__",  # generic 404 / exception trigger
    "/api/__KYTHIA_VANGUARD_TRIGGER__",
    "/?XDEBUG_SESSION_START=1",  # Xdebug trigger
    "/index.php?XDEBUG_SESSION_START=1",
]

# Laravel / Ignition-specific endpoints that only exist in debug mode
_LARAVEL_PATHS = [
    "/_ignition/health-check",
    "/_ignition/execute-solution",
    "/telescope/api/requests",
    "/horizon/api/jobs/failed",
]

# Spring Boot Actuator endpoints
_ACTUATOR_PATHS = [
    "/actuator",
    "/actuator/env",
    "/actuator/configprops",
    "/actuator/beans",
    "/actuator/health",
    "/actuator/info",
    "/actuator/metrics",
    "/actuator/loggers",
    "/actuator/heapdump",
    "/actuator/mappings",
    "/actuator/threaddump",
    "/manage/env",
    "/manage/health",
    "/manage/beans",
]

# Django debug / generic debug endpoints
_DJANGO_PATHS = [
    "/admin/",
    "/__debug__/",
]

# ─── Fingerprint signatures for each framework ───────────────────
_SIGNATURES: list[dict] = [
    {
        "name": "Laravel Ignition",
        "severity": "critical",
        "patterns": [
            re.compile(r"Ignition\s*v?\d+", re.I),
            re.compile(r"facade\.ignition\.solutions", re.I),
            re.compile(r'"type"\s*:\s*"Illuminate\\\\', re.I),
        ],
        "env_leak": re.compile(
            r"APP_KEY|DB_PASSWORD|DB_HOST|MAIL_PASSWORD|AWS_SECRET", re.I
        ),
    },
    {
        "name": "Node.js Stack Trace",
        "severity": "high",
        "patterns": [
            re.compile(r"at Object\.<anonymous>.*\.js:\d+", re.I),
            re.compile(r"SyntaxError|ReferenceError|TypeError", re.I),
            re.compile(r"node_modules", re.I),
        ],
        "env_leak": re.compile(r"process\.env\.|\.env\s*=", re.I),
    },
    {
        "name": "Spring Boot Actuator",
        "severity": "critical",
        "patterns": [
            re.compile(r'"spring\.datasource\.|"server\.port"', re.I),
            re.compile(r'"activeProfiles"', re.I),
            re.compile(r'"contexts"\s*:\s*\{', re.I),
        ],
        "env_leak": re.compile(r"password|secret|credentials|datasource\.url", re.I),
    },
    {
        "name": "Django Debug Page",
        "severity": "high",
        "patterns": [
            re.compile(r"Django\s+Version", re.I),
            re.compile(r"Request\s+Method:|Request\s+URL:", re.I),
            re.compile(r"Traceback\s+\(most\s+recent\s+call\s+last\)", re.I),
        ],
        "env_leak": re.compile(r"SECRET_KEY|DATABASE_URL|DATABASES\s*=", re.I),
    },
    {
        "name": "PHP Error / Xdebug",
        "severity": "high",
        "patterns": [
            re.compile(r"Xdebug v?\d+\.\d+", re.I),
            re.compile(r"Fatal error.*on line \d+", re.I),
            re.compile(r"<b>Notice</b>:.*on line", re.I),
        ],
        "env_leak": re.compile(r"\$_(SERVER|ENV|POST|GET)\[", re.I),
    },
    {
        "name": "Express.js Error Handler",
        "severity": "medium",
        "patterns": [
            re.compile(r"Express\b.*<br>", re.I),
            re.compile(r"Cannot\s+(GET|POST|PUT|DELETE)\s+/", re.I),
        ],
        "env_leak": re.compile(r"process\.env", re.I),
    },
    {
        "name": "Werkzeug Debugger (Flask)",
        "severity": "critical",
        "patterns": [
            re.compile(r"werkzeug\.debug", re.I),
            re.compile(r"Traceback.*werkzeug", re.I),
            re.compile(r"The debugger caught an exception", re.I),
        ],
        "env_leak": re.compile(r"SECRET_KEY|FLASK_ENV|DATABASE_URL", re.I),
    },
]

ALL_PATHS = _TRIGGER_PATHS + _LARAVEL_PATHS + _ACTUATOR_PATHS + _DJANGO_PATHS


# ─────────────────────────────────────────────────────────────────
# Core helpers
# ─────────────────────────────────────────────────────────────────


def _probe(base_url: str, path: str) -> dict | None:
    """Hit one path, fingerprint the response. Returns a finding dict or None."""
    url = urljoin(base_url, path)
    rate_limiter.wait()
    try:
        resp = SESSION.get(url, timeout=TIMEOUT, allow_redirects=True)
    except Exception:
        return None

    body = resp.text[:80_000]  # read at most 80 KB for fingerprinting
    ct = resp.headers.get("Content-Type", "").lower()

    for sig in _SIGNATURES:
        matched_patterns = [p for p in sig["patterns"] if p.search(body)]
        if not matched_patterns:
            continue

        env_leak = bool(sig["env_leak"].search(body))
        finding = {
            "framework": sig["name"],
            "severity": sig["severity"],
            "url": url,
            "status": resp.status_code,
            "env_leak": env_leak,
            "content_type": ct,
            "snippet": _extract_snippet(body, sig["patterns"][0]),
        }
        return finding

    # Generic: JSON actuator-style dumps returned with 200
    if resp.status_code == 200 and "application/json" in ct and len(body) > 200:
        if any(
            k in body for k in ("spring", "activeProfiles", "datasource", "configprops")
        ):
            return {
                "framework": "Spring Boot Actuator (JSON)",
                "severity": "critical",
                "url": url,
                "status": resp.status_code,
                "env_leak": True,
                "content_type": ct,
                "snippet": body[:300],
            }

    return None


def _extract_snippet(body: str, pattern: re.Pattern) -> str:
    """Return up to 200 chars around the first regex match for context."""
    m = pattern.search(body)
    if not m:
        return ""
    start = max(0, m.start() - 80)
    end = min(len(body), m.end() + 120)
    raw = body[start:end].replace("\n", " ").replace("\r", "")
    # Strip HTML tags for readability
    raw = re.sub(r"<[^>]+>", "", raw)
    return raw[:250].strip()


# ─────────────────────────────────────────────────────────────────
# Module entry point
# ─────────────────────────────────────────────────────────────────


def run_debug(target_url: str, result: ScanResult, progress, task) -> None:
    """Probe common debug/error endpoints to detect framework debug-mode leaks."""
    findings: list[dict] = []
    total = len(ALL_PATHS)
    done = 0

    progress.update(task, description="[cyan]Debug Sniper:[/cyan] Launching probes…")

    def _check(path: str):
        nonlocal done
        finding = _probe(target_url, path)
        done += 1
        progress.update(
            task,
            description=f"[cyan]Debug Sniper:[/cyan] {done}/{total} paths…",
            completed=int((done / total) * 50),
        )
        return finding

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(_check, path): path for path in ALL_PATHS}
        for future in as_completed(futures):
            finding = future.result()
            if finding:
                findings.append(finding)
                sev_style = (
                    "red" if finding["severity"] in ("critical", "high") else "yellow"
                )
                env_note = (
                    "\n[bold red]⚠  ENV / CREDENTIAL LEAK DETECTED IN RESPONSE[/bold red]"
                    if finding["env_leak"]
                    else ""
                )
                progress.console.print(
                    Panel(
                        f"[bold]Framework:[/bold] {finding['framework']}\n"
                        f"[bold]URL      :[/bold] [cyan]{escape(finding['url'])}[/cyan]\n"
                        f"[bold]Status   :[/bold] {finding['status']}\n"
                        f"[bold]Severity :[/bold] [{sev_style}]{finding['severity'].upper()}[/{sev_style}]"
                        f"{env_note}",
                        title="[bold red]🐞 DEBUG PAGE EXPOSED[/bold red]",
                        border_style=sev_style,
                    )
                )

    result.debug_findings = findings
    progress.update(task, completed=50)
    score_and_report(result, "debug")


# ─────────────────────────────────────────────────────────────────
# Display function
# ─────────────────────────────────────────────────────────────────


def score_debug(result):
    if not result.debug_findings:
        return 100
    return max(0, 100 - min(len(result.debug_findings) * 20, 80))


def display_debug(result: ScanResult) -> None:
    console.print(
        Rule(f"[{C['bad']}]🐞   FRAMEWORK DEBUG SNIPER[/{C['bad']}]", style="red")
    )

    findings = getattr(result, "debug_findings", [])
    if not findings:
        console.print("  [dim]No debug / error pages exposed.[/dim]\n")
        return

    console.print(
        f"  [{C['bad']}]⚠  {len(findings)} debug endpoint(s) found![/{C['bad']}]\n"
    )

    tbl = Table(
        box=box.ROUNDED,
        border_style="red",
        header_style=C["head"],
        show_lines=True,
    )
    tbl.add_column("Framework", style=C["warn"], min_width=22)
    tbl.add_column("URL", style=C["accent"], min_width=40)
    tbl.add_column("Severity", justify="center", min_width=10)
    tbl.add_column("Creds Leak", justify="center", min_width=10)

    for f in findings:
        sev = f["severity"].upper()
        sev_style = (
            "bold red" if f["severity"] in ("critical", "high") else "bold yellow"
        )
        leak_icon = "[bold red]YES 🔑[/bold red]" if f["env_leak"] else "[dim]no[/dim]"
        tbl.add_row(
            escape(f["framework"]),
            escape(f["url"]),
            f"[{sev_style}]{sev}[/{sev_style}]",
            leak_icon,
        )

    console.print(tbl)

    # Print snippet for critical findings
    for f in findings:
        if f.get("snippet") and f["severity"] in ("critical", "high"):
            console.print(
                Panel(
                    f"[dim]{escape(f['snippet'][:300])}[/dim]",
                    title=f"[yellow]Snippet — {escape(f['framework'])}[/yellow]",
                    border_style="dim",
                )
            )

    console.print()


def export_debug(result: ScanResult, W: callable) -> None:
    if result.debug_findings:
        W(f"### 🐞 Debug Mode Exposure ({len(result.debug_findings)} findings)\n\n")
        for f in result.debug_findings:
            sev = f.get("severity", "info").upper()
            W(f"#### `[{sev}]` {f.get('title', 'Unknown')}\n\n")
            W(f"- **URL:** {f.get('url', '?')}\n")
            W(f"- **Detail:** {f.get('detail', '')}\n")
            if f.get("evidence"):
                W(f"- **Evidence:** `{str(f['evidence'])[:200]}`\n")
            W("\n")
    else:
        W("### 🐞 Debug Mode Exposure\n\n- ✅ No debug mode leaks detected.\n\n")
