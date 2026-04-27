"""
src/modules/fuzzing.py — Module 4: Smart fuzzing + WAF BYPASS MUTATOR.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
from rich import box
from rich.markup import escape
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

from src.config import console, C, rate_limiter, SESSION, TIMEOUT
from src.models import ScanResult
from src.ui.display import _severity_style

try:
    with open("words.txt") as _f:
        FUZZ_WORDLIST = [line.strip() for line in _f if line.strip()]
except FileNotFoundError:
    FUZZ_WORDLIST = ["/.env", "/.git/config", "/admin", "/robots.txt"]

_HIGH_SEVERITY_KEYWORDS = {
    ".git",
    ".env",
    "config",
    "backup",
    "dump",
    "phpinfo",
    "actuator",
}


def _fuzz_single(base_url: str, path: str, progress) -> Optional[dict]:
    url = base_url.rstrip("/") + path
    rate_limiter.wait()
    try:
        resp = SESSION.get(url, timeout=TIMEOUT, allow_redirects=True)
    except Exception:
        return None

    code = resp.status_code

    # WAF BYPASS MUTATOR
    if code in (403, 406, 429):
        mutations = [
            f"/%2e{path}",
            f"{path}/",
            f"{path}//",
            f"{path}.json",
            f"{path}?bypass=1",
        ]
        for mut in mutations:
            mut_url = base_url.rstrip("/") + mut
            try:
                m_resp = SESSION.get(
                    mut_url, headers={"X-Forwarded-For": "127.0.0.1"}, timeout=TIMEOUT
                )
                if m_resp.status_code == 200:
                    progress.console.print(
                        Panel(
                            f"[bold green]WAF BYPASSED![/bold green]\n"
                            f"Original: {url} (Blocked)\n"
                            f"Mutated : {mut_url} (Success 200 OK)",
                            title="WAF BYPASS MUTATOR",
                            border_style="green",
                        )
                    )
                    return {
                        "path": f"{mut} [BYPASSED]",
                        "url": mut_url,
                        "status": 200,
                        "size": len(m_resp.content),
                        "content_type": m_resp.headers.get("Content-Type", ""),
                        "severity": "critical",
                    }
            except Exception:
                pass

    if code not in (200, 301, 302, 401, 403, 500):
        return None

    severity = "info"
    if code == 200:
        severity = (
            "high" if any(kw in path for kw in _HIGH_SEVERITY_KEYWORDS) else "medium"
        )
    elif code in (401, 403):
        severity = "low"

    return {
        "path": path,
        "url": url,
        "status": code,
        "size": len(resp.content),
        "content_type": resp.headers.get("Content-Type", ""),
        "severity": severity,
    }


def run_fuzzing(target_url: str, result: ScanResult, progress, task) -> None:
    findings: list[dict] = []
    total = len(FUZZ_WORDLIST)

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {
            executor.submit(_fuzz_single, target_url, p, progress): p
            for p in FUZZ_WORDLIST
        }
        done = 0
        for future in as_completed(futures):
            done += 1
            progress.update(
                task,
                description=f"[cyan]Fuzz:[/cyan] {done}/{total} paths…",
                completed=int((done / total) * 50),
            )
            finding = future.result()
            if finding:
                findings.append(finding)

    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    result.fuzzing = sorted(findings, key=lambda f: rank.get(f["severity"], 9))


def display_fuzzing(result: ScanResult) -> None:
    console.print(
        Rule(
            f"[{C['accent']}]🔍  DIRECTORY / ENDPOINT FUZZING RESULTS[/{C['accent']}]",
            style="magenta",
        )
    )
    if not result.fuzzing:
        console.print("  [dim]No interesting paths discovered.[/dim]")
        console.print()
        return

    t = Table(
        box=box.ROUNDED, border_style="red", header_style=C["head"], show_lines=True
    )
    t.add_column("Severity", width=10, justify="center")
    t.add_column("HTTP", width=6, justify="center")
    t.add_column("Path", style=C["warn"])
    t.add_column("Size (bytes)", width=14, justify="right")
    t.add_column("Content-Type", style=C["dim"])
    for f in result.fuzzing:
        sev_style = _severity_style(f["severity"])
        t.add_row(
            f"[{sev_style}]{f['severity'].upper()}[/{sev_style}]",
            str(f["status"]),
            escape(f["path"]),
            str(f["size"]),
            escape(f["content_type"][:50]),
        )
    console.print(t)
    console.print()
