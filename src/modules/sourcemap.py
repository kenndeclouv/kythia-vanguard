"""sourcemap.py – Source‑Map Unpacker module

Provides ``run_sourcemap`` which, given a JavaScript file URL, discovers a
referenced ``*.js.map`` file (via HTTP header or trailing comment), downloads it
and writes the original source files to ``reports/sourcemaps_{target}``. Findings are appended to ``ScanResult.sourcemap_findings``.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List

from rich.markup import escape
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text

from src.config import console, C, SESSION, rate_limiter, TIMEOUT
from src.models import ScanResult
from src.scoring import score_and_report

# Regular expression to capture a sourceMappingURL comment at the end of a JS file.
_SOURCE_MAP_RE = re.compile(r"//# sourceMappingURL=([^\s]+)")


def _extract_map_url(js_content: str, base_url: str) -> str | None:
    """Return the absolute URL of the source map if a comment is found.

    ``base_url`` is the URL of the JavaScript file used to resolve relative
    paths. If the server also provides a ``SourceMap`` header, it is preferred.
    """
    # Attempt header first – SESSION.get already fetched headers when retrieving JS.
    # This helper is called after we have the JS response, so headers are available.
    # The calling code will pass the response object if needed.
    # Here we just parse the content.
    match = _SOURCE_MAP_RE.search(js_content)
    if not match:
        return None
    relative = match.group(1).strip()
    # Resolve relative URL against the JS file URL.
    if relative.startswith("http://") or relative.startswith("https://"):
        return relative
    # Join path components.
    if base_url.endswith("/"):
        return base_url + relative
    else:
        return base_url.rsplit("/", 1)[0] + "/" + relative


def _save_map(map_content: str, target: str) -> List[Path]:
    """Parse a JSON source map and write any ``sourcesContent`` entries to disk.

    Returns a list of file paths that were written.
    """
    import json

    try:
        map_json = json.loads(map_content)
    except json.JSONDecodeError:
        return []

    sources = map_json.get("sources", [])
    sources_content = map_json.get("sourcesContent", [])
    if not sources or not sources_content:
        return []

    base_dir = Path("reports") / f"sourcemaps_{target}"
    base_dir.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []
    for src, content in zip(sources, sources_content):
        # Clean up any leading slashes or weird path elements.
        safe_path = Path(src.lstrip("/"))
        out_path = base_dir / safe_path
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(content, encoding="utf-8")
        written.append(out_path)
    return written


def run_sourcemap(
    target_url: str, hostname: str, result: ScanResult, progress, task
) -> None:
    """Retrieve JavaScript files (found by spider), locate their source‑map, download and reconstruct
    the original sources."""

    js_endpoints = getattr(result, "js_endpoints", [])
    if not js_endpoints:
        # If spider hasn't run or found no JS, we can just try the target_url itself if it ends in .js
        if target_url.endswith(".js"):
            js_endpoints = [target_url]
        else:
            progress.update(
                task,
                description="[cyan]Sourcemap:[/cyan] No JS files to check",
                completed=100,
            )
            return

    total = len(js_endpoints)
    done = 0
    all_saved = []

    for js_url in js_endpoints:
        info: dict = {"js_url": js_url, "target": hostname}

        rate_limiter.wait()
        try:
            resp = SESSION.get(js_url, timeout=TIMEOUT)
        except Exception as exc:
            info["error"] = f"request_failed: {exc}"
            result.sourcemap_findings.append(info)
            done += 1
            progress.update(
                task,
                description=f"[cyan]Sourcemap:[/cyan] {done}/{total} files…",
                completed=int((done / total) * 100),
            )
            continue

        if resp.status_code != 200:
            info["error"] = f"non‑200 response: {resp.status_code}"
            result.sourcemap_findings.append(info)
            done += 1
            progress.update(
                task,
                description=f"[cyan]Sourcemap:[/cyan] {done}/{total} files…",
                completed=int((done / total) * 100),
            )
            continue

        # Try to get SourceMap header first.
        map_url = resp.headers.get("SourceMap")
        if not map_url:
            # Fallback to comment parsing.
            map_url = _extract_map_url(resp.text, js_url)
        if not map_url:
            info["error"] = "source map not referenced"
            result.sourcemap_findings.append(info)
            done += 1
            progress.update(
                task,
                description=f"[cyan]Sourcemap:[/cyan] {done}/{total} files…",
                completed=int((done / total) * 100),
            )
            continue

        info["map_url"] = map_url
        # Download the map.
        rate_limiter.wait()
        try:
            map_resp = SESSION.get(map_url, timeout=TIMEOUT)
        except Exception as exc:
            info["error"] = f"map_download_failed: {exc}"
            result.sourcemap_findings.append(info)
            done += 1
            progress.update(
                task,
                description=f"[cyan]Sourcemap:[/cyan] {done}/{total} files…",
                completed=int((done / total) * 100),
            )
            continue

        if map_resp.status_code != 200:
            info["error"] = f"map_non200: {map_resp.status_code}"
            result.sourcemap_findings.append(info)
            done += 1
            progress.update(
                task,
                description=f"[cyan]Sourcemap:[/cyan] {done}/{total} files…",
                completed=int((done / total) * 100),
            )
            continue

        saved_files = _save_map(map_resp.text, hostname)
        info["saved"] = [str(p) for p in saved_files]
        result.sourcemap_findings.append(info)
        all_saved.extend(saved_files)

        progress.console.print(
            Panel(
                f"[bold green]Source Map Unpacked![/bold green]\n"
                f"JS: {js_url}\n"
                f"Files recovered: {len(saved_files)}",
                title="Source-Map Unpacker",
                border_style="green",
            )
        )

        done += 1
        progress.update(
            task,
            description=f"[cyan]Sourcemap:[/cyan] {done}/{total} files…",
            completed=int((done / total) * 100),
        )
        score_and_report(result, "sourcemap")


def score_sourcemap(result):
    if not result.sourcemap_findings:
        return 100
    return max(0, 100 - min(len(result.sourcemap_findings) * 15, 60))


def display_sourcemap(result: ScanResult) -> None:
    console.print(
        Rule(f"[{C['accent']}]🗺️   SOURCE-MAP UNPACKER[/{C['accent']}]", style="magenta")
    )
    if not result.sourcemap_findings:
        console.print("  [dim]No source maps recovered.[/dim]")
        console.print()
        return

    recovered_count = 0
    for finding in result.sourcemap_findings:
        saved = finding.get("saved", [])
        if saved:
            recovered_count += 1
            panel_content = (
                f"JS File: [cyan]{escape(finding.get('js_url', ''))}[/cyan]\n"
            )
            panel_content += (
                f"Map URL: [cyan]{escape(finding.get('map_url', ''))}[/cyan]\n\n"
            )
            panel_content += f"[bold]Recovered {len(saved)} source files:[/bold]\n"
            for f in saved[:10]:
                panel_content += f" - {escape(f)}\n"
            if len(saved) > 10:
                panel_content += f" - ... and {len(saved) - 10} more\n"

            console.print(Panel(Text.from_markup(panel_content), border_style="green"))

    if recovered_count == 0:
        console.print(
            "  [dim]Source maps were checked but none could be downloaded/unpacked.[/dim]"
        )
    console.print()


def export_sourcemap(result: ScanResult, W: callable) -> None:
    if result.sourcemap_findings:
        W("## 🗺️ Source Map Exposure\n\n")
        for f in result.sourcemap_findings:
            W(f"- **Map Found**: `{f.get('url', '?')}`\n")
        W("\n")
