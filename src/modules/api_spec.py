"""
src/modules/api_spec.py — API Spec & Shadow Endpoint Hunter

Strategy:
  1. Brute-force common API specification paths (swagger.json, openapi.yaml, etc.).
  2. If found, parse the JSON/YAML to extract endpoints, methods, and parameters.
  3. Report exposed documentation and outline the API surface.
"""

from __future__ import annotations

import json
from urllib.parse import urljoin

import yaml
from rich.panel import Panel
from rich.table import Table
from rich.markup import escape

from src.config import SESSION, console
from src.models import ScanResult
from src.scoring import score_and_report

_SPEC_PATHS = [
    "/swagger.json",
    "/api/swagger.json",
    "/v1/swagger.json",
    "/v2/swagger.json",
    "/v3/swagger.json",
    "/swagger/v1/swagger.json",
    "/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/openapi.json",
    "/api/openapi.json",
    "/openapi.yaml",
    "/api/openapi.yaml",
    "/docs/swagger.json",
    "/docs/openapi.json",
]


def _parse_spec(content: str) -> list[dict]:
    """Attempt to parse Swagger/OpenAPI spec and return list of endpoints."""
    endpoints = []

    try:
        if content.strip().startswith("{"):
            data = json.loads(content)
        else:
            data = yaml.safe_load(content)

        if not isinstance(data, dict):
            return []

        paths = data.get("paths", {})
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, details in methods.items():
                if method.lower() not in [
                    "get",
                    "post",
                    "put",
                    "delete",
                    "patch",
                    "options",
                ]:
                    continue

                desc = details.get("summary", details.get("description", ""))
                endpoints.append(
                    {
                        "path": path,
                        "method": method.upper(),
                        "description": str(desc)[:100],
                    }
                )
    except Exception:
        pass

    return endpoints


def run_apisec(
    target_url: str, hostname: str, result: ScanResult, progress, task
) -> None:
    """Hunt for exposed API specifications."""
    findings = []

    total = len(_SPEC_PATHS)
    for i, path in enumerate(_SPEC_PATHS):
        progress.update(
            task,
            description=f"[cyan]API Sec Hunter:[/cyan] Probing {path}…",
            completed=(i / total) * 100,
        )

        url = urljoin(target_url, path)
        try:
            r = SESSION.get(url, timeout=5, allow_redirects=True)
            if r.status_code == 200 and (
                "swagger" in r.text.lower()
                or "openapi" in r.text.lower()
                or "paths" in r.text.lower()
            ):
                endpoints = _parse_spec(r.text)

                findings.append(
                    {
                        "url": url,
                        "endpoints_count": len(endpoints),
                        "endpoints": endpoints[:50],  # Store up to 50 for the report
                        "severity": "high" if len(endpoints) > 0 else "medium",
                    }
                )

                progress.console.print(
                    Panel(
                        f"[bold red]EXPOSED API SPECIFICATION DETECTED[/bold red]\n\n"
                        f"  [bold]URL:[/bold] [cyan]{url}[/cyan]\n"
                        f"  [bold]Endpoints parsed:[/bold] {len(endpoints)}\n\n"
                        f"  [dim]This leaks internal API routing and parameters, enabling deeper attacks.[/dim]",
                        title="[bold yellow]⚠️ SHADOW API RISK[/bold yellow]",
                        border_style="yellow",
                    )
                )

        except Exception:
            pass

    result.apisec_findings = findings
    progress.update(task, completed=100)
    score_and_report(result, "api_spec")


def display_apisec(result: ScanResult) -> None:
    findings = getattr(result, "apisec_findings", [])
    if not findings:
        return

    console.print()
    for f in findings:
        tbl = Table(
            "Method",
            "Path",
            "Description",
            title=f"[bold yellow]🔌 Exposed API Spec: {escape(f['url'])} ({f['endpoints_count']} endpoints)[/bold yellow]",
            header_style="bold yellow",
            border_style="yellow",
            show_lines=True,
        )
        for ep in f.get("endpoints", []):
            color = (
                "green"
                if ep["method"] == "GET"
                else "red"
                if ep["method"] in ["POST", "DELETE"]
                else "yellow"
            )
            tbl.add_row(
                f"[{color}]{ep['method']}[/{color}]",
                escape(ep["path"]),
                f"[dim]{escape(ep['description'])}[/dim]",
            )
        console.print(tbl)
        if f["endpoints_count"] > len(f.get("endpoints", [])):
            console.print(
                f"  [dim]...and {f['endpoints_count'] - len(f['endpoints'])} more endpoints truncated.[/dim]"
            )


def export_api_spec(result: ScanResult, W: callable) -> None:
    if result.apisec_findings:
        W("## 📜 API Specification Hunter\n\n")
        for f in result.apisec_findings:
            W(f"- **API**: `{f.get('url', '?')}`\n")
        W("\n")


def score_api_spec(result):
    if not result.apisec_findings:
        return 100
    return max(0, 100 - min(len(result.apisec_findings) * 10, 40))
