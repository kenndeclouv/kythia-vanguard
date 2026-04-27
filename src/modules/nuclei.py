"""
src/modules/nuclei.py — Module: Nuclei Vulnerability Scanner Wrapper.
"""

import subprocess
from src.export import md_table
import json

from rich import box
from rich.align import Align
from rich.markup import escape
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

from src.config import console, C
from src.models import ScanResult
from src.scoring import score_and_report


def run_nuclei_scan(target_url: str, result: ScanResult, progress, task) -> None:
    progress.update(
        task, description="[cyan]Nuclei:[/cyan] Starting engine (may take a while)..."
    )

    command = ["nuclei", "-u", target_url, "-j", "-silent"]
    findings = []
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    try:
        # Jalankan command dan tangkap outputnya secara real-time
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        )

        for line in process.stdout:
            try:
                data = json.loads(line)
                info = data.get("info", {})
                sev = info.get("severity", "info").lower()
                name = info.get("name", "Unknown Vulnerability")

                findings.append(
                    {
                        "id": data.get("template-id", "unknown"),
                        "name": name,
                        "severity": sev,
                        "matched_at": data.get("matched-at", target_url),
                    }
                )

                if sev in counts:
                    counts[sev] += 1
                else:
                    counts[sev] = 1

                # Update progress bar UI
                progress.update(
                    task,
                    description=f"[cyan]Nuclei:[/cyan] Found [{sev.upper()}] {name[:25]}...",
                )

            except json.JSONDecodeError:
                continue

        process.wait()
        result.nuclei_findings = findings
        result.nuclei_summary = counts
        progress.advance(task, 50)

    except FileNotFoundError:
        progress.update(
            task, description="[bold red]✗ Nuclei is not installed on OS![/bold red]"
        )
        progress.advance(task, 50)

        from rich.panel import Panel

        install_msg = (
            "[dim]It seems the Nuclei engine is not installed on your system.[/dim]\n\n"
            "[bold yellow]How to Install on Linux (Ubuntu/Debian) [/bold yellow]\n"
            "1. Make sure Go is installed:    [cyan]sudo apt install golang[/cyan]\n"
            "2. Install Nuclei:               [bold green]go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest[/bold green]\n"
            "3. Register Path:                [bold green]export PATH=$PATH:$HOME/go/bin[/bold green]\n"
            "4. Download Templates:           [bold green]nuclei -update-templates[/bold green]"
        )
        progress.console.print(
            Panel(
                install_msg,
                title="[bold red]Warning: Nuclei Missing[/bold red]",
                border_style="red",
            )
        )
        score_and_report(result, "nuclei")


def score_nuclei(result):
    if not result.nuclei_findings:
        return 100
    _d = {"critical": 25, "high": 15, "medium": 6, "low": 2, "info": 0}
    deduct = sum(
        _d.get(n.get("severity", "info").lower(), 0) for n in result.nuclei_findings
    )
    return max(0, 100 - min(deduct, 90))


def display_nuclei(result: ScanResult) -> None:
    console.print(
        Rule(
            f"[{C['accent']}]☢️  NUCLEI VULNERABILITY SCAN[/{C['accent']}]",
            style="magenta",
        )
    )

    if not result.nuclei_findings:
        console.print("  [dim]No vulnerabilities found.[/dim]\n")
        return

    # Panel Summary Kesimpulan
    counts = result.nuclei_summary
    summary_text = (
        f"[bold red]Critical:[/bold red] {counts.get('critical', 0)} | "
        f"[bold light_coral]High:[/bold light_coral] {counts.get('high', 0)} | "
        f"[bold yellow]Medium:[/bold yellow] {counts.get('medium', 0)} | "
        f"[bold green]Low:[/bold green] {counts.get('low', 0)} | "
        f"[bold blue]Info:[/bold blue] {counts.get('info', 0)}"
    )
    console.print(
        Panel(
            Align.center(summary_text),
            title="[bold white]Nuclei Scan Summary[/bold white]",
            border_style="cyan",
        )
    )
    console.print()

    # Tabel Detail
    t = Table(box=box.ROUNDED, border_style="red", header_style=C["head"])
    t.add_column("Severity", justify="center", width=12)
    t.add_column("Template ID", style="cyan", width=25)
    t.add_column("Vulnerability Name", style="white")
    t.add_column("Matched URL", style="dim")

    # Urutkan dari Critical ke Info
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(
        result.nuclei_findings, key=lambda x: sev_rank.get(x["severity"], 5)
    )

    for f in sorted_findings:
        sev = f["severity"]
        sev_style = (
            "bold red"
            if sev in ["critical", "high"]
            else ("bold yellow" if sev == "medium" else "bold green")
        )
        t.add_row(
            f"[{sev_style}]{sev.upper()}[/{sev_style}]",
            f["id"],
            escape(f["name"]),
            escape(f["matched_at"]),
        )

    console.print(t)
    console.print()


def export_nuclei(result: ScanResult, W: callable) -> None:
    if result.nuclei_findings:
        W(f"## ☢️ Nuclei Scan ({len(result.nuclei_findings)} findings)\n\n")
        rows = [
            [
                n.get("template_id", "?"),
                n.get("severity", "?"),
                n.get("name", "?"),
                n.get("matched_at", "?"),
            ]
            for n in result.nuclei_findings
        ]
        W(md_table(["Template ID", "Severity", "Name", "Matched At"], rows))
        W("\n")
