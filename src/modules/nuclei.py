"""
src/modules/nuclei.py — Module: Nuclei Vulnerability Scanner Wrapper.
"""

import subprocess
import json
from src.models import ScanResult

def run_nuclei_scan(target_url: str, result: ScanResult, progress, task) -> None:
    progress.update(task, description="[cyan]Nuclei:[/cyan] Starting engine (may take a while)...")
    
    command = ["nuclei", "-u", target_url, "-j", "-silent"]
    findings = []
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    try:
        # Jalankan command dan tangkap outputnya secara real-time
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

        for line in process.stdout:
            try:
                data = json.loads(line)
                info = data.get("info", {})
                sev = info.get("severity", "info").lower()
                name = info.get("name", "Unknown Vulnerability")
                
                findings.append({
                    "id": data.get("template-id", "unknown"),
                    "name": name,
                    "severity": sev,
                    "matched_at": data.get("matched-at", target_url)
                })

                if sev in counts:
                    counts[sev] += 1
                else:
                    counts[sev] = 1

                # Update progress bar UI
                progress.update(task, description=f"[cyan]Nuclei:[/cyan] Found [{sev.upper()}] {name[:25]}...")

            except json.JSONDecodeError:
                continue

        process.wait()
        result.nuclei_findings = findings
        result.nuclei_summary = counts
        progress.advance(task, 50) 

    except FileNotFoundError:
        progress.update(task, description="[bold red]✗ Nuclei is not installed on OS![/bold red]")
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
        progress.console.print(Panel(install_msg, title="[bold red]Warning: Nuclei Missing[/bold red]", border_style="red"))