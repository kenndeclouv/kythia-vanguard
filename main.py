#!/usr/bin/env python3
"""
╭──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│                                                                                                                                              │
│                             ██╗  ██╗███████╗███╗   ██╗███╗   ██╗      ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗                            │
│                             ██║ ██╔╝██╔════╝████╗  ██║████╗  ██║      ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║                            │
│                             █████╔╝ █████╗  ██╔██╗ ██║██╔██╗ ██║█████╗██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║                            │
│                             ██╔═██╗ ██╔══╝  ██║╚██╗██║██║╚██╗██║╚════╝██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║                            │
│                             ██║  ██╗███████╗██║ ╚████║██║ ╚████║      ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║                            │
│                             ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═══╝      ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝                            │
│                                                             ╔═══╗ ╦═╗ ╔═╗                                                                    │
│                                                             ╠═══╝ ╠╦╝ ║ ║                                                                    │
│                                                             ╩     ╩╚═ ╚═╝                                                                    │
│                            Author  : Kenndeclouv                                                                                             │
│                            Github  : https://github.com/kenndeclouv                                                                          │
│                            Website : https://kenndeclouv.com                                                                                 │
│                            Version : 1.0.0-rc.1                                                                                              │
│                                                                                                                                              │
╰─────────────────────────────────────────── For authorized security testing only — use responsibly ───────────────────────────────────────────╯
"""

import argparse
import datetime
import importlib
import inspect
import sys
import urllib.parse
from pathlib import Path

# ── src imports
from src.config import (
    console,
    C,
    rate_limiter,
    SCAN_MODULES,
)
from src.models import ScanResult
from src.ui.banner import show_banner
from src.ui.menu import interactive_menu
import src.ui.display as display_ui
from src.scoring import calculate_score
from src.export import export_results

import importlib.util

from rich.panel import Panel
from rich.rule import Rule
from rich.prompt import Confirm
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)

# ─────────────────────────────────────────────────────────────────
# Ensure src/ is on the path when run directly
# ─────────────────────────────────────────────────────────────────

ROOT_DIR = Path(__file__).resolve().parent
SRC_DIR = ROOT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# ─────────────────────────────────────────────────────────────────
# Dependency check
# ─────────────────────────────────────────────────────────────────

required_modules = ["requests", "bs4", "rich", "prompt_toolkit"]
missing_modules = [
    mod for mod in required_modules if importlib.util.find_spec(mod) is None
]

if missing_modules:
    print(f"\n[ERROR] Missing dependencies: {', '.join(missing_modules)}")
    print("Run:  pip install rich requests beautifulsoup4 prompt_toolkit\n")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────────────────────────


def normalise_target(raw: str) -> tuple[str, str]:
    raw = raw.strip().rstrip("/")
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    parsed = urllib.parse.urlparse(raw)
    return raw, parsed.hostname or raw


# ─────────────────────────────────────────────────────────────────
# Scan orchestrator (The Autoload)
# ─────────────────────────────────────────────────────────────────


def run_scan(target_raw: str, modules_selected: list[str]) -> None:
    target_url, hostname = normalise_target(target_raw)

    result = ScanResult()
    result.target = target_url
    result.timestamp = datetime.datetime.now().isoformat()

    console.print()
    console.print(
        Panel(
            f"[bold white]Target :[/bold white] [cyan]{target_url}[/cyan]\n"
            f"[bold white]Host   :[/bold white] [cyan]{hostname}[/cyan]\n"
            f"[bold white]Modules:[/bold white] [yellow]{', '.join(modules_selected)}[/yellow]",
            title="[bold magenta]Scan Configuration[/bold magenta]",
            border_style="magenta",
        )
    )
    console.print()

    # 1. AUTOLOAD RUNNERS
    MODULE_MAP = {}
    for mod_id, mod_desc in SCAN_MODULES:
        if mod_id not in modules_selected:
            continue

        short_name = mod_desc.split("—")[0].strip()

        try:
            # Import file from src/modules/ according to ID in config
            mod_obj = importlib.import_module(f"src.modules.{mod_id}")

            # Search function that starts with 'run_'
            runner_func = None
            for name, obj in inspect.getmembers(mod_obj, inspect.isfunction):
                if name.startswith("run_"):
                    runner_func = obj
                    break

            if runner_func:
                # Because each run_xxx has different parameters (some need hostname, some don't)
                # Just inspect the parameters, then inject the corresponding data!
                sig = inspect.signature(runner_func)

                def make_runner(run_f, signature):
                    def wrapper(p, t):
                        kwargs = {}
                        if "target_url" in signature.parameters:
                            kwargs["target_url"] = target_url
                        if "hostname" in signature.parameters:
                            kwargs["hostname"] = hostname
                        if "result" in signature.parameters:
                            kwargs["result"] = result
                        if "progress" in signature.parameters:
                            kwargs["progress"] = p
                        if "task" in signature.parameters:
                            kwargs["task"] = t
                        return run_f(**kwargs)

                    return wrapper

                MODULE_MAP[mod_id] = (short_name, 50, make_runner(runner_func, sig))
            else:
                console.print(
                    f"[{C['warn']}]⚠ Fungsi run_ tidak ditemukan di module {mod_id}[/{C['warn']}]"
                )

        except Exception as e:
            console.print(
                f"[{C['bad']}]✗ Error memuat module {mod_id}: {e}[/{C['bad']}]"
            )

    # 2. RUN MODULE (Only active)
    with Progress(
        SpinnerColumn(spinner_name="dots12", style="cyan"),
        TextColumn("[progress.description]{task.description}", style="white"),
        BarColumn(bar_width=35, style="cyan", complete_style="bold green"),
        TaskProgressColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        for mod_id in modules_selected:
            if mod_id not in MODULE_MAP:
                continue

            name, total, runner = MODULE_MAP[mod_id]
            task = progress.add_task(f"[cyan]{name}[/cyan]", total=total)
            try:
                runner(progress, task)
                progress.update(
                    task,
                    completed=total,
                    description=f"[green]✓ {name} complete[/green]",
                )
            except Exception as exc:
                progress.update(task, description=f"[red]✗ {name} failed: {exc}[/red]")

    result.score = calculate_score(result)

    console.print()
    console.print(Rule("[bold cyan]═══  SCAN RESULTS  ═══[/bold cyan]", style="cyan"))

    # 3. AUTOLOAD DISPLAY: Search UI function directly inside the module file!
    for mod_id in modules_selected:
        if mod_id not in MODULE_MAP:
            continue

        try:
            # Panggil lagi module-nya (Python otomatis pakai cache, jadi nggak bikin lemot)
            mod_obj = importlib.import_module(f"src.modules.{mod_id}")

            # Cari fungsi apapun yang namanya berawalan "display_" di dalam file module tersebut
            disp_func = None
            for name, obj in inspect.getmembers(mod_obj, inspect.isfunction):
                if name.startswith("display_"):
                    disp_func = obj
                    break

            # Kalau ketemu, langsung eksekusi!
            if disp_func:
                disp_func(result)

        except Exception as e:
            console.print(
                f"[{C['bad']}]✗ Error memuat UI untuk module {mod_id}: {e}[/{C['bad']}]"
            )

    # Still run display_score from src.ui.display as a closing
    display_ui.display_score(result)

    console.print(Rule("[bold]Exporting Reports[/bold]", style="dim"))
    try:
        json_path, md_path = export_results(result, target_raw)
        console.print(
            f"  [{C['ok']}]✓ JSON report:[/{C['ok']}]     [cyan]{json_path}[/cyan]"
        )
        console.print(
            f"  [{C['ok']}]✓ Markdown report:[/{C['ok']}] [cyan]{md_path}[/cyan]"
        )
    except Exception as e:
        console.print(f"  [{C['bad']}]Export failed: {e}[/{C['bad']}]")

    console.print()
    console.print(
        Rule("[dim]KENN-RECON Pro v1.0.0-rc.1 — Scan Complete[/dim]", style="dim")
    )
    console.print()


# ─────────────────────────────────────────────────────────────────
# Interactive entry point & CLI
# ─────────────────────────────────────────────────────────────────


def interactive_main() -> None:
    if sys.platform == "win32":
        console.print(
            "[yellow]⚠️ Windows detected. For best TUI experience, use WSL or Linux.[/yellow]"
        )

    show_banner()

    console.print(
        Panel(
            "[bold yellow]⚠️  LEGAL DISCLAIMER[/bold yellow]\n\n"
            "This tool is for [bold]authorized security testing ONLY[/bold].\n"
            "You must have [bold]explicit written permission[/bold] from the target owner.\n"
            "Unauthorized scanning may violate local and international law.\n"
            "By continuing, you confirm you have the necessary authorization.",
            border_style="yellow",
            expand=True,
        )
    )
    console.print()

    agreed = Confirm.ask(
        "[bold yellow]Do you have explicit authorization to scan the target?[/bold yellow]"
    )
    if not agreed:
        console.print(
            "[bold red]Aborted. Always obtain proper authorization before scanning.[/bold red]"
        )
        sys.exit(0)

    target, modules = interactive_menu()
    console.print()
    run_scan(target, modules)


def _build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="KENN-RECON Pro v1.0.0-rc.1 — Advanced Recon & Security Auditor"
    )
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("interactive", help="Run interactive scanner UI")
    quick = sub.add_parser("quick", help="Quick non-interactive scan")
    quick.add_argument("target", help="Target domain or URL")
    quick.add_argument(
        "--modules",
        "-m",
        default="recon,waf,headers,ports,osint,cve,spider,nuclei",
        help="Comma-separated module list (default: all)",
    )
    quick.add_argument(
        "--rps", type=float, default=5.0, help="Requests per second (default 5)"
    )
    return parser


def main() -> None:
    parser = _build_cli_parser()
    args = parser.parse_args()
    command = args.command or "interactive"

    if command == "interactive":
        interactive_main()
        return

    if command == "quick":
        rate_limiter.delay = 1.0 / args.rps
        modules = [m.strip() for m in args.modules.split(",") if m.strip()]
        run_scan(args.target, modules)
        return

    parser.print_help()


if __name__ == "__main__":
    main()
