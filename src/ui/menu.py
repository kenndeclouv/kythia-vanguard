"""
src/ui/menu.py — Interactive prompt-toolkit menu for target + module selection.
"""

import sys

from prompt_toolkit import prompt as ptk_prompt
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.shortcuts import checkboxlist_dialog, radiolist_dialog
from prompt_toolkit.styles import Style as PtkStyle
from rich.rule import Rule

from src.config import console, SCAN_MODULES, rate_limiter

PTK_STYLE = PtkStyle.from_dict(
    {
        "dialog": "bg:#0d1117 #c9d1d9",
        "dialog frame.label": "bg:#161b22 bold #58a6ff",
        "dialog.body": "bg:#0d1117 #c9d1d9",
        "dialog shadow": "bg:#010409",
        "radio-list": "bg:#0d1117",
        "radio": "#8b949e",
        "radio-checked": "bold #58a6ff",
        "button": "bg:#21262d #c9d1d9",
        "button.focused": "bg:#388bfd bold #ffffff",
    }
)


def interactive_menu() -> tuple[str, list[str]]:
    """
    Prompt the user for a target URL and the modules to run.
    Returns (target_string, list_of_module_keys).
    """
    console.print(Rule("[bold cyan]Configuration[/bold cyan]", style="cyan"))
    console.print()

    target = ptk_prompt(
        HTML("<ansibrightcyan><b> 🎯  Target URL or domain ❯  </b></ansibrightcyan>"),
        style=PtkStyle.from_dict({"": "bg:#0d1117 #c9d1d9"}),
    ).strip()

    if not target:
        console.print("[bold red]No target provided. Exiting.[/bold red]")
        sys.exit(0)

    result = checkboxlist_dialog(
        title="KENN-RECON Pro v1.0.0-rc.1 — Select Scan Modules",
        text="Use SPACE to toggle, ENTER to confirm, TAB to switch focus:",
        values=SCAN_MODULES,
        style=PTK_STYLE,
    ).run()

    if not result:
        console.print("[bold yellow]No modules selected. Exiting.[/bold yellow]")
        sys.exit(0)

    rps_choice = radiolist_dialog(
        title="Rate Limit (requests / second)",
        text="Choose scan aggressiveness (lower = safer for the target):",
        values=[
            (2, "Gentle   —  2 req/s  (recommended for production)"),
            (5, "Normal   —  5 req/s  (balanced)"),
            (10, "Fast     — 10 req/s  (use only on your own infra)"),
            (100, "BRUTAL   — 100 req/s (insanely crazy - may crash servers)"),
        ],
        style=PTK_STYLE,
    ).run()

    if rps_choice:
        rate_limiter.delay = 1.0 / rps_choice

    return target, result
