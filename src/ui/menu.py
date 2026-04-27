"""
src/ui/menu.py — Interactive prompt-toolkit menu for target + module selection.
"""

import os
import sys

from prompt_toolkit import prompt as ptk_prompt
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.shortcuts import checkboxlist_dialog, radiolist_dialog
from prompt_toolkit.styles import Style as PtkStyle
from rich.rule import Rule
from rich.panel import Panel
from rich.align import Align
from rich.text import Text

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

    values = [("ALL", "✓  SELECT ALL MODULES")] + SCAN_MODULES
    result = checkboxlist_dialog(
        title="Kythia Vanguard v1.0.0-rc.1 — Select Scan Modules",
        text="Use SPACE to toggle, ENTER to confirm, TAB to switch focus:",
        values=values,
        style=PTK_STYLE,
    ).run()

    if not result:
        console.print("[bold yellow]No modules selected. Exiting.[/bold yellow]")
        sys.exit(0)

    if "ALL" in result:
        result = [mod_id for mod_id, _ in SCAN_MODULES]

    rps_choice = radiolist_dialog(
        title="Rate Limit (requests / second)",
        text="Choose scan aggressiveness (lower = safer for the target):",
        values=[
            (2, "Gentle   —  2 req/s  (recommended for production)"),
            (5, "Normal   —  5 req/s  (balanced)"),
            (10, "Fast     — 10 req/s  (use only on your own infra)"),
            (100, "BRUTAL   — 100 req/s (insanely crazy - may crash servers)"),
            (10000, "DOOMSDAY — 10000 req/s (Nuclear option - guaranteed takedown)"),
        ],
        style=PTK_STYLE,
    ).run()

    if rps_choice:
        rate_limiter.delay = 1.0 / rps_choice
        if rps_choice == 100:
            os.environ["BRUTAL"] = "1"
            msg = "☠️ BRUTAL MODE ENABLED — No limits, infinite loops active!"
            console.print(
                Panel(
                    Align.center(Text(msg, style="bold red blink")),
                    border_style="red",
                    padding=(1, 2),
                )
            )
        elif rps_choice == 10000:
            os.environ["DOOMSDAY"] = "1"
            os.environ["BRUTAL"] = "1"  # Doomsday implies brutal
            msg = "☢️ DOOMSDAY MODE ENABLED — NUCLEAR OPTION ENGAGED!"
            console.print(
                Panel(
                    Align.center(Text(msg, style="bold white on red blink")),
                    border_style="red",
                    padding=(1, 2),
                )
            )

    return target, result
