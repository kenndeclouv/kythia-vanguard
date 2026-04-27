"""
src/ui/display.py — Rich display functions for each scan module's results.
"""

from rich.align import Align
from rich.panel import Panel

from src.config import console, C
from src.models import ScanResult


# ─────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────


def _severity_style(sev: str) -> str:
    return {
        "high": C["bad"],
        "medium": C["warn"],
        "low": C["ok"],
        "info": C["info"],
        "critical": "bold red",
        "unknown": "dim",
    }.get(sev.lower(), "white")


# ─────────────────────────────────────────────────────────────────
# Display score
# ─────────────────────────────────────────────────────────────────


def display_score(result: ScanResult) -> None:
    score = result.score
    if score >= 80:
        colour, grade, emoji = "green", "A", "🟢"
    elif score >= 60:
        colour, grade, emoji = "yellow", "B", "🟡"
    elif score >= 40:
        colour, grade, emoji = "dark_orange", "C", "🟠"
    else:
        colour, grade, emoji = "red", "D", "🔴"

    bar_filled = int(score / 5)
    bar_empty = 20 - bar_filled
    bar = f"[{colour}]{'█' * bar_filled}[/{colour}][dim]{'░' * bar_empty}[/dim]"

    console.print()
    console.print(
        Panel(
            Align.center(
                f"\n{emoji}  Security Score\n\n"
                f"[bold {colour}]{score}/100[/bold {colour}]  Grade: [bold]{grade}[/bold]\n\n"
                f"{bar}\n",
                vertical="middle",
            ),
            title="[bold white]Overall Security Posture[/bold white]",
            border_style=colour,
            width=60,
            padding=(1, 4),
        )
    )
    console.print()
