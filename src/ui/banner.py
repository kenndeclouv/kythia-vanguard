"""
src/ui/banner.py — ASCII art banner and show_banner().
"""

from rich.align import Align
from rich.panel import Panel
from rich.text import Text

from src.config import console, C

BANNER = r"""
 ██╗  ██╗███████╗███╗   ██╗███╗   ██╗      ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ██║ ██╔╝██╔════╝████╗  ██║████╗  ██║      ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 █████╔╝ █████╗  ██╔██╗ ██║██╔██╗ ██║█████╗██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██╔═██╗ ██╔══╝  ██║╚██╗██║██║╚██╗██║╚════╝██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ██║  ██╗███████╗██║ ╚████║██║ ╚████║      ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═══╝      ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
                                 ╔═══╗ ╦═╗ ╔═╗
                                 ╠═══╝ ╠╦╝ ║ ║
                                 ╩     ╩╚═ ╚═╝
Author  : Kenndeclouv
Github  : https://github.com/kenndeclouv
Website : https://kenndeclouv.com
Version : 1.0.0-rc.1
"""


def show_banner() -> None:
    console.print()
    console.print(
        Panel(
            Align.center(Text(BANNER, style=C["banner"])),
            border_style="cyan",
            subtitle="[dim]For authorized security testing only — use responsibly[/dim]",
            padding=(0, 2),
        )
    )
    console.print()
