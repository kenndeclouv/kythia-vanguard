"""
src/modules/forms.py — Module 5: HTML form enumeration + CSRF token detection.
"""

from rich import box

from rich.markup import escape
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from src.config import console, C, rate_limiter, SESSION, TIMEOUT
from src.models import ScanResult
from src.ui.display import _severity_style
from src.scoring import score_and_report

from bs4 import BeautifulSoup


CSRF_TOKEN_NAMES = {
    "csrf",
    "csrftoken",
    "_token",
    "authenticity_token",
    "__requestverificationtoken",
    "xsrf",
    "anti-csrf",
    "_csrf_token",
    "csrf_token",
    "token",
}

# Normalised set (strip hyphens/underscores) for looser matching
_CSRF_NORMALISED = {t.replace("-", "").replace("_", "") for t in CSRF_TOKEN_NAMES}


def run_form_audit(target_url: str, result: ScanResult, progress, task) -> None:
    progress.update(task, description="[cyan]Forms:[/cyan] Scraping HTML…")
    rate_limiter.wait()

    forms_found: list[dict] = []

    try:
        resp = SESSION.get(target_url, timeout=TIMEOUT, allow_redirects=True)
        if resp.ok:
            soup = BeautifulSoup(resp.text, "html.parser")
            for i, form in enumerate(soup.find_all("form"), start=1):
                action = form.get("action", "(current page)")
                method = form.get("method", "GET").upper()
                inputs = []
                has_csrf = False

                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name", "")
                    itype = inp.get("type", inp.name)
                    inputs.append({"name": name, "type": itype})
                    if (
                        name.lower().replace("-", "").replace("_", "")
                        in _CSRF_NORMALISED
                    ):
                        has_csrf = True

                forms_found.append(
                    {
                        "form_num": i,
                        "action": action,
                        "method": method,
                        "inputs": inputs,
                        "has_csrf": has_csrf,
                        "risk": (
                            "low"
                            if has_csrf
                            else ("high" if method == "POST" else "medium")
                        ),
                    }
                )
    except Exception:
        pass

    result.forms = forms_found
    progress.advance(task, 50)
    score_and_report(result, "forms")


def score_forms(result):
    if not result.forms:
        return 100
    post_forms = [f for f in result.forms if f.get("method") == "POST"]
    if not post_forms:
        return 100
    without_csrf = sum(1 for f in post_forms if not f.get("has_csrf"))
    deduct = int((without_csrf / max(len(post_forms), 1)) * 60)
    return max(0, 100 - deduct)


def display_forms(result: ScanResult) -> None:
    console.print(
        Rule(f"[{C['accent']}]📝  FORM & CSRF AUDIT[/{C['accent']}]", style="magenta")
    )
    if not result.forms:
        console.print("  [dim]No HTML forms found on the target page.[/dim]")
        console.print()
        return

    for form in result.forms:
        csrf_tag = (
            f"[{C['ok']}]✓ CSRF token detected[/{C['ok']}]"
            if form["has_csrf"]
            else f"[{C['bad']}]✗ No CSRF token![/{C['bad']}]"
        )
        risk_style = _severity_style(form["risk"])
        panel_content = f"Action : [cyan]{escape(str(form['action']))}[/cyan]\n"
        panel_content += f"Method : [bold]{form['method']}[/bold]\n"
        panel_content += f"CSRF   : {csrf_tag}\n"
        panel_content += (
            f"Risk   : [{risk_style}]{form['risk'].upper()}[/{risk_style}]\n\n"
        )

        inp_t = Table(
            box=box.MINIMAL,
            border_style="dim",
            show_header=True,
            header_style=C["subtle"],
        )
        inp_t.add_column("Input name", style=C["info"])
        inp_t.add_column("Type", style="white")
        for inp in form["inputs"]:
            inp_t.add_row(escape(inp["name"] or "(no name)"), inp["type"])

        console.print(
            Panel(
                Text.from_markup(panel_content),
                title=f"[bold]Form #{form['form_num']}[/bold]",
                border_style=risk_style,
            )
        )
        console.print(inp_t)
        console.print()


def export_forms(result: ScanResult, W: callable) -> None:
    W(f"## 📝 Forms ({len(result.forms)} found)\n\n")
    for form in result.forms:
        W(f"### Form #{form['form_num']} — `{form['method']}` → `{form['action']}`\n")
        W(f"- CSRF: {'✓ Present' if form['has_csrf'] else '✗ Missing'}\n")
        W(f"- Risk: **{form['risk'].upper()}**\n")
        inputs = ", ".join(i["name"] for i in form["inputs"] if i["name"])
        W(f"- Inputs: `{inputs}`\n\n")
