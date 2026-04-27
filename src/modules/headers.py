"""
src/modules/headers.py
"""

import datetime
from src.export import md_table
import socket
import ssl

from rich import box
from rich.markup import escape
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

from src.config import console, C, SESSION, TIMEOUT
from src.models import ScanResult
from src.scoring import score_and_report

SECURITY_HEADERS: dict[str, tuple] = {
    "strict-transport-security": ("HSTS", "Enforces HTTPS connections"),
    "content-security-policy": ("CSP", "Mitigates XSS & data injection"),
    "x-content-type-options": ("X-Content-Type", "Prevents MIME-type sniffing"),
    "x-frame-options": ("X-Frame", "Prevents clickjacking"),
    "x-xss-protection": ("X-XSS-Prot", "Legacy XSS filter"),
    "referrer-policy": ("Referrer-Policy", "Controls referrer header leakage"),
    "permissions-policy": ("Permissions", "Restricts browser feature access"),
    "cross-origin-opener-policy": ("COOP", "Isolates browsing context"),
    "cross-origin-embedder-policy": ("COEP", "Requires CORP for embedded resources"),
    "cross-origin-resource-policy": ("CORP", "Controls resource sharing"),
    "cache-control": ("Cache-Control", "Controls caching behavior"),
    "x-powered-by": ("X-Powered-By", "⚠ REVEALS server tech"),
    "server": ("Server", "⚠ REVEALS server version"),
}


def run_header_analysis(
    target_url: str, hostname: str, result: ScanResult, progress, task
) -> None:
    progress.update(
        task, description="[cyan]Headers:[/cyan] Analysing security headers…"
    )
    headers_lower = {k.lower(): v for k, v in result.headers.items()}
    sec: dict = {}

    for header, (short, desc) in SECURITY_HEADERS.items():
        present = header in headers_lower
        value = headers_lower.get(header, "")
        dangerous = header in ("x-powered-by",)
        sec[header] = {
            "present": present,
            "value": value,
            "short": short,
            "desc": desc,
            "dangerous": dangerous,
        }

    # CORS Misconfiguration Exploit Test
    progress.update(
        task, description="[cyan]Headers:[/cyan] Injecting Evil CORS Origin…"
    )
    try:
        cors_resp = SESSION.get(
            target_url,
            headers={"Origin": "https://evil-kenn-hacker.com"},
            timeout=TIMEOUT,
        )
        if (
            cors_resp.headers.get("Access-Control-Allow-Origin")
            == "https://evil-kenn-hacker.com"
        ):
            progress.console.print(
                Panel(
                    f"[bold red]CRITICAL VULNERABILITY FOUND![/bold red]\n"
                    f"Target: {target_url}\n"
                    f"Issue : CORS Misconfiguration (Reflects ANY Origin)\n"
                    f"Impact: Attackers can hijack user sessions and steal data via malicious sites.",
                    title="CORS EXPLOIT",
                    border_style="red",
                )
            )
            sec["cors-misconfig"] = {
                "present": True,
                "value": "VULNERABLE (Reflects Origin)",
                "short": "CORS",
                "desc": "API Hijack Risk",
                "dangerous": True,
            }
    except Exception:
        pass

    result.security_headers = sec
    progress.advance(task, 25)

    progress.update(task, description="[cyan]TLS:[/cyan] Inspecting SSL certificate…")
    tls: dict = {}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((hostname, 443), timeout=TIMEOUT),
            server_hostname=hostname,
        ) as ssock:
            cert = ssock.getpeercert()
            tls["subject"] = dict(x[0] for x in cert.get("subject", []))
            tls["issuer"] = dict(x[0] for x in cert.get("issuer", []))
            tls["version"] = cert.get("version")
            tls["serial"] = cert.get("serialNumber")
            tls["not_before"] = cert.get("notBefore")
            tls["not_after"] = cert.get("notAfter")
            tls["protocol"] = ssock.version()
            tls["cipher"] = ssock.cipher()[0] if ssock.cipher() else "N/A"
            tls["alt_names"] = [v for _, v in cert.get("subjectAltName", [])]
            exp = datetime.datetime.strptime(tls["not_after"], "%b %d %H:%M:%S %Y %Z")
            tls["days_to_expiry"] = (exp - datetime.datetime.utcnow()).days
    except Exception as e:
        tls["error"] = str(e)

    result.tls_info = tls
    progress.advance(task, 25)
    score_and_report(result, "headers")


_CRITICAL_HEADERS_SCORE = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
]


def score_headers(result):
    score = 100
    if not result.security_headers:
        return 100
    missing = sum(
        1
        for h in _CRITICAL_HEADERS_SCORE
        if not result.security_headers.get(h, {}).get("present")
    )
    score -= missing * 12
    if result.security_headers.get("x-powered-by", {}).get("present"):
        score -= 5
    tls = result.tls_info
    if tls and "subject" in tls:
        if "error" in tls:
            score -= 20
        elif tls.get("days_to_expiry", 999) < 7:
            score -= 30
        elif tls.get("days_to_expiry", 999) < 30:
            score -= 15
    return max(0, score)


def display_headers(result: ScanResult) -> None:
    console.print(
        Rule(
            f"[{C['accent']}]📋  SECURITY HEADER ANALYSIS[/{C['accent']}]",
            style="magenta",
        )
    )
    t = Table(
        box=box.DOUBLE_EDGE,
        border_style="cyan",
        header_style=C["head"],
        show_lines=True,
    )
    t.add_column("Header", style=C["info"], width=28)
    t.add_column("Short", style=C["subtle"], width=14)
    t.add_column("Status", width=12, justify="center")
    t.add_column("Value / Note", style="white")

    for header, info in result.security_headers.items():
        present = info["present"]
        dangerous = info.get("dangerous", False)
        if dangerous:
            status = "[bold red]⚠ PRESENT[/bold red]"
            val_str = f"[red]{escape(info['value'][:80])}[/red]"
        elif present:
            status = f"[{C['ok']}]✓ Present[/{C['ok']}]"
            val_str = escape(info["value"][:80])
        else:
            status = f"[{C['bad']}]✗ Missing[/{C['bad']}]"
            val_str = f"[dim]{info['desc']}[/dim]"
        t.add_row(header, info["short"], status, val_str)
    console.print(t)
    console.print()

    tls = result.tls_info
    console.print(Rule("[bold]TLS / SSL Certificate[/bold]", style="dim"))
    if "error" in tls:
        console.print(
            f"  [{C['bad']}]⚠  TLS Error: {escape(tls['error'])}[/{C['bad']}]"
        )
    else:
        expiry_style = C["ok"] if tls.get("days_to_expiry", 0) > 30 else C["bad"]
        tls_t = Table(box=box.SIMPLE, border_style="dim", header_style=C["head"])
        tls_t.add_column("Field", style=C["info"], width=22)
        tls_t.add_column("Value", style="white")
        tls_t.add_row("Protocol", tls.get("protocol", "?"))
        tls_t.add_row("Cipher", tls.get("cipher", "?"))
        tls_t.add_row("Issued By", tls.get("issuer", {}).get("organizationName", "?"))
        tls_t.add_row("Valid From", tls.get("not_before", "?"))
        tls_t.add_row("Expires", tls.get("not_after", "?"))
        tls_t.add_row(
            "Days Left",
            f"[{expiry_style}]{tls.get('days_to_expiry', '?')} days[/{expiry_style}]",
        )
        alt = ", ".join(tls.get("alt_names", [])[:6])
        tls_t.add_row("SAN Entries", escape(alt[:100]) if alt else "N/A")
        console.print(tls_t)
    console.print()


def export_headers(result: ScanResult, W: callable) -> None:
    W("## 🔒 Security Headers\n\n")
    if result.security_headers:
        rows = [
            [hdr, "✓" if info["present"] else "✗", info.get("value", "")]
            for hdr, info in result.security_headers.items()
        ]
        W(md_table(["Header", "Present", "Value"], rows))
    W("\n")
