"""
src/modules/oauth.py — OAuth & OIDC Manipulation Hunter

Strategy:
  1. Hunt for OAuth authorization URLs in the sitemap or spider parameters.
  2. Test for missing 'state' parameter (OAuth CSRF).
  3. Test for Open Redirect in 'redirect_uri'.
"""

from __future__ import annotations

from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from rich.panel import Panel
from rich.table import Table
from rich.markup import escape

from src.config import SESSION, console
from src.models import ScanResult


def _build_url(url: str, param_name: str, payload: str) -> str:
    """Replace param_name in the URL query string with the payload."""
    parsed = urlparse(url)
    qs = parse_qsl(parsed.query)
    new_qs = []
    found = False
    for k, v in qs:
        if k == param_name:
            new_qs.append((k, payload))
            found = True
        else:
            new_qs.append((k, v))
            
    if not found:
        new_qs.append((param_name, payload))
        
    new_query = urlencode(new_qs)
    return urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
    )

def _remove_param(url: str, param_name: str) -> str:
    """Remove a parameter from the query string."""
    parsed = urlparse(url)
    qs = parse_qsl(parsed.query)
    new_qs = [(k, v) for k, v in qs if k != param_name]
    new_query = urlencode(new_qs)
    return urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
    )


def run_oauth(target_url: str, hostname: str, result: ScanResult, progress, task) -> None:
    """Hunt for OAuth misconfigurations."""
    findings = []
    
    # 1. Find potential OAuth URLs
    oauth_urls = set()
    
    # Check parameters
    parameters = getattr(result, "parameters", {})
    for url, params in parameters.items():
        if "client_id" in params and "redirect_uri" in params:
            oauth_urls.add(url)
            
    # Check sitemap
    sitemap = getattr(result, "sitemap", [])
    for url in sitemap:
        if "client_id=" in url and "redirect_uri=" in url:
            oauth_urls.add(url)
            
    if not oauth_urls:
        progress.update(task, completed=100)
        return

    progress.update(task, description=f"[cyan]OAuth Hunter:[/cyan] Testing {len(oauth_urls)} OAuth flows…")

    for url in oauth_urls:
        parsed = urlparse(url)
        qs_dict = dict(parse_qsl(parsed.query))
        
        provider = parsed.netloc
        
        # Test 1: Missing State Parameter (CSRF)
        if "state" not in qs_dict:
            findings.append({
                "url": url,
                "provider": provider,
                "vulnerability": "Missing 'state' parameter",
                "severity": "high",
                "detail": "OAuth flow is vulnerable to CSRF. An attacker can force a victim to log into the attacker's account."
            })
            progress.console.print(
                Panel(
                    f"[bold red]OAUTH CSRF VULNERABILITY[/bold red]\n\n"
                    f"  [bold]Provider:[/bold] {provider}\n"
                    f"  [bold]URL:[/bold] [dim]{url[:100]}...[/dim]\n\n"
                    f"  [dim]Missing 'state' parameter allows Cross-Site Request Forgery on the login flow.[/dim]",
                    title="[bold red blink]☠ OAUTH CSRF ☠[/bold red blink]",
                    border_style="red"
                )
            )

        # Test 2: Open Redirect via redirect_uri
        evil_redirect = "https://evil.com/callback"
        test_url = _build_url(url, "redirect_uri", evil_redirect)
        
        try:
            # We don't follow redirects because we want to see if the provider accepts it (302 to evil.com) 
            # or rejects it (400 Bad Request, or 302 to an error page).
            # Note: Many providers validate redirect_uri strictly now, but custom ones might not.
            r = SESSION.get(test_url, timeout=5, allow_redirects=False)
            
            if r.status_code in (301, 302, 303, 307, 308):
                location = r.headers.get("Location", "")
                if location.startswith(evil_redirect):
                    findings.append({
                        "url": test_url,
                        "provider": provider,
                        "vulnerability": "Open Redirect / Unvalidated redirect_uri",
                        "severity": "critical",
                        "detail": f"Provider allowed redirect to {evil_redirect}. This can lead to OAuth token theft."
                    })
                    progress.console.print(
                        Panel(
                            f"[bold red]OAUTH OPEN REDIRECT (TOKEN LEAK)[/bold red]\n\n"
                            f"  [bold]Provider:[/bold] {provider}\n"
                            f"  [bold]Test URL:[/bold] [dim]{test_url[:100]}...[/dim]\n"
                            f"  [bold]Result:[/bold] Provider redirected to {location}\n\n"
                            f"  [dim]Attacker can steal authorization codes or tokens by manipulating the redirect_uri.[/dim]",
                            title="[bold red blink]☠ OAUTH TOKEN THEFT ☠[/bold red blink]",
                            border_style="red"
                        )
                    )
        except Exception:
            pass

    result.oauth_findings = findings
    progress.update(task, completed=100)


def display_oauth(result: ScanResult) -> None:
    findings = getattr(result, "oauth_findings", [])
    if not findings:
        return

    console.print()
    tbl = Table(
        "Provider", "Vulnerability", "Severity", "Detail",
        title="[bold red]🔐 OAuth Misconfigurations[/bold red]",
        header_style="bold red",
        border_style="red",
        show_lines=True
    )
    for f in findings:
        color = "red" if f['severity'] == "critical" else "yellow"
        tbl.add_row(
            escape(f["provider"]),
            f"[bold {color}]{escape(f['vulnerability'])}[/bold {color}]",
            f"[{color}]{f['severity'].upper()}[/{color}]",
            f"[dim]{escape(f['detail'])}[/dim]",
        )
    console.print(tbl)
