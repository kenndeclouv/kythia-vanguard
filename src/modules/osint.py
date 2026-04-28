"""
src/modules/osint.py — Module 7: OSINT intelligence layer.

Covers:
  1. Have I Been Pwned — domain/email breach check
  2. ASN / BGP         — IP range ownership
  3. Wayback Machine   — historically exposed endpoints
  4. GitHub dorks      — passive search query generation
"""

import re
from src.export import md_table
import urllib.parse

from rich.markup import escape
from rich.table import Table
from rich.rule import Rule
from rich import box

from src.config import console, C, SESSION, TIMEOUT, HIBP_API_KEY
from src.models import ScanResult
from src.scoring import score_and_report


def _extract_domain_emails(hostname: str) -> list[str]:
    """Generate plausible admin-style email addresses for HIBP checks."""
    return [
        f"admin@{hostname}",
        f"info@{hostname}",
        f"security@{hostname}",
        f"webmaster@{hostname}",
        f"contact@{hostname}",
    ]


def run_osint(
    target_url: str, hostname: str, result: ScanResult, progress, task
) -> None:

    # ── 1. Have I Been Pwned
    progress.update(
        task, description="[cyan]OSINT:[/cyan] Checking breach database (HIBP)…"
    )
    breach_info: dict = {"domain_breach": [], "checked_emails": [], "api_note": ""}

    if getattr(result, "is_ip", False):
        breach_info["api_note"] = "Target is an IP. HIBP domain breach lookup skipped."
    else:
        try:
            headers_hibp = {"User-Agent": "kythia-vanguard/1.0.0-rc.1"}
            if HIBP_API_KEY:
                headers_hibp["hibp-api-key"] = HIBP_API_KEY

            r = SESSION.get(
                "https://haveibeenpwned.com/api/v3/breaches",
                headers=headers_hibp,
                timeout=TIMEOUT,
            )
            if r.ok:
                all_breaches = r.json()
                breach_info["total_known_breaches"] = len(all_breaches)
                breach_info["api_note"] = (
                    "Full per-domain email lookup requires HIBP API key (set HIBP_API_KEY env var). "
                    "Showing global breach stats only."
                    if not HIBP_API_KEY
                    else "API key present — per-email lookup enabled."
                )

                if HIBP_API_KEY:
                    checked = []
                    for email in _extract_domain_emails(hostname):
                        try:
                            er = SESSION.get(
                                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                                headers=headers_hibp,
                                timeout=TIMEOUT,
                            )
                            if er.status_code == 200:
                                checked.append(
                                    {
                                        "email": email,
                                        "breaches": [b["Name"] for b in er.json()],
                                        "pwned": True,
                                    }
                                )
                            elif er.status_code == 404:
                                checked.append(
                                    {"email": email, "breaches": [], "pwned": False}
                                )
                        except Exception:
                            pass
                    breach_info["checked_emails"] = checked
        except Exception as e:
            breach_info["error"] = str(e)

    result.osint_breach = breach_info
    progress.advance(task, 15)

    # ── 2. ASN / BGP
    progress.update(
        task, description="[cyan]OSINT:[/cyan] ASN/BGP lookup (ip-api + bgpview)…"
    )
    asn_info: dict = {}
    try:
        a_records = result.dns_records.get("A", [])
        ip = a_records[0] if a_records else ""
        if ip:
            r = SESSION.get(
                f"http://ip-api.com/json/{ip}?fields=as,asname,org,isp",
                timeout=TIMEOUT,
            )
            if r.ok:
                data = r.json()
                asn_info["as_number"] = data.get("as", "")
                asn_info["as_name"] = data.get("asname", "")
                asn_info["org"] = data.get("org", "")

                as_num = re.search(r"AS(\d+)", asn_info["as_number"])
                if as_num:
                    asn_id = as_num.group(1)
                    bgp = SESSION.get(
                        f"https://api.bgpview.io/asn/{asn_id}/prefixes",
                        timeout=TIMEOUT,
                    )
                    if bgp.ok:
                        prefixes = bgp.json().get("data", {})
                        ipv4 = [p["prefix"] for p in prefixes.get("ipv4_prefixes", [])]
                        ipv6 = [p["prefix"] for p in prefixes.get("ipv6_prefixes", [])]
                        asn_info["ipv4_ranges"] = ipv4[:20]
                        asn_info["ipv6_ranges"] = ipv6[:10]
                        asn_info["total_ipv4_ranges"] = len(ipv4)
    except Exception as e:
        asn_info["error"] = str(e)

    result.osint_asn = asn_info
    progress.advance(task, 15)

    # ── 3. Wayback Machine
    progress.update(
        task, description="[cyan]OSINT:[/cyan] Wayback Machine historical scan…"
    )
    wayback_urls: list[str] = []
    try:
        cdx_url = (
            f"http://web.archive.org/cdx/search/cdx"
            f"?url={hostname}/*&output=json&fl=original&collapse=urlkey"
            f"&filter=statuscode:200&limit=200"
        )
        r = SESSION.get(cdx_url, timeout=15)
        if r.ok:
            rows = r.json()
            all_urls = [row[0] for row in rows[1:] if row]

            interesting_patterns = [
                r"/api/",
                r"/admin",
                r"/config",
                r"/backup",
                r"\.env",
                r"/graphql",
                r"/swagger",
                r"/actuator",
                r"\.git",
                r"/login",
                r"/dashboard",
                r"/panel",
                r"/debug",
                r"/upload",
                r"/files",
                r"/docs",
                r"/internal",
            ]
            for url in all_urls:
                path = urllib.parse.urlparse(url).path.lower()
                for pat in interesting_patterns:
                    if re.search(pat, path):
                        wayback_urls.append(url)
                        break

            wayback_urls = list(set(wayback_urls))[:50]
    except Exception as e:
        wayback_urls = [f"Error: {e}"]

    result.osint_wayback = wayback_urls
    progress.advance(task, 10)

    # ── 4. GitHub dork hints (passive — generate queries only)
    progress.update(
        task, description="[cyan]OSINT:[/cyan] Generating GitHub OSINT dorks…"
    )
    result.osint_github = [
        f'"{hostname}" password',
        f'"{hostname}" api_key OR secret OR token',
        f'"{hostname}" .env OR config',
        f"org:{hostname.split('.')[0]} filename:.env",
        f'"{hostname}" db_password OR database_url',
        f'"{hostname}" aws_access_key_id',
        f'site:github.com "{hostname}" secret',
    ]
    progress.advance(task, 10)

    # ── 5. Subdomain Takeover Scanner
    progress.update(
        task, description="[cyan]OSINT:[/cyan] Scanning for Subdomain Takeovers…"
    )
    TAKEOVER_SIGS = {
        "GitHub Pages": "There isn't a GitHub Pages site here.",
        "AWS S3": "NoSuchBucket",
        "Heroku": "No such app",
        "Webflow": "The page you are looking for doesn't exist or has been moved.",
        "Shopify": "Sorry, this shop is currently unavailable.",
    }

    if not getattr(result, "is_ip", False):
        # Ambil max 30 subdo biar ga kelamaan (fokus ke yang dipanen OTX/crt.sh)
        for sub in result.subdomains[:30]:
            try:
                tr = SESSION.get(f"http://{sub}", timeout=3)
                for provider, sig in TAKEOVER_SIGS.items():
                    if sig in tr.text:
                        from rich.panel import Panel

                        progress.console.print(
                            Panel(
                                f"[bold red]SUBDOMAIN TAKEOVER VULNERABILITY![/bold red]\n"
                                f"Target   : [cyan]{sub}[/cyan]\n"
                                f"Provider : [yellow]{provider}[/yellow]\n"
                                f"Impact   : You can hijack this subdomain and host your own content!",
                                title="SUBDOMAIN TAKEOVER SCANNER",
                                border_style="red",
                            )
                        )
            except Exception:
                pass

    progress.advance(task, 5)
    score_and_report(result, "osint")


def score_osint(result):
    score = 100
    if result.osint_breach:
        if any(e.get("pwned") for e in result.osint_breach.get("checked_emails", [])):
            score -= 20
    if len(result.osint_wayback) > 50:
        score -= 10
    return max(0, score)


def display_osint(result: ScanResult) -> None:
    console.print(
        Rule(
            f"[{C['accent']}]🧠  OSINT INTELLIGENCE LAYER[/{C['accent']}]",
            style="magenta",
        )
    )

    # ── Breach data
    console.print(Rule("[bold]Have I Been Pwned — Breach Intel[/bold]", style="dim"))
    breach = result.osint_breach
    if "error" in breach:
        console.print(f"  [{C['bad']}]Error: {breach['error']}[/{C['bad']}]")
    else:
        if breach.get("api_note"):
            console.print(f"  [{C['dim']}]ℹ  {breach['api_note']}[/{C['dim']}]")
        if breach.get("total_known_breaches"):
            console.print(
                f"  Total known public breaches in HIBP database: "
                f"[cyan]{breach['total_known_breaches']}[/cyan]"
            )
        checked = breach.get("checked_emails", [])
        if checked:
            brt = Table(box=box.SIMPLE, border_style="dim", header_style=C["head"])
            brt.add_column("Email", style=C["info"])
            brt.add_column("Pwned?", width=10, justify="center")
            brt.add_column("Breaches Found")
            for e in checked:
                pwned_str = (
                    f"[{C['bad']}]YES[/{C['bad']}]"
                    if e["pwned"]
                    else f"[{C['ok']}]No[/{C['ok']}]"
                )
                brt.add_row(
                    e["email"],
                    pwned_str,
                    ", ".join(e["breaches"])[:80] if e["breaches"] else "—",
                )
            console.print(brt)
        else:
            console.print(
                "  [dim]Set HIBP_API_KEY env var for per-email breach lookup.[/dim]"
            )
    console.print()

    # ── ASN / BGP
    console.print(Rule("[bold]ASN / BGP — IP Range Ownership[/bold]", style="dim"))
    asn = result.osint_asn
    if asn and "error" not in asn:
        asn_t = Table(box=box.SIMPLE, border_style="dim", header_style=C["head"])
        asn_t.add_column("Field", style=C["info"], width=18)
        asn_t.add_column("Value", style="white")
        asn_t.add_row("AS Number", asn.get("as_number", "—"))
        asn_t.add_row("AS Name", asn.get("as_name", "—"))
        asn_t.add_row("Org", asn.get("org", "—"))
        asn_t.add_row(
            "IPv4 Ranges",
            f"{asn.get('total_ipv4_ranges', '?')} total — "
            f"showing {len(asn.get('ipv4_ranges', []))}",
        )
        console.print(asn_t)
        if asn.get("ipv4_ranges"):
            rng_t = Table(box=box.MINIMAL, border_style="dim", header_style=C["subtle"])
            rng_t.add_column("IPv4 Prefix", style=C["warn"])
            for prefix in asn.get("ipv4_ranges", [])[:15]:
                rng_t.add_row(prefix)
            console.print(rng_t)
    else:
        console.print(f"  [dim]{asn.get('error', 'No ASN data available.')}[/dim]")
    console.print()

    # ── Wayback Machine
    console.print(
        Rule("[bold]Wayback Machine — Historical Endpoints[/bold]", style="dim")
    )
    wb = result.osint_wayback
    if wb:
        wb_t = Table(box=box.MINIMAL, border_style="dim", header_style=C["subtle"])
        wb_t.add_column(
            f"Interesting historical URLs ({len(wb)} found)", style=C["warn"]
        )
        for url in wb[:25]:
            wb_t.add_row(escape(url))
        if len(wb) > 25:
            wb_t.add_row(f"… and {len(wb) - 25} more — see JSON report")
        console.print(wb_t)
    else:
        console.print("  [dim]No interesting historical endpoints found.[/dim]")
    console.print()

    # ── GitHub dork hints
    console.print(
        Rule("[bold]GitHub OSINT — Recommended Search Queries[/bold]", style="dim")
    )
    console.print("  [dim]Run these searches manually on github.com/search:[/dim]")
    for dork in result.osint_github:
        console.print(f"  [{C['warn']}]❯[/{C['warn']}]  [cyan]{escape(dork)}[/cyan]")
    console.print()


def export_osint(result: ScanResult, W: callable) -> None:
    W("## 🕵️ OSINT Intelligence\n\n")
    if result.osint_asn:
        W("### ASN / BGP\n\n")
        W(md_table(["Field", "Value"], [[k, v] for k, v in result.osint_asn.items()]))
    if result.osint_wayback:
        W(f"\n### Wayback Machine ({len(result.osint_wayback)} URLs)\n\n")
        for url in result.osint_wayback[:50]:
            W(f"- {url}\n")
    if result.osint_github:
        W("\n### GitHub OSINT Dorks\n\n")
        for dork in result.osint_github:
            W(f"- `{dork}`\n")
    W("\n")
