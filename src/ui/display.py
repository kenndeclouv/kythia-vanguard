"""
src/ui/display.py — Rich display functions for each scan module's results.
"""

from rich import box
from rich.align import Align
from rich.markup import escape
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from src.config import console, C
from src.models import ScanResult


# ─────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────

def _severity_style(sev: str) -> str:
    return {
        "high":     C["bad"],
        "medium":   C["warn"],
        "low":      C["ok"],
        "info":     C["info"],
        "critical": "bold red",
        "unknown":  "dim",
    }.get(sev.lower(), "white")


# ─────────────────────────────────────────────────────────────────
# Module display functions
# ─────────────────────────────────────────────────────────────────

def display_recon(result: ScanResult) -> None:
    console.print(Rule(f"[{C['accent']}]🌐  RECON RESULTS[/{C['accent']}]", style="magenta"))
    whois = result.whois

    t = Table(title="WHOIS / RDAP Info", box=box.ROUNDED, border_style="cyan",
              show_header=True, header_style=C["head"])
    t.add_column("Field", style=C["info"], width=20)
    t.add_column("Value", style="white")
    for k, v in whois.items():
        if k == "ip_geo":
            continue
        val = ", ".join(v) if isinstance(v, list) else str(v)
        t.add_row(k.replace("_", " ").title(), val)
    if "ip_geo" in whois:
        geo = whois["ip_geo"]
        t.add_row("IP Location",
                  f"{geo.get('city','?')}, {geo.get('regionName','?')}, {geo.get('country','?')}")
        t.add_row("ISP / Org",
                  f"{geo.get('isp','?')} — {geo.get('org','?')}")
    console.print(t)
    console.print()

    dns_t = Table(title="DNS Records", box=box.SIMPLE_HEAVY, border_style="blue",
                  header_style=C["head"])
    dns_t.add_column("Type",    style=C["accent"], width=8)
    dns_t.add_column("Records", style="white")
    for rtype, records in result.dns_records.items():
        if records:
            dns_t.add_row(rtype, "\n".join(records))
    console.print(dns_t)
    console.print()

    if result.subdomains:
        sub_t = Table(
            title=f"Subdomains ({len(result.subdomains)} found via crt.sh)",
            box=box.MINIMAL_DOUBLE_HEAD, border_style="cyan", header_style=C["head"],
        )
        sub_t.add_column("Subdomain", style=C["warn"])
        for sub in result.subdomains[:30]:
            sub_t.add_row(sub)
        if len(result.subdomains) > 30:
            sub_t.add_row(f"… and {len(result.subdomains)-30} more")
        console.print(sub_t)
    else:
        console.print("[dim]No subdomains found via crt.sh.[/dim]")
    console.print()


def display_waf(result: ScanResult) -> None:
    console.print(Rule(f"[{C['accent']}]🛡️   WAF / CDN / SERVER DETECTION[/{C['accent']}]",
                       style="magenta"))
    if result.waf_cdn:
        for provider, headers in result.waf_cdn.items():
            console.print(
                f"  [bold green]✓ DETECTED:[/bold green] [bold white]{provider}[/bold white]  "
                f"[dim](matched: {', '.join(headers)})[/dim]"
            )
    else:
        console.print("  [dim]No known WAF/CDN fingerprints detected.[/dim]")
    console.print()

    interesting = [
        "server", "x-powered-by", "via", "x-cache", "age",
        "cf-ray", "x-amz-cf-id", "x-served-by",
    ]
    hdr_t = Table(title="Notable HTTP Response Headers", box=box.ROUNDED,
                  border_style="blue", header_style=C["head"])
    hdr_t.add_column("Header", style=C["info"], width=30)
    hdr_t.add_column("Value",  style="white")
    for h in interesting:
        val = (result.headers.get(h)
               or result.headers.get(h.title())
               or result.headers.get(h.upper()))
        if val:
            hdr_t.add_row(h, escape(str(val)))
    console.print(hdr_t)
    console.print()


def display_headers(result: ScanResult) -> None:
    console.print(Rule(f"[{C['accent']}]📋  SECURITY HEADER ANALYSIS[/{C['accent']}]",
                       style="magenta"))
    t = Table(box=box.DOUBLE_EDGE, border_style="cyan", header_style=C["head"], show_lines=True)
    t.add_column("Header",       style=C["info"],   width=28)
    t.add_column("Short",        style=C["subtle"], width=14)
    t.add_column("Status",       width=12, justify="center")
    t.add_column("Value / Note", style="white")

    for header, info in result.security_headers.items():
        present   = info["present"]
        dangerous = info.get("dangerous", False)
        if dangerous:
            status  = "[bold red]⚠ PRESENT[/bold red]"
            val_str = f"[red]{escape(info['value'][:80])}[/red]"
        elif present:
            status  = f"[{C['ok']}]✓ Present[/{C['ok']}]"
            val_str = escape(info["value"][:80])
        else:
            status  = f"[{C['bad']}]✗ Missing[/{C['bad']}]"
            val_str = f"[dim]{info['desc']}[/dim]"
        t.add_row(header, info["short"], status, val_str)
    console.print(t)
    console.print()

    tls = result.tls_info
    console.print(Rule("[bold]TLS / SSL Certificate[/bold]", style="dim"))
    if "error" in tls:
        console.print(f"  [{C['bad']}]⚠  TLS Error: {escape(tls['error'])}[/{C['bad']}]")
    else:
        expiry_style = C["ok"] if tls.get("days_to_expiry", 0) > 30 else C["bad"]
        tls_t = Table(box=box.SIMPLE, border_style="dim", header_style=C["head"])
        tls_t.add_column("Field", style=C["info"], width=22)
        tls_t.add_column("Value", style="white")
        tls_t.add_row("Protocol",   tls.get("protocol", "?"))
        tls_t.add_row("Cipher",     tls.get("cipher",   "?"))
        tls_t.add_row("Issued By",  tls.get("issuer", {}).get("organizationName", "?"))
        tls_t.add_row("Valid From", tls.get("not_before", "?"))
        tls_t.add_row("Expires",    tls.get("not_after",  "?"))
        tls_t.add_row("Days Left",
                      f"[{expiry_style}]{tls.get('days_to_expiry', '?')} days[/{expiry_style}]")
        alt = ", ".join(tls.get("alt_names", [])[:6])
        tls_t.add_row("SAN Entries", escape(alt[:100]) if alt else "N/A")
        console.print(tls_t)
    console.print()


def display_fuzzing(result: ScanResult) -> None:
    console.print(Rule(f"[{C['accent']}]🔍  DIRECTORY / ENDPOINT FUZZING RESULTS[/{C['accent']}]",
                       style="magenta"))
    if not result.fuzzing:
        console.print("  [dim]No interesting paths discovered.[/dim]")
        console.print()
        return

    t = Table(box=box.ROUNDED, border_style="red", header_style=C["head"], show_lines=True)
    t.add_column("Severity",     width=10, justify="center")
    t.add_column("HTTP",         width=6,  justify="center")
    t.add_column("Path",         style=C["warn"])
    t.add_column("Size (bytes)", width=14, justify="right")
    t.add_column("Content-Type", style=C["dim"])
    for f in result.fuzzing:
        sev_style = _severity_style(f["severity"])
        t.add_row(
            f"[{sev_style}]{f['severity'].upper()}[/{sev_style}]",
            str(f["status"]),
            escape(f["path"]),
            str(f["size"]),
            escape(f["content_type"][:50]),
        )
    console.print(t)
    console.print()


def display_forms(result: ScanResult) -> None:
    console.print(Rule(f"[{C['accent']}]📝  FORM & CSRF AUDIT[/{C['accent']}]", style="magenta"))
    if not result.forms:
        console.print("  [dim]No HTML forms found on the target page.[/dim]")
        console.print()
        return

    for form in result.forms:
        csrf_tag   = (f"[{C['ok']}]✓ CSRF token detected[/{C['ok']}]" if form["has_csrf"]
                      else f"[{C['bad']}]✗ No CSRF token![/{C['bad']}]")
        risk_style = _severity_style(form["risk"])
        panel_content  = f"Action : [cyan]{escape(str(form['action']))}[/cyan]\n"
        panel_content += f"Method : [bold]{form['method']}[/bold]\n"
        panel_content += f"CSRF   : {csrf_tag}\n"
        panel_content += f"Risk   : [{risk_style}]{form['risk'].upper()}[/{risk_style}]\n\n"

        inp_t = Table(box=box.MINIMAL, border_style="dim",
                      show_header=True, header_style=C["subtle"])
        inp_t.add_column("Input name", style=C["info"])
        inp_t.add_column("Type",       style="white")
        for inp in form["inputs"]:
            inp_t.add_row(escape(inp["name"] or "(no name)"), inp["type"])

        console.print(Panel(Text.from_markup(panel_content),
                            title=f"[bold]Form #{form['form_num']}[/bold]",
                            border_style=risk_style))
        console.print(inp_t)
        console.print()


def display_ports(result: ScanResult) -> None:
    console.print(Rule(f"[{C['accent']}]🔌  PORT SCAN RESULTS[/{C['accent']}]", style="magenta"))
    if not result.open_ports:
        console.print("  [dim]No open ports found among the top 25 common ports.[/dim]")
        console.print()
        return

    dangerous_ports = {21, 23, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 27017}
    t = Table(box=box.ROUNDED, border_style="yellow", header_style=C["head"])
    t.add_column("Port",    width=8,  justify="right", style=C["accent"])
    t.add_column("Service", width=16, style="white")
    t.add_column("State",   width=10, justify="center")
    t.add_column("Banner",  style=C["dim"], width=40)
    t.add_column("Risk",    width=30)

    for p in result.open_ports:
        is_risky  = p["port"] in dangerous_ports
        risk_str  = (f"[{C['bad']}]⚠ Potentially dangerous[/{C['bad']}]"
                     if is_risky else f"[{C['ok']}]Expected[/{C['ok']}]")
        banner_str = escape(p.get("banner", "")[:40]) or "[dim]—[/dim]"
        t.add_row(str(p["port"]), p["service"],
                  f"[{C['ok']}]OPEN[/{C['ok']}]", banner_str, risk_str)
    console.print(t)
    console.print()


def display_osint(result: ScanResult) -> None:
    console.print(Rule(f"[{C['accent']}]🧠  OSINT INTELLIGENCE LAYER[/{C['accent']}]",
                       style="magenta"))

    # ── Breach data
    console.print(Rule("[bold]Have I Been Pwned — Breach Intel[/bold]", style="dim"))
    breach = result.osint_breach
    if "error" in breach:
        console.print(f"  [{C['bad']}]Error: {breach['error']}[/{C['bad']}]")
    else:
        if breach.get("api_note"):
            console.print(f"  [{C['dim']}]ℹ  {breach['api_note']}[/{C['dim']}]")
        if breach.get("total_known_breaches"):
            console.print(f"  Total known public breaches in HIBP database: "
                          f"[cyan]{breach['total_known_breaches']}[/cyan]")
        checked = breach.get("checked_emails", [])
        if checked:
            brt = Table(box=box.SIMPLE, border_style="dim", header_style=C["head"])
            brt.add_column("Email",    style=C["info"])
            brt.add_column("Pwned?",   width=10, justify="center")
            brt.add_column("Breaches Found")
            for e in checked:
                pwned_str = (f"[{C['bad']}]YES[/{C['bad']}]" if e["pwned"]
                             else f"[{C['ok']}]No[/{C['ok']}]")
                brt.add_row(e["email"], pwned_str,
                            ", ".join(e["breaches"])[:80] if e["breaches"] else "—")
            console.print(brt)
        else:
            console.print("  [dim]Set HIBP_API_KEY env var for per-email breach lookup.[/dim]")
    console.print()

    # ── ASN / BGP
    console.print(Rule("[bold]ASN / BGP — IP Range Ownership[/bold]", style="dim"))
    asn = result.osint_asn
    if asn and "error" not in asn:
        asn_t = Table(box=box.SIMPLE, border_style="dim", header_style=C["head"])
        asn_t.add_column("Field", style=C["info"], width=18)
        asn_t.add_column("Value", style="white")
        asn_t.add_row("AS Number",   asn.get("as_number", "—"))
        asn_t.add_row("AS Name",     asn.get("as_name",   "—"))
        asn_t.add_row("Org",         asn.get("org",        "—"))
        asn_t.add_row("IPv4 Ranges",
                      f"{asn.get('total_ipv4_ranges','?')} total — "
                      f"showing {len(asn.get('ipv4_ranges', []))}")
        console.print(asn_t)
        if asn.get("ipv4_ranges"):
            rng_t = Table(box=box.MINIMAL, border_style="dim", header_style=C["subtle"])
            rng_t.add_column("IPv4 Prefix", style=C["warn"])
            for prefix in asn.get("ipv4_ranges", [])[:15]:
                rng_t.add_row(prefix)
            console.print(rng_t)
    else:
        console.print(f"  [dim]{asn.get('error','No ASN data available.')}[/dim]")
    console.print()

    # ── Wayback Machine
    console.print(Rule("[bold]Wayback Machine — Historical Endpoints[/bold]", style="dim"))
    wb = result.osint_wayback
    if wb:
        wb_t = Table(box=box.MINIMAL, border_style="dim", header_style=C["subtle"])
        wb_t.add_column(f"Interesting historical URLs ({len(wb)} found)", style=C["warn"])
        for url in wb[:25]:
            wb_t.add_row(escape(url))
        if len(wb) > 25:
            wb_t.add_row(f"… and {len(wb)-25} more — see JSON report")
        console.print(wb_t)
    else:
        console.print("  [dim]No interesting historical endpoints found.[/dim]")
    console.print()

    # ── GitHub dork hints
    console.print(Rule("[bold]GitHub OSINT — Recommended Search Queries[/bold]", style="dim"))
    console.print("  [dim]Run these searches manually on github.com/search:[/dim]")
    for dork in result.osint_github:
        console.print(f"  [{C['warn']}]❯[/{C['warn']}]  [cyan]{escape(dork)}[/cyan]")
    console.print()


def display_cve(result: ScanResult) -> None:
    console.print(Rule(f"[{C['accent']}]🔬  CVE INTELLIGENCE LAYER[/{C['accent']}]",
                       style="magenta"))

    # ── CMS Detection
    console.print(Rule("[bold]CMS / Framework Fingerprinting[/bold]", style="dim"))
    if result.cms_detected:
        cms_t = Table(box=box.ROUNDED, border_style="cyan", header_style=C["head"])
        cms_t.add_column("CMS / Platform",   style=C["info"], width=20)
        cms_t.add_column("Version Detected", style="white",   width=18)
        cms_t.add_column("Confidence",       style=C["warn"], width=14)
        for cms, info in result.cms_detected.items():
            cms_t.add_row(cms,
                          info.get("version",    "unknown"),
                          f"{info.get('confidence','?')}%")
        console.print(cms_t)
    else:
        console.print("  [dim]No CMS fingerprints detected.[/dim]")
    console.print()

    # ── CVE Findings
    console.print(Rule("[bold]CVE Matches (via NVD/NIST API)[/bold]", style="dim"))
    if not result.cve_findings:
        console.print("  [dim]No CVEs matched. (No banner data or no matching NVD entries.)[/dim]")
        console.print("  [dim]Tip: Run port scan first so banners can be grabbed.[/dim]")
        console.print()
        return

    cve_t = Table(box=box.DOUBLE_EDGE, border_style="red",
                  header_style=C["head"], show_lines=True)
    cve_t.add_column("CVE ID",      style=C["bad"],  width=16)
    cve_t.add_column("Product",     style=C["info"], width=14)
    cve_t.add_column("Version",     style="white",   width=10)
    cve_t.add_column("CVSS v3",     width=10, justify="center")
    cve_t.add_column("Severity",    width=12, justify="center")
    cve_t.add_column("Port",        width=6,  justify="right")
    cve_t.add_column("Description", style=C["dim"])

    for cve in result.cve_findings:
        sev    = cve.get("severity", "UNKNOWN")
        sev_st = _severity_style(sev)
        cvss   = str(cve.get("cvss_v3", "?")) if cve.get("cvss_v3") else "?"
        cve_t.add_row(
            escape(cve["cve_id"]),
            escape(cve.get("product", "?")),
            escape(cve.get("version", "?")),
            cvss,
            f"[{sev_st}]{sev}[/{sev_st}]",
            str(cve.get("port", "?")),
            escape(cve["description"][:100]),
        )
    console.print(cve_t)
    console.print()


def display_spider(result: ScanResult) -> None:
    console.print(Rule(f"[{C['accent']}]🕸️   DEEP CRAWLER RESULTS[/{C['accent']}]",
                       style="magenta"))

    # ── Sitemap
    console.print(Rule("[bold]Crawled Internal URLs[/bold]", style="dim"))
    console.print(f"  Total unique internal pages discovered: [cyan]{len(result.sitemap)}[/cyan]")
    if result.sitemap:
        sm_t = Table(box=box.MINIMAL, border_style="dim", header_style=C["subtle"])
        sm_t.add_column("URL", style=C["warn"])
        for url in result.sitemap[:30]:
            sm_t.add_row(escape(url))
        if len(result.sitemap) > 30:
            sm_t.add_row(f"[dim]… and {len(result.sitemap)-30} more in JSON report[/dim]")
        console.print(sm_t)
    console.print()

    # ── JS API Endpoints
    console.print(Rule("[bold]JS-Discovered API Endpoints[/bold]", style="dim"))
    if result.js_endpoints:
        js_t = Table(box=box.MINIMAL, border_style="dim", header_style=C["subtle"])
        js_t.add_column(
            f"Endpoints found in JS files ({len(result.js_endpoints)} unique)",
            style=C["accent"],
        )
        for ep in result.js_endpoints[:40]:
            js_t.add_row(escape(ep))
        if len(result.js_endpoints) > 40:
            js_t.add_row(f"[dim]… and {len(result.js_endpoints)-40} more in JSON report[/dim]")
        console.print(js_t)
    else:
        console.print("  [dim]No hidden API endpoints discovered in JS files.[/dim]")
    console.print()

    # ── Parameter Mining
    console.print(Rule("[bold]Discovered Query Parameters[/bold]", style="dim"))
    if result.parameters:
        pm_t = Table(box=box.MINIMAL, border_style="dim", header_style=C["subtle"])
        pm_t.add_column("URL",        style=C["warn"],   width=60)
        pm_t.add_column("Parameters", style=C["accent"])
        for url, parms in list(result.parameters.items())[:20]:
            pm_t.add_row(escape(url[:60]), ", ".join(parms))
        console.print(pm_t)
    else:
        console.print("  [dim]No query parameters found.[/dim]")
    console.print()

def display_nuclei(result: ScanResult) -> None:
    console.print(Rule(f"[{C['accent']}]☢️  NUCLEI VULNERABILITY SCAN[/{C['accent']}]", style="magenta"))

    if not result.nuclei_findings:
        console.print("  [dim]Aman sentosa! Tidak ada kerentanan atau Nuclei gagal jalan.[/dim]\n")
        return

    # Panel Summary Kesimpulan
    counts = result.nuclei_summary
    summary_text = (
        f"[bold red]Critical:[/bold red] {counts.get('critical', 0)} | "
        f"[bold light_coral]High:[/bold light_coral] {counts.get('high', 0)} | "
        f"[bold yellow]Medium:[/bold yellow] {counts.get('medium', 0)} | "
        f"[bold green]Low:[/bold green] {counts.get('low', 0)} | "
        f"[bold blue]Info:[/bold blue] {counts.get('info', 0)}"
    )
    console.print(Panel(Align.center(summary_text), title="[bold white]Nuclei Scan Summary[/bold white]", border_style="cyan"))
    console.print()

    # Tabel Detail
    t = Table(box=box.ROUNDED, border_style="red", header_style=C["head"])
    t.add_column("Severity", justify="center", width=12)
    t.add_column("Template ID", style="cyan", width=25)
    t.add_column("Vulnerability Name", style="white")
    t.add_column("Matched URL", style="dim")

    # Urutkan dari Critical ke Info
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(result.nuclei_findings, key=lambda x: sev_rank.get(x['severity'], 5))

    for f in sorted_findings:
        sev = f['severity']
        sev_style = "bold red" if sev in ['critical', 'high'] else ("bold yellow" if sev == 'medium' else "bold green")
        t.add_row(
            f"[{sev_style}]{sev.upper()}[/{sev_style}]",
            f['id'],
            escape(f['name']),
            escape(f['matched_at'])
        )

    console.print(t)
    console.print()

def display_score(result: ScanResult) -> None:
    score = result.score
    if score >= 80:
        colour, grade, emoji = "green",       "A", "🟢"
    elif score >= 60:
        colour, grade, emoji = "yellow",      "B", "🟡"
    elif score >= 40:
        colour, grade, emoji = "dark_orange", "C", "🟠"
    else:
        colour, grade, emoji = "red",         "D", "🔴"

    bar_filled = int(score / 5)
    bar_empty  = 20 - bar_filled
    bar        = f"[{colour}]{'█' * bar_filled}[/{colour}][dim]{'░' * bar_empty}[/dim]"

    console.print()
    console.print(Panel(
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
    ))
    console.print()
