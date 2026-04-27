"""
src/modules/recon.py
"""

from rich import box
from src.export import md_table
from rich.rule import Rule
from rich.table import Table

from src.config import console, C, SESSION, TIMEOUT, rate_limiter
from src.models import ScanResult
from src.scoring import score_and_report


def run_recon(
    target_url: str, hostname: str, result: ScanResult, progress, task
) -> None:
    # ── 1. WHOIS / RDAP
    progress.update(task, description="[cyan]Recon:[/cyan] RDAP / WHOIS lookup…")
    whois_data: dict = {}
    try:
        r = SESSION.get(f"https://rdap.org/domain/{hostname}", timeout=TIMEOUT)
        if r.ok:
            raw = r.json()
            whois_data["registrar"] = next(
                (
                    e.get("ldhName", "")
                    for e in raw.get("entities", [])
                    if "registrar" in e.get("roles", [])
                ),
                "N/A",
            )
            whois_data["registered"] = raw.get("events", [{}])[0].get(
                "eventDate", "N/A"
            )[:10]
            whois_data["expires"] = next(
                (
                    e.get("eventDate", "N/A")[:10]
                    for e in raw.get("events", [])
                    if e.get("eventAction") == "expiration"
                ),
                "N/A",
            )
            whois_data["name_servers"] = [
                ns.get("ldhName", "") for ns in raw.get("nameservers", [])
            ]
            whois_data["status"] = raw.get("status", [])
    except Exception:
        whois_data["error"] = "RDAP lookup failed or timeout"
    result.whois = whois_data
    progress.advance(task, 10)

    # ── 2. MULTI-SOURCE SUBDOMAIN ENUMERATION (crt.sh + AlienVault OTX)
    progress.update(
        task, description="[cyan]Recon:[/cyan] Multi-source subdomain hunting…"
    )
    subdomains: set = set()

    # Source A: crt.sh
    try:
        r_crt = SESSION.get(f"https://crt.sh/?q=%25.{hostname}&output=json", timeout=15)
        if r_crt.ok:
            for entry in r_crt.json():
                names = entry.get("name_value", "").split("\n")
                for name in names:
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(hostname) and name != hostname:
                        subdomains.add(name)
    except Exception:
        pass  # Lanjut ke AlienVault kalau crt.sh down

    # Source B: AlienVault OTX (Passive DNS)
    try:
        r_otx = SESSION.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{hostname}/passive_dns",
            timeout=15,
        )
        if r_otx.ok:
            for entry in r_otx.json().get("passive_dns", []):
                name = entry.get("hostname", "").strip().lower().lstrip("*.")
                if name.endswith(hostname) and name != hostname:
                    subdomains.add(name)
    except Exception:
        pass

    # Ambil top 100 subdomain biar nggak kepanjangan di UI
    result.subdomains = sorted(subdomains)[:100]
    progress.advance(task, 15)

    # ── 3. ADVANCED DNS & EMAIL SECURITY AUDIT
    progress.update(
        task, description="[cyan]Recon:[/cyan] DNS & Security Records (SPF/DMARC)…"
    )
    dns_records: dict = {}

    # Cek Standard Records
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "SOA"):
        try:
            rate_limiter.wait()
            r = SESSION.get(
                "https://dns.google/resolve",
                params={"name": hostname, "type": rtype},
                timeout=TIMEOUT,
            )
            if r.ok:
                answers = r.json().get("Answer", [])
                dns_records[rtype] = [a.get("data", "").strip('"') for a in answers]
        except Exception:
            dns_records[rtype] = []

    # Cek DMARC Record (Sangat penting buat pentest phishing)
    try:
        r_dmarc = SESSION.get(
            "https://dns.google/resolve",
            params={"name": f"_dmarc.{hostname}", "type": "TXT"},
            timeout=TIMEOUT,
        )
        if r_dmarc.ok and r_dmarc.json().get("Answer"):
            dns_records["DMARC"] = [
                a.get("data", "").strip('"') for a in r_dmarc.json().get("Answer")
            ]
    except Exception:
        pass

    result.dns_records = dns_records

    # ── 3.5. FINGERPRINTING DARI DNS
    # Identifikasi provider email & cek kerentanan spoofing
    if dns_records.get("MX"):
        mx_data = " ".join(dns_records["MX"]).lower()
        if "google" in mx_data:
            whois_data["email_provider"] = "Google Workspace"
        elif "outlook" in mx_data:
            whois_data["email_provider"] = "Microsoft 365"
        elif "zoho" in mx_data:
            whois_data["email_provider"] = "Zoho Mail"
        elif "titan" in mx_data:
            whois_data["email_provider"] = "Titan Mail (Hostinger)"
        else:
            whois_data["email_provider"] = "Custom / Other"

    # Cek kerentanan Email Spoofing (SPF)
    spf_found = any("v=spf1" in txt for txt in dns_records.get("TXT", []))
    whois_data["spoofing_protection"] = (
        "✓ Secured (SPF Found)" if spf_found else "⚠ Vulnerable (No SPF Record)"
    )

    progress.advance(task, 15)

    # ── 4. IP GEOLOCATION
    progress.update(task, description="[cyan]Recon:[/cyan] IP geolocation…")
    a_records = dns_records.get("A", [])
    if a_records:
        try:
            r = SESSION.get(
                f"http://ip-api.com/json/{a_records[0]}"
                f"?fields=country,regionName,city,isp,org,as",
                timeout=TIMEOUT,
            )
            if r.ok:
                result.whois["ip_geo"] = r.json()
        except Exception:
            pass
    progress.advance(task, 10)
    score_and_report(result, "recon")


def score_recon(result):
    score = 100
    whois = result.whois or {}
    if not whois.get("spf_record"):
        score -= 15
    if len(result.subdomains) > 20:
        score -= 10
    return max(0, score)


def display_recon(result: ScanResult) -> None:
    console.print(
        Rule(f"[{C['accent']}]🌐  RECON RESULTS[/{C['accent']}]", style="magenta")
    )
    whois = result.whois

    t = Table(
        title="WHOIS / RDAP Info",
        box=box.ROUNDED,
        border_style="cyan",
        show_header=True,
        header_style=C["head"],
    )
    t.add_column("Field", style=C["info"], width=20)
    t.add_column("Value", style="white")
    for k, v in whois.items():
        if k == "ip_geo":
            continue
        val = ", ".join(v) if isinstance(v, list) else str(v)
        t.add_row(k.replace("_", " ").title(), val)
    if "ip_geo" in whois:
        geo = whois["ip_geo"]
        t.add_row(
            "IP Location",
            f"{geo.get('city', '?')}, {geo.get('regionName', '?')}, {geo.get('country', '?')}",
        )
        t.add_row("ISP / Org", f"{geo.get('isp', '?')} — {geo.get('org', '?')}")
    console.print(t)
    console.print()

    dns_t = Table(
        title="DNS Records",
        box=box.SIMPLE_HEAVY,
        border_style="blue",
        header_style=C["head"],
    )
    dns_t.add_column("Type", style=C["accent"], width=8)
    dns_t.add_column("Records", style="white")
    for rtype, records in result.dns_records.items():
        if records:
            dns_t.add_row(rtype, "\n".join(records))
    console.print(dns_t)
    console.print()

    if result.subdomains:
        sub_t = Table(
            title=f"Subdomains ({len(result.subdomains)} found via crt.sh)",
            box=box.MINIMAL_DOUBLE_HEAD,
            border_style="cyan",
            header_style=C["head"],
        )
        sub_t.add_column("Subdomain", style=C["warn"])
        for sub in result.subdomains[:30]:
            sub_t.add_row(sub)
        if len(result.subdomains) > 30:
            sub_t.add_row(f"… and {len(result.subdomains) - 30} more")
        console.print(sub_t)
    else:
        console.print("[dim]No subdomains found via crt.sh.[/dim]")
    console.print()


def export_recon(result: ScanResult, W: callable) -> None:
    W("## 📋 WHOIS\n\n")
    if result.whois:
        W(md_table(["Field", "Value"], [[k, v] for k, v in result.whois.items()]))
    W("\n")
    W(f"## 🌐 Subdomains ({len(result.subdomains)} found)\n\n")
    for s in result.subdomains:
        W(f"- `{s}`\n")
    W("\n")
