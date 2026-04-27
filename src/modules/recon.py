"""
src/modules/recon.py — Module 1: WHOIS / RDAP · Subdomains · DNS · IP geolocation.
"""

import urllib.parse

from src.config import SESSION, TIMEOUT
from src.models import ScanResult


def run_recon(target_url: str, hostname: str, result: ScanResult, progress, task) -> None:
    # ── WHOIS / RDAP
    progress.update(task, description="[cyan]Recon:[/cyan] WHOIS lookup…")
    whois_data: dict = {}
    try:
        r = SESSION.get(f"https://rdap.org/domain/{hostname}", timeout=TIMEOUT)
        if r.ok:
            raw = r.json()
            whois_data["registrar"] = next(
                (e.get("ldhName", "") for e in raw.get("entities", [])
                 if "registrar" in e.get("roles", [])), "N/A")
            whois_data["registered"] = raw.get("events", [{}])[0].get("eventDate", "N/A")[:10]
            whois_data["expires"] = next(
                (e.get("eventDate", "N/A")[:10] for e in raw.get("events", [])
                 if e.get("eventAction") == "expiration"), "N/A")
            whois_data["name_servers"] = [ns.get("ldhName", "")
                                          for ns in raw.get("nameservers", [])]
            whois_data["status"] = raw.get("status", [])
    except Exception:
        whois_data["error"] = "RDAP lookup failed"
    result.whois = whois_data
    progress.advance(task, 10)

    # ── Subdomain enumeration (crt.sh)
    progress.update(task, description="[cyan]Recon:[/cyan] Subdomain enumeration (crt.sh)…")
    subdomains: set = set()
    try:
        r = SESSION.get(f"https://crt.sh/?q=%25.{hostname}&output=json", timeout=15)
        if r.ok:
            for entry in r.json():
                names = entry.get("name_value", "").split("\n")
                for name in names:
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(hostname) and name != hostname:
                        subdomains.add(name)
    except Exception:
        pass
    result.subdomains = sorted(subdomains)[:50]
    progress.advance(task, 15)

    # ── DNS records
    progress.update(task, description="[cyan]Recon:[/cyan] DNS record enumeration…")
    dns_records: dict = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "SOA"):
        try:
            r = SESSION.get(
                "https://dns.google/resolve",
                params={"name": hostname, "type": rtype},
                timeout=TIMEOUT,
            )
            if r.ok:
                answers = r.json().get("Answer", [])
                dns_records[rtype] = [a.get("data", "") for a in answers]
        except Exception:
            dns_records[rtype] = []
    result.dns_records = dns_records
    progress.advance(task, 15)

    # ── IP geolocation
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
