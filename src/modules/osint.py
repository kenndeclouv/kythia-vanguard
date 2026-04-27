"""
src/modules/osint.py — Module 7: OSINT intelligence layer.

Covers:
  1. Have I Been Pwned — domain/email breach check
  2. ASN / BGP         — IP range ownership
  3. Wayback Machine   — historically exposed endpoints
  4. GitHub dorks      — passive search query generation
"""

import re
import urllib.parse

from src.config import SESSION, TIMEOUT, HIBP_API_KEY
from src.models import ScanResult


def _extract_domain_emails(hostname: str) -> list[str]:
    """Generate plausible admin-style email addresses for HIBP checks."""
    return [
        f"admin@{hostname}",
        f"info@{hostname}",
        f"security@{hostname}",
        f"webmaster@{hostname}",
        f"contact@{hostname}",
    ]


def run_osint(target_url: str, hostname: str, result: ScanResult, progress, task) -> None:

    # ── 1. Have I Been Pwned
    progress.update(task, description="[cyan]OSINT:[/cyan] Checking breach database (HIBP)…")
    breach_info: dict = {"domain_breach": [], "checked_emails": [], "api_note": ""}

    try:
        headers_hibp = {"User-Agent": "KENN-RECON-Pro/1.0.0-rc.1"}
        if HIBP_API_KEY:
            headers_hibp["hibp-api-key"] = HIBP_API_KEY

        r = SESSION.get("https://haveibeenpwned.com/api/v3/breaches",
                        headers=headers_hibp, timeout=TIMEOUT)
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
                            headers=headers_hibp, timeout=TIMEOUT,
                        )
                        if er.status_code == 200:
                            checked.append({
                                "email":    email,
                                "breaches": [b["Name"] for b in er.json()],
                                "pwned":    True,
                            })
                        elif er.status_code == 404:
                            checked.append({"email": email, "breaches": [], "pwned": False})
                    except Exception:
                        pass
                breach_info["checked_emails"] = checked
    except Exception as e:
        breach_info["error"] = str(e)

    result.osint_breach = breach_info
    progress.advance(task, 15)

    # ── 2. ASN / BGP
    progress.update(task, description="[cyan]OSINT:[/cyan] ASN/BGP lookup (ip-api + bgpview)…")
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
                asn_info["as_number"] = data.get("as",     "")
                asn_info["as_name"]   = data.get("asname", "")
                asn_info["org"]       = data.get("org",    "")

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
                        asn_info["ipv4_ranges"]       = ipv4[:20]
                        asn_info["ipv6_ranges"]       = ipv6[:10]
                        asn_info["total_ipv4_ranges"] = len(ipv4)
    except Exception as e:
        asn_info["error"] = str(e)

    result.osint_asn = asn_info
    progress.advance(task, 15)

    # ── 3. Wayback Machine
    progress.update(task, description="[cyan]OSINT:[/cyan] Wayback Machine historical scan…")
    wayback_urls: list[str] = []
    try:
        cdx_url = (
            f"http://web.archive.org/cdx/search/cdx"
            f"?url={hostname}/*&output=json&fl=original&collapse=urlkey"
            f"&filter=statuscode:200&limit=200"
        )
        r = SESSION.get(cdx_url, timeout=15)
        if r.ok:
            rows     = r.json()
            all_urls = [row[0] for row in rows[1:] if row]

            interesting_patterns = [
                r"/api/", r"/admin", r"/config", r"/backup", r"\.env",
                r"/graphql", r"/swagger", r"/actuator", r"\.git",
                r"/login", r"/dashboard", r"/panel", r"/debug",
                r"/upload", r"/files", r"/docs", r"/internal",
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
    progress.update(task, description="[cyan]OSINT:[/cyan] Generating GitHub OSINT dorks…")
    result.osint_github = [
        f'"{hostname}" password',
        f'"{hostname}" api_key OR secret OR token',
        f'"{hostname}" .env OR config',
        f'org:{hostname.split(".")[0]} filename:.env',
        f'"{hostname}" db_password OR database_url',
        f'"{hostname}" aws_access_key_id',
        f'site:github.com "{hostname}" secret',
    ]
    progress.advance(task, 10)
