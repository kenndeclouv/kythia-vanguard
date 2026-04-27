"""
src/modules/cve.py — Module 8: CVE intelligence via banner grabbing + NVD NIST API.
"""

import re
from src.export import md_table
import time

from rich import box
from rich.markup import escape
from rich.rule import Rule
from rich.table import Table


from src.config import console, C, rate_limiter, SESSION, TIMEOUT
from src.models import ScanResult
from src.ui.display import _severity_style
from src.scoring import score_and_report

# ── CMS fingerprinting signatures
CMS_SIGNATURES: dict[str, dict] = {
    "WordPress": {
        "paths": ["/wp-login.php", "/wp-admin/", "/wp-content/", "/wp-includes/"],
        "meta": ["generator.*wordpress"],
        "body": ["wp-content", "wp-includes", "WordPress"],
    },
    "Joomla": {
        "paths": ["/administrator/", "/components/", "/modules/"],
        "meta": ["generator.*joomla"],
        "body": ["/components/com_", "Joomla"],
    },
    "Drupal": {
        "paths": ["/sites/default/", "/modules/", "/themes/"],
        "headers": {"x-generator": "drupal"},
        "meta": ["generator.*drupal"],
        "body": ["Drupal.settings", "/sites/all/"],
    },
    "Django": {
        "headers": {"server": "wsgiserver"},
        "body": ["csrfmiddlewaretoken", 'name="csrfmiddlewaretoken"'],
    },
    "Laravel": {
        "body": ["laravel_session", "XSRF-TOKEN"],
        "headers": {"set-cookie": ["laravel_session", "XSRF-TOKEN"]},
    },
    "Laravel Livewire": {
        "body": [
            "livewire.js",
            "wire:id",
            "wire:model",
            "window.livewire",
            "wire:snapshot",
        ],
    },
    "Spring Boot": {
        "paths": ["/actuator", "/actuator/health"],
        "headers": {"x-application-context": "application"},
    },
    "Next.js": {
        "headers": {"x-powered-by": "next.js"},
        "body": ["__NEXT_DATA__", "_next/static", "next/router"],
    },
    "React": {
        "body": [
            "data-reactroot",
            "_reactRootContainer",
            "react.development.js",
            "react-dom",
        ],
    },
    "Vue.js": {
        "body": ["data-v-", "vue.js", "vue.min.js", "window.__VUE__"],
    },
    "Nginx": {
        "headers": {"server": "nginx"},
    },
    "Apache": {
        "headers": {"server": "apache"},
    },
}

# Product → NVD CPE keyword mapping for CVE searches
PRODUCT_CPE_MAP: dict[str, str] = {
    "nginx": "nginx",
    "apache": "apache_http_server",
    "wordpress": "wordpress",
    "joomla": "joomla",
    "drupal": "drupal",
    "django": "django",
    "spring boot": "spring_boot",
    "openssl": "openssl",
    "openssh": "openssh",
    "mysql": "mysql",
    "postgresql": "postgresql",
    "redis": "redis",
    "mongodb": "mongodb",
    "elasticsearch": "elasticsearch",
}

# Regex patterns to extract version strings from service banners
VERSION_PATTERNS: list[str] = [
    r"(?i)nginx[/ ](\d+\.\d+\.?\d*)",
    r"(?i)apache[/ ](\d+\.\d+\.?\d*)",
    r"(?i)openssh[_-](\d+\.\d+\.?\d*)",
    r"(?i)openssl[/ ](\d+\.\d+\.?\d*)",
    r"(?i)mysql\s+(\d+\.\d+\.?\d*)",
    r"(?i)redis\s+(\d+\.\d+\.?\d*)",
    r"(?i)php[/ ](\d+\.\d+\.?\d*)",
    r"(?i)python[/ ](\d+\.\d+\.?\d*)",
    r"(?i)tomcat[/ ](\d+\.\d+\.?\d*)",
]


def _parse_banner_versions(banners: dict) -> list[dict]:
    """Extract product + version pairs from grabbed service banners."""
    found: list[dict] = []
    for port, banner in banners.items():
        for pat in VERSION_PATTERNS:
            m = re.search(pat, banner)
            if m:
                pm = re.search(
                    r"(?i)(nginx|apache|openssh|openssl|mysql|redis|php|python|tomcat)",
                    banner,
                )
                product = pm.group(1).lower() if pm else "unknown"
                found.append(
                    {
                        "port": port,
                        "product": product,
                        "version": m.group(1),
                        "banner": banner[:200],
                    }
                )
    return found


def _lookup_nvd_cves(product: str, version: str) -> list[dict]:
    """Query NVD NIST 2.0 API for CVEs matching a product/version pair."""
    cves: list[dict] = []
    keyword = PRODUCT_CPE_MAP.get(product.lower(), product.lower())

    try:
        r = SESSION.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={
                "keywordSearch": f"{keyword} {version}",
                "resultsPerPage": 10,
                "startIndex": 0,
            },
            timeout=15,
            headers={"Accept": "application/json"},
        )
        if r.ok:
            for item in r.json().get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                metrics = cve.get("metrics", {})
                cvss_v3 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}).get(
                    "baseScore"
                ) or metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {}).get(
                    "baseScore"
                )
                if cvss_v3:
                    if cvss_v3 >= 9.0:
                        severity = "CRITICAL"
                    elif cvss_v3 >= 7.0:
                        severity = "HIGH"
                    elif cvss_v3 >= 4.0:
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"
                else:
                    severity = "UNKNOWN"

                desc = next(
                    (
                        d["value"]
                        for d in cve.get("descriptions", [])
                        if d.get("lang") == "en"
                    ),
                    "No description available",
                )
                cves.append(
                    {
                        "cve_id": cve_id,
                        "product": product,
                        "version": version,
                        "cvss_v3": cvss_v3,
                        "severity": severity,
                        "description": desc[:300],
                    }
                )
    except Exception:
        pass
    return cves


def _fingerprint_cms(
    target_url: str, hostname: str, resp_body: str, headers_lower: dict
) -> dict:
    """Detect CMS and estimate version from response body / headers."""
    detected: dict = {}

    for cms, sigs in CMS_SIGNATURES.items():
        score = 0

        for kw in sigs.get("body", []):
            if re.search(kw, resp_body, re.IGNORECASE):
                score += 2

        for pat in sigs.get("meta", []):
            m = re.search(
                r'<meta[^>]+name=["\']generator["\'][^>]*content=["\']([^"\']*)["\']',
                resp_body,
                re.IGNORECASE,
            )
            if m and re.search(pat, m.group(1), re.IGNORECASE):
                score += 3
                ver_m = re.search(r"(\d+\.\d+\.?\d*)", m.group(1))
                if ver_m:
                    detected.setdefault(cms, {})["version"] = ver_m.group(1)

        for h_key, h_val in sigs.get("headers", {}).items():
            if h_key in headers_lower:
                if h_val == "" or h_val.lower() in headers_lower[h_key].lower():
                    score += 2

        if score >= 2:
            detected.setdefault(cms, {})["confidence"] = min(100, score * 15)

    # Standalone server product/version from Server header
    srv = headers_lower.get("server", "")
    if srv:
        ver_m = re.search(r"(\d+\.\d+\.?\d*)", srv)
        product_m = re.search(r"(?i)(nginx|apache|iis|lighttpd|gunicorn|uvicorn)", srv)
        if product_m:
            pname = product_m.group(1)
            detected.setdefault(pname, {})["confidence"] = 50
            if ver_m:
                detected[pname]["version"] = ver_m.group(1)
        elif ver_m:
            # Generic server name fallback
            name_m = re.search(r"^(\w+)", srv)
            if name_m:
                pname = name_m.group(1)
                detected.setdefault(pname, {})["confidence"] = 50
                detected[pname]["version"] = ver_m.group(1)

    return detected


def run_cve_intelligence(
    target_url: str, hostname: str, result: ScanResult, progress, task
) -> None:
    # ── Step 1: Parse service banners
    progress.update(task, description="[cyan]CVE:[/cyan] Parsing service banners…")
    banner_products = _parse_banner_versions(result.banners)
    progress.advance(task, 10)

    # ── Step 2: CMS fingerprinting
    progress.update(task, description="[cyan]CVE:[/cyan] CMS fingerprinting…")
    rate_limiter.wait()
    try:
        resp = SESSION.get(target_url, timeout=TIMEOUT, allow_redirects=True)
        if resp.ok:
            body = resp.text
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}

            result.cms_detected = _fingerprint_cms(
                target_url, hostname, body, headers_lower
            )

            # Also extract from Server header if not already captured
            srv = headers_lower.get("server", "")
            if srv:
                for pat in VERSION_PATTERNS:
                    m = re.search(pat, srv)
                    if m:
                        pm = re.search(
                            r"(?i)(nginx|apache|iis|lighttpd|gunicorn|uvicorn)", srv
                        )
                        if pm:
                            entry = {
                                "port": 443,
                                "product": pm.group(1).lower(),
                                "version": m.group(1),
                                "banner": srv,
                            }
                            if entry not in banner_products:
                                banner_products.append(entry)
    except Exception:
        pass
    progress.advance(task, 10)

    # ── Step 3: NVD CVE lookup
    progress.update(task, description="[cyan]CVE:[/cyan] Querying NVD/NIST database…")
    all_cves: list[dict] = []
    for bp in banner_products:
        cves = _lookup_nvd_cves(bp["product"], bp["version"])
        for cve in cves:
            cve["port"] = bp["port"]
        all_cves.extend(cves)
        time.sleep(0.7)  # NVD rate limit: ~5 req/30 s without an API key

    all_cves.sort(key=lambda c: c.get("cvss_v3") or 0, reverse=True)
    result.cve_findings = all_cves[:30]
    progress.advance(task, 30)
    score_and_report(result, "cve")


def score_cve(result):
    if not result.cve_findings:
        return 100
    _d = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 6, "LOW": 2}
    deduct = sum(_d.get(c.get("severity", "LOW"), 2) for c in result.cve_findings)
    return max(0, 100 - min(deduct, 90))


def display_cve(result: ScanResult) -> None:
    console.print(
        Rule(
            f"[{C['accent']}]🔬  CVE INTELLIGENCE LAYER[/{C['accent']}]",
            style="magenta",
        )
    )

    # ── CMS Detection
    console.print(Rule("[bold]CMS / Framework Fingerprinting[/bold]", style="dim"))
    if result.cms_detected:
        cms_t = Table(box=box.ROUNDED, border_style="cyan", header_style=C["head"])
        cms_t.add_column("CMS / Platform", style=C["info"], width=20)
        cms_t.add_column("Version Detected", style="white", width=18)
        cms_t.add_column("Confidence", style=C["warn"], width=14)
        for cms, info in result.cms_detected.items():
            cms_t.add_row(
                cms, info.get("version", "unknown"), f"{info.get('confidence', '?')}%"
            )
        console.print(cms_t)
    else:
        console.print("  [dim]No CMS fingerprints detected.[/dim]")
    console.print()

    # ── CVE Findings
    console.print(Rule("[bold]CVE Matches (via NVD/NIST API)[/bold]", style="dim"))
    if not result.cve_findings:
        console.print(
            "  [dim]No CVEs matched. (No banner data or no matching NVD entries.)[/dim]"
        )
        console.print(
            "  [dim]Tip: Run port scan first so banners can be grabbed.[/dim]"
        )
        console.print()
        return

    cve_t = Table(
        box=box.DOUBLE_EDGE, border_style="red", header_style=C["head"], show_lines=True
    )
    cve_t.add_column("CVE ID", style=C["bad"], width=16)
    cve_t.add_column("Product", style=C["info"], width=14)
    cve_t.add_column("Version", style="white", width=10)
    cve_t.add_column("CVSS v3", width=10, justify="center")
    cve_t.add_column("Severity", width=12, justify="center")
    cve_t.add_column("Port", width=6, justify="right")
    cve_t.add_column("Description", style=C["dim"])

    for cve in result.cve_findings:
        sev = cve.get("severity", "UNKNOWN")
        sev_st = _severity_style(sev)
        cvss = str(cve.get("cvss_v3", "?")) if cve.get("cvss_v3") else "?"
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


def export_cve(result: ScanResult, W: callable) -> None:
    W("## 🦠 CVE Intelligence\n\n")
    if result.cms_detected:
        W("### CMS / Framework Detection\n\n")
        for cms, info in result.cms_detected.items():
            W(
                f"- **{cms}** v{info.get('version', '?')} (confidence: {info.get('confidence', '?')}%)\n"
            )
        W("\n")
    if result.cve_findings:
        W(f"### CVE Findings ({len(result.cve_findings)} matched)\n\n")
        rows = [
            [
                c["cve_id"],
                c["product"],
                c["version"],
                c.get("cvss_v3", "?"),
                c["severity"],
                c.get("port", "?"),
            ]
            for c in result.cve_findings
        ]
        W(
            md_table(
                ["CVE ID", "Product", "Version", "CVSS v3", "Severity", "Port"],
                rows,
            )
        )
    W("\n")
