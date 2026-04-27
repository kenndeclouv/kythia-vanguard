"""
src/models.py — Data model for a completed scan.
"""

from dataclasses import dataclass, field


@dataclass
class ScanResult:
    target: str = ""
    timestamp: str = ""

    # ── core modules
    whois: dict = field(default_factory=dict)
    subdomains: list = field(default_factory=list)
    dns_records: dict = field(default_factory=dict)
    waf_cdn: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    security_headers: dict = field(default_factory=dict)
    tls_info: dict = field(default_factory=dict)
    fuzzing: list = field(default_factory=list)
    forms: list = field(default_factory=list)
    open_ports: list = field(default_factory=list)
    score: int = 0
    cloud_findings: list = field(default_factory=list)
    graphql_findings: list = field(default_factory=list)
    sourcemap_findings: list = field(default_factory=list)

    # ── v2: OSINT
    osint_breach: dict = field(default_factory=dict)  # HaveIBeenPwned results
    osint_asn: dict = field(default_factory=dict)  # ASN / BGP / IP range
    osint_wayback: list = field(default_factory=list)  # Old endpoints from Wayback
    osint_github: list = field(default_factory=list)  # GitHub dork queries

    # ── v2: CVE Intelligence
    banners: dict = field(default_factory=dict)  # port → banner text
    cve_findings: list = field(
        default_factory=list
    )  # [{cve_id, cvss, desc, port, product}]
    cms_detected: dict = field(default_factory=dict)  # {cms: {version, confidence}}

    # ── v2: Deep Crawler
    sitemap: list = field(default_factory=list)  # all internal URLs found
    js_endpoints: list = field(default_factory=list)  # hidden API endpoints from JS
    parameters: dict = field(default_factory=dict)  # url → [param, ...]

    # ── v2: nuclei
    nuclei_findings: list = field(default_factory=list)
    nuclei_summary: dict = field(default_factory=dict)

    # ── v3: new modules
    debug_findings: list = field(default_factory=list)  # Framework debug leaks
    infra_findings: list = field(default_factory=list)  # Docker/Redis/Infra exposure
    webhook_findings: list = field(default_factory=list)  # Discord/Telegram/Slack creds
    git_findings: dict = field(default_factory=dict)  # Exposed .git dump results
