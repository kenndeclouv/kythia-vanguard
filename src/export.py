"""
src/export.py — Export scan results to JSON and Markdown reports.
"""

import datetime
import json
import os
from dataclasses import asdict

from src.models import ScanResult


def export_results(result: ScanResult, target: str) -> tuple[str, str]:
    """
    Write a JSON report and a Markdown report to the reports/ directory.
    Returns (json_path, md_path).
    """
    os.makedirs("reports", exist_ok=True)

    safe_name = (
        target
        .replace("https://", "")
        .replace("http://",  "")
        .replace("/", "_")
        .replace(":", "_")
    )
    ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    base = os.path.join("reports", f"{safe_name}_{ts}")

    # ── JSON
    json_path = f"{base}.json"
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(asdict(result), fh, indent=2, default=str)

    # ── Markdown
    md_path = f"{base}.md"
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write("# KENN-RECON Pro v1.0.0-rc.1 Report\n\n")
        fh.write(f"**Target:** {result.target}  \n")
        fh.write(f"**Timestamp:** {result.timestamp}  \n")
        fh.write(f"**Security Score:** {result.score}/100\n\n---\n\n")

        # WHOIS
        fh.write("## WHOIS\n\n| Field | Value |\n|---|---|\n")
        for k, v in result.whois.items():
            fh.write(f"| {k} | {v} |\n")

        # Subdomains
        fh.write(f"\n## Subdomains ({len(result.subdomains)} found)\n\n")
        for s in result.subdomains:
            fh.write(f"- `{s}`\n")

        # WAF / CDN
        fh.write("\n## WAF / CDN Detection\n\n")
        for p, h in result.waf_cdn.items():
            fh.write(f"- **{p}** (matched: {', '.join(h)})\n")

        # Security headers
        fh.write("\n## Security Headers\n\n| Header | Present | Value |\n|---|---|---|\n")
        for hdr, info in result.security_headers.items():
            fh.write(f"| {hdr} | {'✓' if info['present'] else '✗'} | {info.get('value','')} |\n")

        # TLS
        fh.write("\n## TLS / SSL\n\n| Field | Value |\n|---|---|\n")
        for k, v in result.tls_info.items():
            fh.write(f"| {k} | {v} |\n")

        # Fuzzing
        fh.write(f"\n## Fuzzing Results ({len(result.fuzzing)} findings)\n\n")
        if result.fuzzing:
            fh.write("| Severity | Status | Path |\n|---|---|---|\n")
            for f in result.fuzzing:
                fh.write(f"| {f['severity'].upper()} | {f['status']} | `{f['path']}` |\n")

        # Forms
        fh.write(f"\n## Forms ({len(result.forms)} found)\n\n")
        for form in result.forms:
            fh.write(f"### Form #{form['form_num']} — {form['method']} → {form['action']}\n")
            fh.write(f"- CSRF token: {'✓ Present' if form['has_csrf'] else '✗ Missing'}\n")
            fh.write(f"- Risk: {form['risk'].upper()}\n")
            fh.write(f"- Inputs: {', '.join(i['name'] for i in form['inputs'] if i['name'])}\n\n")

        # Open ports
        fh.write(f"\n## Open Ports ({len(result.open_ports)} found)\n\n")
        if result.open_ports:
            dangerous_ports = {21, 23, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 27017}
            fh.write("| Port | Service | Banner | Note |\n|---|---|---|---|\n")
            for p in result.open_ports:
                note = "⚠ Dangerous" if p["port"] in dangerous_ports else "OK"
                fh.write(
                    f"| {p['port']} | {p['service']} "
                    f"| {p.get('banner','')[:60]} | {note} |\n"
                )

        # OSINT
        fh.write("\n## OSINT Intelligence\n\n### ASN\n\n")
        for k, v in result.osint_asn.items():
            fh.write(f"- **{k}**: {v}\n")

        fh.write(f"\n### Wayback Machine ({len(result.osint_wayback)} interesting URLs)\n\n")
        for url in result.osint_wayback:
            fh.write(f"- {url}\n")

        fh.write("\n### GitHub OSINT Dorks\n\n")
        for dork in result.osint_github:
            fh.write(f"- `{dork}`\n")

        # CVE
        fh.write("\n## CVE Intelligence\n\n### CMS / Framework Detection\n\n")
        for cms, info in result.cms_detected.items():
            fh.write(
                f"- **{cms}** — version: {info.get('version','?')} "
                f"(confidence: {info.get('confidence','?')}%)\n"
            )

        fh.write(f"\n### CVE Findings ({len(result.cve_findings)} matched)\n\n")
        if result.cve_findings:
            fh.write("| CVE ID | Product | Version | CVSS v3 | Severity | Port |\n"
                     "|---|---|---|---|---|---|\n")
            for cve in result.cve_findings:
                fh.write(
                    f"| {cve['cve_id']} | {cve['product']} | {cve['version']} | "
                    f"{cve.get('cvss_v3','?')} | {cve['severity']} | {cve.get('port','?')} |\n"
                )

        # Deep crawler
        fh.write(f"\n## Deep Crawler\n\n### Sitemap ({len(result.sitemap)} URLs)\n\n")
        for url in result.sitemap:
            fh.write(f"- {url}\n")

        fh.write(f"\n### JS-Discovered API Endpoints ({len(result.js_endpoints)})\n\n")
        for ep in result.js_endpoints:
            fh.write(f"- `{ep}`\n")

        fh.write("\n### Query Parameters Mined\n\n")
        for url, parms in result.parameters.items():
            fh.write(f"- **{url}** → {', '.join(parms)}\n")

    return json_path, md_path
