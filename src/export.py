"""
src/export.py — Export scan results to JSON and Markdown reports.
"""

import datetime
import json
import os
from dataclasses import asdict

from src.models import ScanResult


def _md_table(headers: list[str], rows: list[list]) -> str:
    h = " | ".join(headers)
    sep = " | ".join(["---"] * len(headers))
    lines = [f"| {h} |", f"| {sep} |"]
    for row in rows:
        lines.append("| " + " | ".join(str(c) for c in row) + " |")
    return "\n".join(lines) + "\n"


def export_results(result: ScanResult, target: str) -> tuple[str, str]:
    os.makedirs("reports", exist_ok=True)

    safe_name = (
        target.replace("https://", "")
        .replace("http://", "")
        .replace("/", "_")
        .replace(":", "_")
    )
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    base = os.path.join("reports", f"{safe_name}_{ts}")

    # ── JSON ─────────────────────────────────────────────────────────
    json_path = f"{base}.json"
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(asdict(result), fh, indent=2, default=str)

    # ── Markdown ─────────────────────────────────────────────────────
    md_path = f"{base}.md"
    with open(md_path, "w", encoding="utf-8") as fh:
        W = fh.write

        # ── Header ───────────────────────────────────────────────────
        W("# 🛡️ K-Vanguard Security Assessment Report\n\n")
        W("| Field | Value |\n|---|---|\n")
        W(f"| **Target** | {result.target} |\n")
        W(f"| **Timestamp** | {result.timestamp} |\n")
        W(f"| **Security Score** | {result.score}/100 |\n\n")
        W("---\n\n")

        # ── WHOIS ────────────────────────────────────────────────────
        W("## 📋 WHOIS\n\n")
        if result.whois:
            W(_md_table(["Field", "Value"], [[k, v] for k, v in result.whois.items()]))
        W("\n")

        # ── Subdomains ───────────────────────────────────────────────
        W(f"## 🌐 Subdomains ({len(result.subdomains)} found)\n\n")
        for s in result.subdomains:
            W(f"- `{s}`\n")
        W("\n")

        # ── WAF / CDN ────────────────────────────────────────────────
        W("## 🛡️ WAF / CDN Detection\n\n")
        if result.waf_cdn:
            for p, h in result.waf_cdn.items():
                matched = ", ".join(h) if isinstance(h, list) else str(h)
                W(f"- **{p}** (matched: {matched})\n")
        else:
            W("- No WAF/CDN detected.\n")
        W("\n")

        # ── Security Headers ─────────────────────────────────────────
        W("## 🔒 Security Headers\n\n")
        if result.security_headers:
            rows = [
                [hdr, "✓" if info["present"] else "✗", info.get("value", "")]
                for hdr, info in result.security_headers.items()
            ]
            W(_md_table(["Header", "Present", "Value"], rows))
        W("\n")

        # ── TLS ──────────────────────────────────────────────────────
        W("## 🔐 TLS / SSL\n\n")
        if result.tls_info:
            W(
                _md_table(
                    ["Field", "Value"], [[k, v] for k, v in result.tls_info.items()]
                )
            )
        W("\n")

        # ── Open Ports ───────────────────────────────────────────────
        W(f"## 🔌 Open Ports ({len(result.open_ports)} found)\n\n")
        if result.open_ports:
            dangerous = {21, 23, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 27017}
            rows = [
                [
                    p["port"],
                    p["service"],
                    p.get("banner", "")[:60],
                    "⚠️ Dangerous" if p["port"] in dangerous else "OK",
                ]
                for p in result.open_ports
            ]
            W(_md_table(["Port", "Service", "Banner", "Note"], rows))
        W("\n")

        # ── Fuzzing ──────────────────────────────────────────────────
        W(f"## 🕵️ Fuzzing ({len(result.fuzzing)} findings)\n\n")
        if result.fuzzing:
            rows = [
                [f["severity"].upper(), f["status"], f"`{f['path']}`"]
                for f in result.fuzzing
            ]
            W(_md_table(["Severity", "Status", "Path"], rows))
        W("\n")

        # ── Forms ────────────────────────────────────────────────────
        W(f"## 📝 Forms ({len(result.forms)} found)\n\n")
        for form in result.forms:
            W(
                f"### Form #{form['form_num']} — `{form['method']}` → `{form['action']}`\n"
            )
            W(f"- CSRF: {'✓ Present' if form['has_csrf'] else '✗ Missing'}\n")
            W(f"- Risk: **{form['risk'].upper()}**\n")
            inputs = ", ".join(i["name"] for i in form["inputs"] if i["name"])
            W(f"- Inputs: `{inputs}`\n\n")

        # ── OSINT ────────────────────────────────────────────────────
        W("## 🕵️ OSINT Intelligence\n\n")
        if result.osint_asn:
            W("### ASN / BGP\n\n")
            W(
                _md_table(
                    ["Field", "Value"], [[k, v] for k, v in result.osint_asn.items()]
                )
            )
        if result.osint_wayback:
            W(f"\n### Wayback Machine ({len(result.osint_wayback)} URLs)\n\n")
            for url in result.osint_wayback[:50]:
                W(f"- {url}\n")
        if result.osint_github:
            W("\n### GitHub OSINT Dorks\n\n")
            for dork in result.osint_github:
                W(f"- `{dork}`\n")
        W("\n")

        # ── CVE ──────────────────────────────────────────────────────
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
                _md_table(
                    ["CVE ID", "Product", "Version", "CVSS v3", "Severity", "Port"],
                    rows,
                )
            )
        W("\n")

        # ── Deep Crawler ─────────────────────────────────────────────
        W("## 🕸️ Deep Crawler\n\n")
        W(f"### Sitemap ({len(result.sitemap)} URLs)\n\n")
        for url in result.sitemap[:100]:
            W(f"- {url}\n")
        if len(result.sitemap) > 100:
            W(f"\n> …and {len(result.sitemap) - 100} more in the JSON report.\n")
        W(f"\n### JS-Discovered Endpoints ({len(result.js_endpoints)})\n\n")
        for ep in result.js_endpoints:
            W(f"- `{ep}`\n")
        W("\n### Query Parameters Mined\n\n")
        for url, parms in result.parameters.items():
            W(f"- **`{url}`** → `{', '.join(parms)}`\n")
        W("\n")

        # ── Nuclei ───────────────────────────────────────────────────
        if result.nuclei_findings:
            W(f"## ☢️ Nuclei Scan ({len(result.nuclei_findings)} findings)\n\n")
            rows = [
                [
                    n.get("template_id", "?"),
                    n.get("severity", "?"),
                    n.get("name", "?"),
                    n.get("matched_at", "?"),
                ]
                for n in result.nuclei_findings
            ]
            W(_md_table(["Template ID", "Severity", "Name", "Matched At"], rows))
            W("\n")

        # ══════════════════════════════════════════════════════════════
        # GOD-MODE MODULES
        # ══════════════════════════════════════════════════════════════
        W("---\n\n## ⚡ God-Mode Attack Modules\n\n")

        # ── Debug Sniper ─────────────────────────────────────────────
        if result.debug_findings:
            W(f"### 🐞 Debug Mode Exposure ({len(result.debug_findings)} findings)\n\n")
            for f in result.debug_findings:
                sev = f.get("severity", "info").upper()
                W(f"#### `[{sev}]` {f.get('title', 'Unknown')}\n\n")
                W(f"- **URL:** {f.get('url', '?')}\n")
                W(f"- **Detail:** {f.get('detail', '')}\n")
                if f.get("evidence"):
                    W(f"- **Evidence:** `{str(f['evidence'])[:200]}`\n")
                W("\n")
        else:
            W("### 🐞 Debug Mode Exposure\n\n- ✅ No debug mode leaks detected.\n\n")

        # ── Infra Exposure ───────────────────────────────────────────
        if result.infra_findings:
            W(
                f"### 🐳 Infrastructure Exposure ({len(result.infra_findings)} findings)\n\n"
            )
            rows = [
                [
                    f.get("service", "?"),
                    f.get("url", f.get("host", "?")),
                    f.get("severity", "?").upper(),
                    f.get("detail", ""),
                ]
                for f in result.infra_findings
            ]
            W(_md_table(["Service", "URL / Host", "Severity", "Detail"], rows))
            W("\n")
        else:
            W(
                "### 🐳 Infrastructure Exposure\n\n- ✅ No exposed Docker/Redis/Portainer found.\n\n"
            )

        # ── Webhook Hunter ───────────────────────────────────────────
        if result.webhook_findings:
            W(
                f"### 🔔 Webhook / Bot Credential Leaks ({len(result.webhook_findings)} found)\n\n"
            )
            W(
                "> [!CAUTION]\n> The following credentials were found hardcoded in JavaScript files.\n\n"
            )
            rows = [
                [
                    f.get("type", "?"),
                    f.get("source_url", "?")[:80],
                    f"`{str(f.get('token', ''))[:40]}…`",
                ]
                for f in result.webhook_findings
            ]
            W(_md_table(["Type", "Source URL", "Token (truncated)"], rows))
            W("\n")
        else:
            W(
                "### 🔔 Webhook / Bot Credential Leaks\n\n- ✅ No hardcoded webhook tokens found.\n\n"
            )

        # ── Subdomain Takeover ───────────────────────────────────────
        if result.takeover_findings:
            W(
                f"### 👻 Subdomain Takeover ({len(result.takeover_findings)} vulnerable)\n\n"
            )
            W(
                "> [!CAUTION]\n> These subdomains can be claimed immediately on the listed platforms.\n\n"
            )
            rows = [
                [
                    f.get("subdomain", "?"),
                    f.get("cname", "?"),
                    f.get("platform", "?"),
                    f.get("evidence", ""),
                ]
                for f in result.takeover_findings
            ]
            W(_md_table(["Subdomain", "CNAME", "Platform", "Evidence"], rows))
            W("\n")
        else:
            W("### 👻 Subdomain Takeover\n\n- ✅ No vulnerable subdomains found.\n\n")

        # ── JS Secret Hunter ─────────────────────────────────────────
        if result.js_secret_findings:
            W(f"### 🕵️ JS Secret Hunter ({len(result.js_secret_findings)} secrets)\n\n")
            W("> [!CAUTION]\n> Secrets found hardcoded in JavaScript source files.\n\n")
            rows = [
                [
                    f.get("type", "?"),
                    f.get("url", "?")[:80],
                    f"`{str(f.get('value', ''))[:50]}`",
                ]
                for f in result.js_secret_findings
            ]
            W(_md_table(["Secret Type", "Source URL", "Value"], rows))
            W("\n")
        else:
            W("### 🕵️ JS Secret Hunter\n\n- ✅ No secrets found in JS files.\n\n")

        # ── CORS ─────────────────────────────────────────────────────
        if result.cors_findings:
            W(f"### 🌍 CORS Misconfiguration ({len(result.cors_findings)} issues)\n\n")
            rows = [
                [
                    f.get("url", "?"),
                    f.get("origin_tested", "?"),
                    f.get("acao", "?"),
                    f.get("severity", "?").upper(),
                ]
                for f in result.cors_findings
            ]
            W(_md_table(["URL", "Origin Tested", "ACAO Header", "Severity"], rows))
            W("\n")
        else:
            W("### 🌍 CORS Misconfiguration\n\n- ✅ No CORS issues found.\n\n")

        # ── JWT ──────────────────────────────────────────────────────
        if result.jwt_findings:
            W(f"### 🔑 JWT Analysis ({len(result.jwt_findings)} tokens)\n\n")
            rows = [
                [
                    f.get("url", "?")[:60],
                    f.get("algorithm", "?"),
                    "✓ Cracked" if f.get("cracked") else "✗",
                    f.get("secret", "")[:30] if f.get("cracked") else "N/A",
                    f.get("severity", "info").upper(),
                ]
                for f in result.jwt_findings
            ]
            W(
                _md_table(
                    ["Source URL", "Algorithm", "Cracked?", "Secret", "Severity"], rows
                )
            )
            W("\n")
        else:
            W("### 🔑 JWT Analysis\n\n- ✅ No JWT vulnerabilities found.\n\n")

        # ══════════════════════════════════════════════════════════════
        # ATTACK SIMULATION RESULTS
        # ══════════════════════════════════════════════════════════════
        W("---\n\n## 💥 Attack Simulation Results\n\n")

        # ── Stress Test ──────────────────────────────────────────────
        W("### 📈 Stress Test (Load Testing)\n\n")
        sf = result.stress_findings
        if sf:
            if sf.get("aborted"):
                W(
                    f"> [!NOTE]\n> **Stress test was automatically aborted.**\n> **Reason:** {sf.get('reason', 'Unknown')}\n\n"
                )
            else:
                summary = sf.get("summary", {})
                if summary:
                    W(
                        _md_table(
                            ["Metric", "Value"],
                            [
                                ["Total Waves", summary.get("total_waves", "?")],
                                [
                                    "Total Requests",
                                    f"{summary.get('total_requests', 0):,}",
                                ],
                                ["Peak VUs", summary.get("peak_vus", "?")],
                                [
                                    "Overall Error Rate",
                                    f"{summary.get('error_rate_pct', 0):.1f}%",
                                ],
                                [
                                    "Avg P99 Latency",
                                    f"{summary.get('avg_p99_ms', 0):.0f}ms",
                                ],
                                [
                                    "Max P99 Latency",
                                    f"{summary.get('max_p99_ms', 0):.0f}ms",
                                ],
                                ["Flags", ", ".join(sf.get("flags", [])) or "None"],
                            ],
                        )
                    )
                waves = sf.get("waves", [])
                if waves:
                    W("\n#### Wave-by-Wave Breakdown\n\n")
                    rows = [
                        [
                            w.get("vu_count", "?"),
                            f"{w.get('rps', 0):.1f}",
                            f"{w.get('error_rate', 0):.1f}%",
                            f"{w.get('ms_p99', 0)}ms",
                            w.get("status", "?"),
                        ]
                        for w in waves
                    ]
                    W(
                        _md_table(
                            ["VUs", "RPS", "Error Rate", "P99 Latency", "Status"], rows
                        )
                    )
        else:
            W("- Stress test was not run.\n")
        W("\n")

        # ── Layer 7 DoS ──────────────────────────────────────────────
        W("### 💣 Layer 7 DoS Analysis\n\n")
        df = result.dos_findings
        if df:
            # Slowloris
            slow = df.get("slowloris", {})
            status = slow.get("status", "not_run")
            if status == "vulnerable":
                W("> [!CAUTION]\n> **Slowloris: VULNERABLE**\n\n")
                W(f"- **Impact:** {slow.get('impact', '?')}\n")
                W(f"- **Detail:** {slow.get('reason', '?')}\n")
                W(
                    f"- **Sockets Opened:** {slow.get('sockets_opened', '?')} | **Survived:** {slow.get('sockets_survived', '?')}\n\n"
                )
            elif status == "skipped":
                W(f"- **Slowloris:** ⏭️ Skipped — {slow.get('reason', '')}\n\n")
            else:
                W(f"- **Slowloris:** ✅ {slow.get('reason', 'Safe')}\n\n")

            # DB DoS
            db = df.get("db_dos", {})
            if db.get("status") == "vulnerable":
                W("> [!CAUTION]\n> **Database Exhaustion: VULNERABLE**\n\n")
                W(f"- **Impact:** {db.get('impact', '?')}\n")
                for ep in db.get("endpoints", []):
                    W(f"  - `{ep['url']}`\n")
                    heavy_str = (
                        ep["heavy_ms"]
                        if isinstance(ep["heavy_ms"], str)
                        else f"{ep['heavy_ms']:.0f}ms"
                    )
                    W(
                        f"    - Baseline: `{ep['baseline_ms']:.0f}ms` → Payload: `{heavy_str}`\n"
                    )
            elif db.get("status") == "skipped":
                W(f"- **Database Exhaustion:** ⏭️ {db.get('reason', 'Skipped')}\n")
            else:
                W(f"- **Database Exhaustion:** ✅ {db.get('reason', 'Safe')}\n")
            W("\n")

            # XML-RPC
            xml = df.get("xmlrpc", {})
            if xml.get("status") == "vulnerable":
                W("> [!CAUTION]\n> **XML-RPC Amplification: VULNERABLE**\n\n")
                W(f"- **URL:** `{xml.get('url', '?')}`\n")
                W(f"- **Detail:** {xml.get('reason', '?')}\n")
                W(f"- **Impact:** {xml.get('impact', '?')}\n")
            else:
                W(f"- **XML-RPC:** ✅ {xml.get('reason', 'Safe')}\n")
        else:
            W("- DoS module was not run.\n")
        W("\n")

        # ── Footer ───────────────────────────────────────────────────
        W("---\n\n")
        W(f"*Generated by K-Vanguard v1.0.0-rc.1 — {result.timestamp}*\n")

    return json_path, md_path
