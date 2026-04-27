"""
src/scoring.py — Security score calculator (0–100).
"""

from src.models import ScanResult

_CRITICAL_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
]

_DANGEROUS_PORTS = {21, 23, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 27017}


def calculate_score(result: ScanResult) -> int:
    score = 100

    # Security headers
    for h in _CRITICAL_HEADERS:
        if not result.security_headers.get(h, {}).get("present"):
            score -= 5

    if result.security_headers.get("x-powered-by", {}).get("present"):
        score -= 3

    # TLS certificate
    tls = result.tls_info
    if "error" in tls:
        score -= 15
    elif tls.get("days_to_expiry", 999) < 7:
        score -= 20
    elif tls.get("days_to_expiry", 999) < 30:
        score -= 10

    # Fuzzing hits
    for f in result.fuzzing:
        if f["severity"] == "high":
            score -= 10
        elif f["severity"] == "medium":
            score -= 3

    # Exposed dangerous ports
    for p in result.open_ports:
        if p["port"] in _DANGEROUS_PORTS:
            score -= 5

    # POST forms without CSRF protection
    for form in result.forms:
        if form["method"] == "POST" and not form["has_csrf"]:
            score -= 8

    # v2: CVE findings
    for cve in result.cve_findings:
        sev = cve.get("severity", "LOW")
        if sev == "CRITICAL":
            score -= 15
        elif sev == "HIGH":
            score -= 8
        elif sev == "MEDIUM":
            score -= 3

    # v2: Breach data
    if any(e.get("pwned") for e in result.osint_breach.get("checked_emails", [])):
        score -= 10

    # v2: Large number of historically exposed endpoints
    if len(result.osint_wayback) > 10:
        score -= 5

    return max(0, min(100, score))
