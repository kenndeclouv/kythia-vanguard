"""
src/modules/headers.py — Module 3: Security header analysis + TLS inspection.
"""

import datetime
import socket
import ssl

from src.config import SESSION, TIMEOUT
from src.models import ScanResult

SECURITY_HEADERS: dict[str, tuple] = {
    "strict-transport-security":    ("HSTS",           "Enforces HTTPS connections"),
    "content-security-policy":      ("CSP",            "Mitigates XSS & data injection"),
    "x-content-type-options":       ("X-Content-Type", "Prevents MIME-type sniffing"),
    "x-frame-options":              ("X-Frame",        "Prevents clickjacking"),
    "x-xss-protection":             ("X-XSS-Prot",    "Legacy XSS filter (deprecated but useful)"),
    "referrer-policy":              ("Referrer-Policy","Controls referrer header leakage"),
    "permissions-policy":           ("Permissions",    "Restricts browser feature access"),
    "cross-origin-opener-policy":   ("COOP",           "Isolates browsing context"),
    "cross-origin-embedder-policy": ("COEP",           "Requires CORP for embedded resources"),
    "cross-origin-resource-policy": ("CORP",           "Controls resource sharing"),
    "cache-control":                ("Cache-Control",  "Controls caching behavior"),
    "x-powered-by":                 ("X-Powered-By",  "⚠ REVEALS server tech — should be REMOVED"),
    "server":                       ("Server",         "⚠ REVEALS server version — consider hiding"),
}


def run_header_analysis(
    target_url: str, hostname: str, result: ScanResult, progress, task
) -> None:
    # ── Security headers (from headers already grabbed by WAF module)
    progress.update(task, description="[cyan]Headers:[/cyan] Analysing security headers…")
    headers_lower = {k.lower(): v for k, v in result.headers.items()}
    sec: dict = {}

    for header, (short, desc) in SECURITY_HEADERS.items():
        present   = header in headers_lower
        value     = headers_lower.get(header, "")
        dangerous = header in ("x-powered-by",)
        sec[header] = {
            "present":   present,
            "value":     value,
            "short":     short,
            "desc":      desc,
            "dangerous": dangerous,
        }
    result.security_headers = sec
    progress.advance(task, 25)

    # ── TLS certificate inspection
    progress.update(task, description="[cyan]TLS:[/cyan] Inspecting SSL certificate…")
    tls: dict = {}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((hostname, 443), timeout=TIMEOUT),
            server_hostname=hostname,
        ) as ssock:
            cert = ssock.getpeercert()
            tls["subject"]       = dict(x[0] for x in cert.get("subject", []))
            tls["issuer"]        = dict(x[0] for x in cert.get("issuer", []))
            tls["version"]       = cert.get("version")
            tls["serial"]        = cert.get("serialNumber")
            tls["not_before"]    = cert.get("notBefore")
            tls["not_after"]     = cert.get("notAfter")
            tls["protocol"]      = ssock.version()
            tls["cipher"]        = ssock.cipher()[0] if ssock.cipher() else "N/A"
            tls["alt_names"]     = [v for _, v in cert.get("subjectAltName", [])]
            exp = datetime.datetime.strptime(tls["not_after"], "%b %d %H:%M:%S %Y %Z")
            tls["days_to_expiry"] = (exp - datetime.datetime.utcnow()).days
    except ssl.SSLCertVerificationError as e:
        tls["error"] = f"Certificate verification failed: {e}"
    except Exception as e:
        tls["error"] = str(e)

    result.tls_info = tls
    progress.advance(task, 25)
