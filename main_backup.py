#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║         KENN-RECON Pro v2.0 — Advanced Recon & Security Auditor  ║
║         Author  : KENN-RECON Project                             ║
║         Purpose : Safe, non-destructive security reconnaissance  ║
║         License : For authorized testing only                    ║
╚══════════════════════════════════════════════════════════════════╝

LEGAL DISCLAIMER:
  This tool is intended EXCLUSIVELY for authorized security testing,
  bug-bounty programs, and penetration tests where explicit written
  permission has been granted. Unauthorized scanning is illegal.
  The authors accept NO liability for misuse.

NEW IN v2.0:
  ▸ OSINT Layer     — Have I Been Pwned · ASN/BGP · Wayback Machine · GitHub/Shodan hints
  ▸ CVE Intelligence — Banner grabbing · NVD/NIST API CVE lookup · CVSS scoring · CMS fingerprint
  ▸ Deep Crawler    — Recursive spider · JS API endpoint extraction · Parameter mining
"""

# ─────────────────────────────────────────────────────────────────
# Standard-library imports
# ─────────────────────────────────────────────────────────────────
import os
import re
import sys
import ssl
import json
import time
import argparse
import socket
import datetime
import ipaddress
import threading
import urllib.parse
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import Optional
from pathlib import Path

# ─────────────────────────────────────────────────────────────────
# Third-party imports
# pip install rich requests beautifulsoup4 prompt_toolkit
# ─────────────────────────────────────────────────────────────────
try:
    import requests
    from bs4 import BeautifulSoup
    from rich import box
    from rich.align import Align
    from rich.columns import Columns
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.markup import escape
    from rich.panel import Panel
    from rich.progress import (
        BarColumn, MofNCompleteColumn, Progress,
        SpinnerColumn, TaskProgressColumn, TextColumn, TimeElapsedColumn,
    )
    from rich.prompt import Confirm, Prompt
    from rich.rule import Rule
    from rich.style import Style
    from rich.table import Table
    from rich.text import Text
    from rich.tree import Tree
    from prompt_toolkit import prompt as ptk_prompt
    from prompt_toolkit.formatted_text import HTML
    from prompt_toolkit.shortcuts import radiolist_dialog, checkboxlist_dialog
    from prompt_toolkit.styles import Style as PtkStyle
except ImportError as exc:
    print(f"\n[ERROR] Missing dependency: {exc}")
    print("Run:  pip install rich requests beautifulsoup4 prompt_toolkit\n")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────
# Global console (Rich)
# ─────────────────────────────────────────────────────────────────
console = Console(highlight=False)

# ─────────────────────────────────────────────────────────────────
# Rate-limiter: shared token-bucket to stay gentle on targets
# ─────────────────────────────────────────────────────────────────
class RateLimiter:
    """Simple token-bucket rate limiter shared across threads."""

    def __init__(self, rps: float = 5.0):
        self.delay = 1.0 / rps
        self._lock = threading.Lock()
        self._last = time.monotonic()

    def wait(self):
        with self._lock:
            now = time.monotonic()
            gap = self._last + self.delay - now
            if gap > 0:
                time.sleep(gap)
            self._last = time.monotonic()

# Global rate-limiter (default 5 req/s – adjusted at runtime)
rate_limiter = RateLimiter(rps=5.0)

# ─────────────────────────────────────────────────────────────────
# Shared HTTP session with timeout & user-agent
# ─────────────────────────────────────────────────────────────────
SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "KENN-RECON-Pro/2.0 (Security Audit; authorized)",
    "Accept":     "text/html,application/xhtml+xml,*/*",
})
SESSION.verify = False          # TLS errors are findings, not blockers
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 8   # seconds per HTTP request

ROOT_DIR = Path(__file__).resolve().parent
SRC_DIR  = ROOT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

# ─────────────────────────────────────────────────────────────────
# Colour palette
# ─────────────────────────────────────────────────────────────────
C = {
    "banner":   "bold cyan",
    "accent":   "bold magenta",
    "ok":       "bold green",
    "warn":     "bold yellow",
    "bad":      "bold red",
    "info":     "bold blue",
    "dim":      "dim white",
    "head":     "bold white",
    "subtle":   "grey62",
}

# ─────────────────────────────────────────────────────────────────
# Data structures — extended for v2
# ─────────────────────────────────────────────────────────────────
@dataclass
class ScanResult:
    target:           str  = ""
    timestamp:        str  = ""
    # ── existing modules
    whois:            dict = field(default_factory=dict)
    subdomains:       list = field(default_factory=list)
    dns_records:      dict = field(default_factory=dict)
    waf_cdn:          dict = field(default_factory=dict)
    headers:          dict = field(default_factory=dict)
    security_headers: dict = field(default_factory=dict)
    tls_info:         dict = field(default_factory=dict)
    fuzzing:          list = field(default_factory=list)
    forms:            list = field(default_factory=list)
    open_ports:       list = field(default_factory=list)
    score:            int  = 0
    # ── NEW v2: OSINT
    osint_breach:     dict = field(default_factory=dict)   # HaveIBeenPwned results
    osint_asn:        dict = field(default_factory=dict)   # ASN / BGP / IP range
    osint_wayback:    list = field(default_factory=list)   # Old endpoints from Wayback
    osint_github:     list = field(default_factory=list)   # GitHub dork results
    # ── NEW v2: CVE Intelligence
    banners:          dict = field(default_factory=dict)   # port → banner text
    cve_findings:     list = field(default_factory=list)   # [{cve_id, cvss, desc, port, product}]
    cms_detected:     dict = field(default_factory=dict)   # {cms, version, plugins: [...]}
    # ── NEW v2: Deep Crawler
    sitemap:          list = field(default_factory=list)   # all internal URLs found
    js_endpoints:     list = field(default_factory=list)   # hidden API endpoints from JS
    parameters:       dict = field(default_factory=dict)   # url → [param, param, ...]

# ─────────────────────────────────────────────────────────────────
# ░░  BANNER  ░░
# ─────────────────────────────────────────────────────────────────
BANNER = r"""
 ██╗  ██╗███████╗███╗   ██╗███╗   ██╗      ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ██║ ██╔╝██╔════╝████╗  ██║████╗  ██║      ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 █████╔╝ █████╗  ██╔██╗ ██║██╔██╗ ██║█████╗██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██╔═██╗ ██╔══╝  ██║╚██╗██║██║╚██╗██║╚════╝██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ██║  ██╗███████╗██║ ╚████║██║ ╚████║      ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═══╝      ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
                                 ╔═══╗ ╦═╗ ╔═╗
                                 ╠═══╝ ╠╦╝ ║ ║
                                 ╩     ╩╚═ ╚═╝
                     Advanced Recon & Security Auditor v2.0
              + OSINT  |  CVE Intelligence  |  Deep Crawler
"""

def show_banner():
    console.print()
    console.print(Panel(
        Align.center(Text(BANNER, style=C["banner"])),
        border_style="cyan",
        subtitle="[dim]For authorized security testing only — use responsibly[/dim]",
        padding=(0, 2),
    ))
    console.print()

# ─────────────────────────────────────────────────────────────────
# ░░  INTERACTIVE MENU  ░░
# ─────────────────────────────────────────────────────────────────

SCAN_MODULES = [
    ("recon",    "🌐  Auto Recon          — WHOIS · Subdomains · DNS · IP Routing"),
    ("waf",      "🛡️   WAF / CDN Detection — Fingerprint protective layers"),
    ("headers",  "📋  Header Analysis     — Security headers · TLS/SSL certificate"),
    ("fuzz",     "🔍  Smart Directory Fuzz— Exposed endpoints scanner (rate-limited)"),
    ("forms",    "📝  Form & CSRF Audit   — Map inputs, detect missing CSRF tokens"),
    ("ports",    "🔌  Port Scan           — Safe scan of top 25 common ports"),
    # ── NEW v2 modules
    ("osint",    "🧠  OSINT Intelligence  — HaveIBeenPwned · ASN/BGP · Wayback · GitHub"),
    ("cve",      "🔬  CVE Intelligence    — Banner grab · NVD lookup · CMS fingerprint"),
    ("spider",   "🕸️   Deep Crawler        — Recursive spider · JS endpoints · Param mining"),
]

PTK_STYLE = PtkStyle.from_dict({
    "dialog":            "bg:#0d1117 #c9d1d9",
    "dialog frame.label":"bg:#161b22 bold #58a6ff",
    "dialog.body":       "bg:#0d1117 #c9d1d9",
    "dialog shadow":     "bg:#010409",
    "radio-list":        "bg:#0d1117",
    "radio":             "#8b949e",
    "radio-checked":     "bold #58a6ff",
    "button":            "bg:#21262d #c9d1d9",
    "button.focused":    "bg:#388bfd bold #ffffff",
})

# Optional API keys — loaded from env or left empty for free-tier fallback
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")
HIBP_API_KEY   = os.environ.get("HIBP_API_KEY",   "")   # required for HIBP v3

def interactive_menu() -> tuple[str, list[str]]:
    console.print(Rule("[bold cyan]Configuration[/bold cyan]", style="cyan"))
    console.print()

    target = ptk_prompt(
        HTML("<ansibrightcyan><b> 🎯  Target URL or domain ❯  </b></ansibrightcyan>"),
        style=PtkStyle.from_dict({"": "bg:#0d1117 #c9d1d9"}),
    ).strip()

    if not target:
        console.print("[bold red]No target provided. Exiting.[/bold red]")
        sys.exit(0)

    result = checkboxlist_dialog(
        title="KENN-RECON Pro v2.0 — Select Scan Modules",
        text="Use SPACE to toggle, ENTER to confirm, TAB to switch focus:",
        values=SCAN_MODULES,
        style=PTK_STYLE,
    ).run()

    if not result:
        console.print("[bold yellow]No modules selected. Exiting.[/bold yellow]")
        sys.exit(0)

    rps_choice = radiolist_dialog(
        title="Rate Limit (requests / second)",
        text="Choose scan aggressiveness (lower = safer for the target):",
        values=[
            (2,   "🐢  Gentle   —  2 req/s  (recommended for production)"),
            (5,   "🚶  Normal   —  5 req/s  (balanced)"),
            (10,  "🏃  Fast     — 10 req/s  (use only on your own infra)"),
            (100, "🔥  BRUTAL   — 100 req/s (insanely crazy – may crash servers)"),
        ],
        style=PTK_STYLE,
    ).run()

    if rps_choice:
        rate_limiter.delay = 1.0 / rps_choice

    return target, result

# ─────────────────────────────────────────────────────────────────
# ░░  HELPER UTILITIES  ░░
# ─────────────────────────────────────────────────────────────────

def normalise_target(raw: str) -> tuple[str, str]:
    raw = raw.strip().rstrip("/")
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    parsed = urllib.parse.urlparse(raw)
    return raw, parsed.hostname or raw

def safe_get(url: str, **kwargs) -> Optional[requests.Response]:
    rate_limiter.wait()
    try:
        return SESSION.get(url, timeout=TIMEOUT, allow_redirects=True, **kwargs)
    except Exception:
        return None

def _extract_domain_emails(hostname: str) -> list[str]:
    """
    Derive plausible email addresses for HIBP checks from common patterns.
    Uses mx records and common admin patterns (all public info).
    """
    return [
        f"admin@{hostname}",
        f"info@{hostname}",
        f"security@{hostname}",
        f"webmaster@{hostname}",
        f"contact@{hostname}",
    ]

# ─────────────────────────────────────────────────────────────────
# ░░  MODULE 1 — AUTO RECON  ░░  (unchanged from v1)
# ─────────────────────────────────────────────────────────────────

def run_recon(target_url: str, hostname: str, result: ScanResult, progress, task):
    progress.update(task, description="[cyan]Recon:[/cyan] WHOIS lookup…")
    whois_data = {}
    try:
        r = SESSION.get(f"https://rdap.org/domain/{hostname}", timeout=TIMEOUT)
        if r.ok:
            raw = r.json()
            whois_data["registrar"]    = next(
                (e.get("ldhName","") for e in raw.get("entities",[])
                 if "registrar" in e.get("roles",[])), "N/A")
            whois_data["registered"]   = raw.get("events",[{}])[0].get("eventDate","N/A")[:10]
            whois_data["expires"]      = next(
                (e.get("eventDate","N/A")[:10] for e in raw.get("events",[])
                 if e.get("eventAction") == "expiration"), "N/A")
            whois_data["name_servers"] = [ns.get("ldhName","") for ns in raw.get("nameservers",[])]
            whois_data["status"]       = raw.get("status", [])
    except Exception:
        whois_data["error"] = "RDAP lookup failed"
    result.whois = whois_data
    progress.advance(task, 10)

    progress.update(task, description="[cyan]Recon:[/cyan] Subdomain enumeration (crt.sh)…")
    subdomains = set()
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

    progress.update(task, description="[cyan]Recon:[/cyan] DNS record enumeration…")
    dns_records = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "SOA"):
        try:
            r = SESSION.get(
                "https://dns.google/resolve",
                params={"name": hostname, "type": rtype},
                timeout=TIMEOUT,
            )
            if r.ok:
                answers = r.json().get("Answer", [])
                dns_records[rtype] = [a.get("data","") for a in answers]
        except Exception:
            dns_records[rtype] = []
    result.dns_records = dns_records
    progress.advance(task, 15)

    progress.update(task, description="[cyan]Recon:[/cyan] IP geolocation…")
    a_records = dns_records.get("A", [])
    if a_records:
        try:
            r = SESSION.get(
                f"http://ip-api.com/json/{a_records[0]}?fields=country,regionName,city,isp,org,as",
                timeout=TIMEOUT,
            )
            if r.ok:
                result.whois["ip_geo"] = r.json()
        except Exception:
            pass
    progress.advance(task, 10)

# ─────────────────────────────────────────────────────────────────
# ░░  MODULE 2 — WAF / CDN DETECTION  ░░  (unchanged from v1)
# ─────────────────────────────────────────────────────────────────

WAF_SIGNATURES = {
    "Cloudflare":            {"server": "cloudflare", "cf-ray": ""},
    "AWS WAF / CloudFront":  {"x-amz-cf-id": "", "x-amzn-requestid": "", "x-amz-cf-pop": ""},
    "Akamai":                {"x-akamai-transformed": "", "x-check-cacheable": ""},
    "Sucuri":                {"x-sucuri-id": "", "server": "sucuri"},
    "Fastly":                {"x-served-by": "cache", "fastly-restarts": ""},
    "Imperva / Incapsula":   {"x-iinfo": "", "x-cdn": "incapsula"},
    "Nginx (proxy)":         {"server": "nginx"},
    "Apache":                {"server": "apache"},
    "Microsoft Azure":       {"x-msedge-ref": "", "x-azure-ref": ""},
    "Varnish":               {"x-varnish": "", "via": "varnish"},
    "Vercel":                {"x-vercel-id": ""},
    "Netlify":               {"x-nf-request-id": "", "server": "netlify"},
}

def run_waf_detection(target_url: str, result: ScanResult, progress, task):
    progress.update(task, description="[cyan]WAF:[/cyan] Fetching headers…")
    resp = safe_get(target_url)
    detected    = {}
    raw_headers = {}

    if resp is not None:
        raw_headers   = dict(resp.headers)
        lower_headers = {k.lower(): v.lower() for k, v in resp.headers.items()}

        for provider, sigs in WAF_SIGNATURES.items():
            matched = []
            for h_key, h_val in sigs.items():
                if h_key in lower_headers:
                    if h_val == "" or h_val in lower_headers[h_key]:
                        matched.append(h_key)
            if matched:
                detected[provider] = matched

    result.headers = raw_headers
    result.waf_cdn = detected
    progress.advance(task, 50)

# ─────────────────────────────────────────────────────────────────
# ░░  MODULE 3 — SECURITY HEADERS & TLS  ░░  (unchanged from v1)
# ─────────────────────────────────────────────────────────────────

SECURITY_HEADERS = {
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

def run_header_analysis(target_url: str, hostname: str, result: ScanResult, progress, task):
    progress.update(task, description="[cyan]Headers:[/cyan] Analysing security headers…")
    headers_lower = {k.lower(): v for k, v in result.headers.items()}
    sec = {}

    for header, (short, desc) in SECURITY_HEADERS.items():
        present   = header in headers_lower
        value     = headers_lower.get(header, "")
        dangerous = header in ("x-powered-by",)
        sec[header] = {"present": present, "value": value,
                       "short": short, "desc": desc, "dangerous": dangerous}
    result.security_headers = sec
    progress.advance(task, 25)

    progress.update(task, description="[cyan]TLS:[/cyan] Inspecting SSL certificate…")
    tls = {}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((hostname, 443), timeout=TIMEOUT),
            server_hostname=hostname
        ) as ssock:
            cert = ssock.getpeercert()
            tls["subject"]        = dict(x[0] for x in cert.get("subject", []))
            tls["issuer"]         = dict(x[0] for x in cert.get("issuer", []))
            tls["version"]        = cert.get("version")
            tls["serial"]         = cert.get("serialNumber")
            tls["not_before"]     = cert.get("notBefore")
            tls["not_after"]      = cert.get("notAfter")
            tls["protocol"]       = ssock.version()
            tls["cipher"]         = ssock.cipher()[0] if ssock.cipher() else "N/A"
            tls["alt_names"]      = [v for _, v in cert.get("subjectAltName", [])]
            exp = datetime.datetime.strptime(tls["not_after"], "%b %d %H:%M:%S %Y %Z")
            tls["days_to_expiry"] = (exp - datetime.datetime.utcnow()).days
    except ssl.SSLCertVerificationError as e:
        tls["error"] = f"Certificate verification failed: {e}"
    except Exception as e:
        tls["error"] = str(e)

    result.tls_info = tls
    progress.advance(task, 25)

# ─────────────────────────────────────────────────────────────────
# ░░  MODULE 4 — SMART DIRECTORY FUZZING  ░░  (unchanged from v1)
# ─────────────────────────────────────────────────────────────────

try:
    with open('words.txt', 'r') as _f:
        FUZZ_WORDLIST = [line.strip() for line in _f if line.strip()]
except FileNotFoundError:
    FUZZ_WORDLIST = [
        "/.git/config", "/.git/HEAD", "/.env", "/.env.local", "/.env.backup",
        "/.htaccess", "/.htpasswd", "/.DS_Store", "/robots.txt", "/sitemap.xml",
        "/admin", "/admin/", "/administrator", "/wp-admin", "/wp-login.php",
        "/wp-config.php", "/wp-config.php.bak", "/config.php", "/config.json",
        "/config.yaml", "/config.yml", "/settings.py", "/settings.json",
        "/phpinfo.php", "/info.php", "/test.php", "/debug.php",
        "/api", "/api/v1", "/api/v2", "/api/swagger", "/swagger.json",
        "/openapi.json", "/graphql", "/graphiql",
        "/backup", "/backup.zip", "/backup.tar.gz", "/dump.sql",
        "/.well-known/security.txt", "/.well-known/openid-configuration",
        "/server-status", "/server-info", "/.travis.yml", "/Dockerfile",
        "/docker-compose.yml", "/package.json", "/composer.json", "/Gemfile",
        "/web.config", "/crossdomain.xml", "/clientaccesspolicy.xml",
        "/actuator", "/actuator/health", "/actuator/env", "/actuator/mappings",
        "/console", "/h2-console", "/jenkins", "/jmx-console",
        "/phpmyadmin", "/pma", "/dbadmin", "/myadmin",
        "/login", "/logout", "/register", "/signup", "/forgot-password",
        "/reset-password", "/dashboard", "/panel", "/cpanel",
        "/static/", "/assets/", "/uploads/", "/files/", "/media/",
        "/logs/", "/log/", "/error_log", "/access_log",
        "/CHANGELOG.md", "/CHANGELOG.txt", "/README.md", "/LICENSE",
        "/WEB-INF/", "/WEB-INF/web.xml",
        "/application.properties", "/application.yml",
    ]

def _fuzz_single(base_url: str, path: str) -> Optional[dict]:
    url  = base_url.rstrip("/") + path
    resp = safe_get(url)
    if resp is None:
        return None
    code = resp.status_code
    if code in (200, 301, 302, 401, 403, 500):
        severity = "info"
        if code == 200:
            severity = "high" if any(kw in path for kw in [
                ".git", ".env", "config", "backup", "dump", "phpinfo", "actuator"
            ]) else "medium"
        elif code in (401, 403):
            severity = "low"
        return {
            "path": path, "url": url, "status": code,
            "size": len(resp.content),
            "content_type": resp.headers.get("Content-Type", ""),
            "severity": severity,
        }
    return None

def run_fuzzing(target_url: str, result: ScanResult, progress, task):
    findings = []
    total    = len(FUZZ_WORDLIST)
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(_fuzz_single, target_url, p): p for p in FUZZ_WORDLIST}
        done = 0
        for future in as_completed(futures):
            done += 1
            pct = int((done / total) * 50)
            progress.update(task, description=f"[cyan]Fuzz:[/cyan] {done}/{total} paths…", completed=pct)
            finding = future.result()
            if finding:
                findings.append(finding)
    rank = {"high": 0, "medium": 1, "low": 2, "info": 3}
    result.fuzzing = sorted(findings, key=lambda f: rank.get(f["severity"], 9))

# ─────────────────────────────────────────────────────────────────
# ░░  MODULE 5 — FORM & CSRF AUDIT  ░░  (unchanged from v1)
# ─────────────────────────────────────────────────────────────────

CSRF_TOKEN_NAMES = {
    "csrf", "csrftoken", "_token", "authenticity_token", "__requestverificationtoken",
    "xsrf", "anti-csrf", "_csrf_token", "csrf_token", "token",
}

def run_form_audit(target_url: str, result: ScanResult, progress, task):
    progress.update(task, description="[cyan]Forms:[/cyan] Scraping HTML…")
    resp        = safe_get(target_url)
    forms_found = []

    if resp is not None and resp.ok:
        soup = BeautifulSoup(resp.text, "html.parser")
        for i, form in enumerate(soup.find_all("form"), start=1):
            action   = form.get("action", "(current page)")
            method   = form.get("method", "GET").upper()
            inputs   = []
            has_csrf = False

            for inp in form.find_all(["input", "textarea", "select"]):
                name  = inp.get("name", "")
                itype = inp.get("type", inp.name)
                inputs.append({"name": name, "type": itype})
                if name.lower().replace("-","").replace("_","") in {
                    t.replace("-","").replace("_","") for t in CSRF_TOKEN_NAMES
                }:
                    has_csrf = True

            forms_found.append({
                "form_num": i,
                "action":   action,
                "method":   method,
                "inputs":   inputs,
                "has_csrf": has_csrf,
                "risk":     "low" if has_csrf else ("high" if method == "POST" else "medium"),
            })

    result.forms = forms_found
    progress.advance(task, 50)

# ─────────────────────────────────────────────────────────────────
# ░░  MODULE 6 — PORT SCAN  ░░  (extended: banner grabbing)
# ─────────────────────────────────────────────────────────────────

TOP_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    587: "SMTP-TLS", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "Oracle", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "Jupyter", 9200: "Elasticsearch", 27017: "MongoDB",
}

def _probe_port(host: str, port: int) -> Optional[dict]:
    """TCP connect + optional banner grab on text-based services."""
    try:
        s = socket.create_connection((host, port), timeout=2)
        banner = ""
        # Grab banner for services that push one immediately
        if port in (21, 22, 25, 110, 143, 587, 993, 995):
            try:
                s.settimeout(2)
                banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
            except Exception:
                pass
        elif port in (80, 8080, 8888):
            try:
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                s.settimeout(2)
                banner = s.recv(512).decode("utf-8", errors="ignore").strip()
            except Exception:
                pass
        s.close()
        return {"port": port, "service": TOP_PORTS.get(port, "?"), "state": "open", "banner": banner}
    except Exception:
        return None

def run_port_scan(hostname: str, result: ScanResult, progress, task):
    open_ports = []
    total      = len(TOP_PORTS)
    done       = 0
    banners    = {}

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(_probe_port, hostname, port): port for port in TOP_PORTS}
        for future in as_completed(futures):
            done += 1
            progress.update(
                task,
                description=f"[cyan]Ports:[/cyan] Scanning {done}/{total}…",
                completed=int((done / total) * 50),
            )
            res = future.result()
            if res:
                open_ports.append(res)
                if res["banner"]:
                    banners[res["port"]] = res["banner"]

    result.open_ports = sorted(open_ports, key=lambda p: p["port"])
    result.banners    = banners   # stored for CVE module

# ─────────────────────────────────────────────────────────────────
# ░░  MODULE 7 — OSINT INTELLIGENCE LAYER  ░░  ← NEW
# ─────────────────────────────────────────────────────────────────

def run_osint(target_url: str, hostname: str, result: ScanResult, progress, task):
    """
    Passive OSINT gathering:
      1. Have I Been Pwned — check breach data for domain emails
      2. ASN/BGP lookup   — map IP ranges owned by the organisation
      3. Wayback Machine  — find historically exposed endpoints
      4. GitHub dork hint — list potential GitHub search queries
    """

    # ── 1. Have I Been Pwned (domain breach check)
    progress.update(task, description="[cyan]OSINT:[/cyan] Checking breach database (HIBP)…")
    breach_info = {"domain_breach": [], "checked_emails": [], "api_note": ""}

    # HIBP v3 requires an API key for email lookups; domain search is available without one
    try:
        # Domain-level breach search (no key needed for domain endpoint)
        headers_hibp = {"User-Agent": "KENN-RECON-Pro/2.0"}
        if HIBP_API_KEY:
            headers_hibp["hibp-api-key"] = HIBP_API_KEY

        r = SESSION.get(
            f"https://haveibeenpwned.com/api/v3/breaches",
            headers=headers_hibp, timeout=TIMEOUT
        )
        if r.ok:
            all_breaches = r.json()
            # Filter breaches that exposed email data relevant to our domain
            # (HIBP doesn't expose per-domain queries without a paid key — we show top recent)
            breach_info["total_known_breaches"] = len(all_breaches)
            breach_info["api_note"] = (
                "Full per-domain email lookup requires HIBP API key (set HIBP_API_KEY env var). "
                "Showing global breach stats only."
            ) if not HIBP_API_KEY else "API key present — per-email lookup enabled."

            # With API key: check each plausible admin email
            if HIBP_API_KEY:
                checked = []
                for email in _extract_domain_emails(hostname):
                    try:
                        er = SESSION.get(
                            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                            headers=headers_hibp, timeout=TIMEOUT
                        )
                        if er.status_code == 200:
                            breaches = [b["Name"] for b in er.json()]
                            checked.append({"email": email, "breaches": breaches, "pwned": True})
                        elif er.status_code == 404:
                            checked.append({"email": email, "breaches": [], "pwned": False})
                    except Exception:
                        pass
                breach_info["checked_emails"] = checked
    except Exception as e:
        breach_info["error"] = str(e)

    result.osint_breach = breach_info
    progress.advance(task, 15)

    # ── 2. ASN / BGP — find IP ranges owned by the org
    progress.update(task, description="[cyan]OSINT:[/cyan] ASN/BGP lookup (ip-api + bgpview)…")
    asn_info = {}
    try:
        a_records = result.dns_records.get("A", [])
        ip = a_records[0] if a_records else ""
        if ip:
            # ip-api for basic AS info
            r = SESSION.get(f"http://ip-api.com/json/{ip}?fields=as,asname,org,isp", timeout=TIMEOUT)
            if r.ok:
                data = r.json()
                asn_info["as_number"] = data.get("as","")
                asn_info["as_name"]   = data.get("asname","")
                asn_info["org"]       = data.get("org","")

                # Extract raw ASN number for BGPView lookup
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
                        asn_info["ipv4_ranges"] = ipv4[:20]   # cap at 20
                        asn_info["ipv6_ranges"] = ipv6[:10]
                        asn_info["total_ipv4_ranges"] = len(ipv4)
    except Exception as e:
        asn_info["error"] = str(e)

    result.osint_asn = asn_info
    progress.advance(task, 15)

    # ── 3. Wayback Machine — find old/deleted endpoints
    progress.update(task, description="[cyan]OSINT:[/cyan] Wayback Machine historical scan…")
    wayback_urls = []
    try:
        # CDX API: get list of all snapshots for this domain, filtered to interesting paths
        cdx_url = (
            f"http://web.archive.org/cdx/search/cdx"
            f"?url={hostname}/*&output=json&fl=original&collapse=urlkey"
            f"&filter=statuscode:200&limit=200"
        )
        r = SESSION.get(cdx_url, timeout=15)
        if r.ok:
            rows = r.json()
            # rows[0] is the header row
            all_urls = [row[0] for row in rows[1:] if row]

            # Filter for potentially interesting historical endpoints
            interesting_patterns = [
                r"/api/", r"/admin", r"/config", r"/backup", r"\.env",
                r"/graphql", r"/swagger", r"/actuator", r"\.git",
                r"/login", r"/dashboard", r"/panel", r"/debug",
                r"/upload", r"/files", r"/docs", r"/internal",
            ]
            for url in all_urls:
                parsed_path = urllib.parse.urlparse(url).path.lower()
                for pat in interesting_patterns:
                    if re.search(pat, parsed_path):
                        wayback_urls.append(url)
                        break

            wayback_urls = list(set(wayback_urls))[:50]  # deduplicate, cap at 50
    except Exception as e:
        wayback_urls = [f"Error: {e}"]

    result.osint_wayback = wayback_urls
    progress.advance(task, 10)

    # ── 4. GitHub dork hints (passive — generate search queries, don't scrape GitHub)
    progress.update(task, description="[cyan]OSINT:[/cyan] Generating GitHub OSINT dorks…")
    github_dorks = [
        f'"{hostname}" password',
        f'"{hostname}" api_key OR secret OR token',
        f'"{hostname}" .env OR config',
        f'org:{hostname.split(".")[0]} filename:.env',
        f'"{hostname}" db_password OR database_url',
        f'"{hostname}" aws_access_key_id',
        f'site:github.com "{hostname}" secret',
    ]
    result.osint_github = github_dorks
    progress.advance(task, 10)

# ─────────────────────────────────────────────────────────────────
# ░░  MODULE 8 — CVE INTELLIGENCE  ░░  ← NEW
# ─────────────────────────────────────────────────────────────────

# CMS fingerprinting signatures
CMS_SIGNATURES = {
    "WordPress": {
        "paths":    ["/wp-login.php", "/wp-admin/", "/wp-content/", "/wp-includes/"],
        "headers":  {"x-powered-by": ""},
        "meta":     ["generator.*wordpress"],
        "body":     ["wp-content", "wp-includes", "WordPress"],
    },
    "Joomla": {
        "paths":    ["/administrator/", "/components/", "/modules/"],
        "meta":     ["generator.*joomla"],
        "body":     ["/components/com_", "Joomla"],
    },
    "Drupal": {
        "paths":    ["/sites/default/", "/modules/", "/themes/"],
        "headers":  {"x-generator": "drupal"},
        "meta":     ["generator.*drupal"],
        "body":     ["Drupal.settings", "/sites/all/"],
    },
    "Django": {
        "headers":  {"server": ""},
        "body":     ["csrfmiddlewaretoken", "__admin__"],
    },
    "Laravel": {
        "body":     ["laravel_session", "XSRF-TOKEN"],
        "headers":  {"set-cookie": "laravel"},
    },
    "Spring Boot": {
        "paths":    ["/actuator", "/actuator/health"],
        "headers":  {"x-application-context": ""},
    },
    "Next.js": {
        "headers":  {"x-powered-by": "next.js"},
        "body":     ["__NEXT_DATA__", "_next/static"],
    },
    "Nginx": {
        "headers":  {"server": "nginx"},
    },
    "Apache": {
        "headers":  {"server": "apache"},
    },
}

# Product → NVD CPE keyword mapping for CVE searches
PRODUCT_CPE_MAP = {
    "nginx":       "nginx",
    "apache":      "apache_http_server",
    "wordpress":   "wordpress",
    "joomla":      "joomla",
    "drupal":      "drupal",
    "django":      "django",
    "spring boot": "spring_boot",
    "openssl":     "openssl",
    "openssh":     "openssh",
    "mysql":       "mysql",
    "postgresql":  "postgresql",
    "redis":       "redis",
    "mongodb":     "mongodb",
    "elasticsearch": "elasticsearch",
}

# Regex patterns to extract version from banners
VERSION_PATTERNS = [
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
    """Extract product+version pairs from grabbed banners."""
    found = []
    for port, banner in banners.items():
        for pat in VERSION_PATTERNS:
            m = re.search(pat, banner)
            if m:
                product_match = re.search(r"(?i)(nginx|apache|openssh|openssl|mysql|redis|php|python|tomcat)", banner)
                product = product_match.group(1).lower() if product_match else "unknown"
                found.append({
                    "port":    port,
                    "product": product,
                    "version": m.group(1),
                    "banner":  banner[:200],
                })
    return found


def _lookup_nvd_cves(product: str, version: str) -> list[dict]:
    """
    Query NVD NIST API for CVEs matching a product/version.
    Returns list of {cve_id, cvss_v3, severity, description}.
    """
    cves = []
    keyword = PRODUCT_CPE_MAP.get(product.lower(), product.lower())

    try:
        # NVD 2.0 API — free, no key required (rate-limited to 5 req/30s without key)
        r = SESSION.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={
                "keywordSearch": f"{keyword} {version}",
                "resultsPerPage": 10,
                "startIndex":     0,
            },
            timeout=15,
            headers={"Accept": "application/json"},
        )
        if r.ok:
            data = r.json()
            for item in data.get("vulnerabilities", []):
                cve  = item.get("cve", {})
                cve_id  = cve.get("id", "")
                metrics = cve.get("metrics", {})
                cvss_v3 = (
                    metrics.get("cvssMetricV31", [{}])[0]
                    .get("cvssData", {})
                    .get("baseScore", None)
                ) or (
                    metrics.get("cvssMetricV30", [{}])[0]
                    .get("cvssData", {})
                    .get("baseScore", None)
                )
                severity = "UNKNOWN"
                if cvss_v3:
                    if cvss_v3 >= 9.0:   severity = "CRITICAL"
                    elif cvss_v3 >= 7.0: severity = "HIGH"
                    elif cvss_v3 >= 4.0: severity = "MEDIUM"
                    else:                severity = "LOW"

                desc_list = cve.get("descriptions", [])
                desc = next(
                    (d["value"] for d in desc_list if d.get("lang") == "en"),
                    "No description available"
                )
                cves.append({
                    "cve_id":      cve_id,
                    "product":     product,
                    "version":     version,
                    "cvss_v3":     cvss_v3,
                    "severity":    severity,
                    "description": desc[:300],
                })
    except Exception:
        pass
    return cves


def _fingerprint_cms(target_url: str, hostname: str, resp_body: str, headers_lower: dict) -> dict:
    """Detect CMS and guess version from response body/headers/paths."""
    detected = {}
    for cms, sigs in CMS_SIGNATURES.items():
        score = 0

        # Check body keywords
        for kw in sigs.get("body", []):
            if re.search(kw, resp_body, re.IGNORECASE):
                score += 2

        # Check meta generator tag
        for pat in sigs.get("meta", []):
            m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]*content=["\']([^"\']*)["\']',
                          resp_body, re.IGNORECASE)
            if m and re.search(pat, m.group(1), re.IGNORECASE):
                score += 3
                # Try to extract version from generator string
                ver_m = re.search(r"(\d+\.\d+\.?\d*)", m.group(1))
                if ver_m:
                    detected.setdefault(cms, {})["version"] = ver_m.group(1)

        # Check headers
        for h_key, h_val in sigs.get("headers", {}).items():
            if h_key in headers_lower:
                if h_val == "" or h_val.lower() in headers_lower[h_key].lower():
                    score += 2

        if score >= 2:
            detected.setdefault(cms, {})["confidence"] = min(100, score * 15)

    # Version extraction from server header
    srv = headers_lower.get("server", "")
    if srv:
        ver_m = re.search(r"(\d+\.\d+\.?\d*)", srv)
        if ver_m:
            for cms in detected:
                if cms.lower() in srv.lower():
                    detected[cms]["version"] = ver_m.group(1)
        # standalone server product
        product_m = re.search(r"^(\w+)", srv)
        if product_m:
            pname = product_m.group(1)
            detected.setdefault(pname, {})["confidence"] = 50
            if ver_m:
                detected[pname]["version"] = ver_m.group(1)

    return detected


def run_cve_intelligence(target_url: str, hostname: str, result: ScanResult, progress, task):
    """
    1. Parse banners grabbed by port scan → extract product+version
    2. Query NVD NIST API for matching CVEs
    3. Fingerprint CMS from target homepage
    """

    # ── Step 1: Parse banners from port scan
    progress.update(task, description="[cyan]CVE:[/cyan] Parsing service banners…")
    banner_products = _parse_banner_versions(result.banners)
    progress.advance(task, 10)

    # ── Step 2: Fetch target homepage for CMS fingerprinting
    progress.update(task, description="[cyan]CVE:[/cyan] CMS fingerprinting…")
    resp = safe_get(target_url)
    if resp is not None and resp.ok:
        body          = resp.text
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        cms_detected = _fingerprint_cms(target_url, hostname, body, headers_lower)
        result.cms_detected = cms_detected

        # Also extract server header product/version if not already bannerized
        srv = headers_lower.get("server", "")
        if srv:
            for pat in VERSION_PATTERNS:
                m = re.search(pat, srv)
                if m:
                    product_m = re.search(r"(?i)(nginx|apache|iis|lighttpd|gunicorn|uvicorn)", srv)
                    if product_m:
                        entry = {
                            "port":    443,
                            "product": product_m.group(1).lower(),
                            "version": m.group(1),
                            "banner":  srv,
                        }
                        # Avoid duplicates
                        if entry not in banner_products:
                            banner_products.append(entry)
    progress.advance(task, 10)

    # ── Step 3: CVE lookup for each discovered product/version pair
    progress.update(task, description="[cyan]CVE:[/cyan] Querying NVD/NIST database…")
    all_cves = []
    for bp in banner_products:
        cves = _lookup_nvd_cves(bp["product"], bp["version"])
        for cve in cves:
            cve["port"] = bp["port"]
        all_cves.extend(cves)
        time.sleep(0.7)   # NVD rate limit: ~5 req/30s without API key

    # Sort by CVSS score descending
    all_cves.sort(key=lambda c: (c.get("cvss_v3") or 0), reverse=True)
    result.cve_findings = all_cves[:30]   # cap at 30 CVEs
    progress.advance(task, 30)

# ─────────────────────────────────────────────────────────────────
# ░░  MODULE 9 — DEEP CRAWLER & SPIDER  ░░  ← NEW
# ─────────────────────────────────────────────────────────────────

# Regex to find API endpoint-like strings inside JS files
JS_API_PATTERNS = [
    r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|http\.(?:get|post))\s*\(["'`]([^"'`\s)]{5,100})["'`]""",
    r"""["'`](/api/[^\s"'`>)]{3,80})["'`]""",
    r"""["'`](/v\d+/[^\s"'`>)]{3,80})["'`]""",
    r"""["'`](/graphql[^\s"'`>)]{0,40})["'`]""",
    r"""["'`](/rest/[^\s"'`>)]{3,60})["'`]""",
    r"""endpoint\s*[:=]\s*["'`]([^"'`\s]{5,100})["'`]""",
    r"""url\s*[:=]\s*["'`]([/][^"'`\s]{3,80})["'`]""",
]

# Regex to find query parameters
PARAM_PATTERN = re.compile(r"[?&]([a-zA-Z_][a-zA-Z0-9_]{0,30})=")


def _is_internal(url: str, hostname: str) -> bool:
    """Check if a URL belongs to the same hostname."""
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.hostname is not None and (
            parsed.hostname == hostname or parsed.hostname.endswith("." + hostname)
        )
    except Exception:
        return False


def _normalise_url(url: str, base_url: str, hostname: str) -> Optional[str]:
    """Resolve relative URLs; return None if not internal or not HTTP(S)."""
    try:
        full = urllib.parse.urljoin(base_url, url)
        parsed = urllib.parse.urlparse(full)
        if parsed.scheme not in ("http", "https"):
            return None
        if not _is_internal(full, hostname):
            return None
        # Strip fragment
        return urllib.parse.urlunparse(parsed._replace(fragment=""))
    except Exception:
        return None


def _extract_links(html: str, base_url: str, hostname: str) -> set[str]:
    """Extract all internal links from an HTML page."""
    links = set()
    try:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all(["a", "link", "script", "form", "iframe", "frame"]):
            for attr in ("href", "src", "action"):
                raw = tag.get(attr)
                if raw:
                    norm = _normalise_url(raw, base_url, hostname)
                    if norm:
                        links.add(norm)
    except Exception:
        pass
    return links


def _extract_js_endpoints(js_text: str, base_url: str, hostname: str) -> list[str]:
    """Mine a JavaScript file for hidden API endpoint strings."""
    endpoints = []
    for pat in JS_API_PATTERNS:
        for m in re.finditer(pat, js_text):
            ep = m.group(1)
            # Skip obvious non-endpoints
            if len(ep) < 3 or ep.startswith("//") or "." in ep.split("/")[-1][-5:]:
                continue
            norm = _normalise_url(ep, base_url, hostname)
            if norm:
                endpoints.append(norm)
            elif ep.startswith("/"):
                endpoints.append(ep)   # keep as relative path
    return list(set(endpoints))


def _extract_params(url: str) -> list[str]:
    """Extract query parameter names from a URL."""
    parsed = urllib.parse.urlparse(url)
    return PARAM_PATTERN.findall(parsed.query)


def run_deep_crawler(target_url: str, hostname: str, result: ScanResult, progress, task,
                     max_pages: int = 80):
    """
    Recursive spider:
      - Follow all internal links up to max_pages
      - Extract JS files and mine API endpoints
      - Collect all query parameters for fuzzing hints
    """
    visited   = set()
    queue     = {target_url}
    sitemap   = []
    js_eps    = []
    params    = defaultdict(set)

    progress.update(task, description="[cyan]Spider:[/cyan] Starting recursive crawl…")

    while queue and len(visited) < max_pages:
        # Process up to 10 URLs in parallel per wave
        batch = list(queue - visited)[:10]
        queue -= set(batch)

        def _fetch_page(url: str):
            resp = safe_get(url)
            if resp is None or not resp.ok:
                return url, None, set(), []
            content_type = resp.headers.get("Content-Type", "")
            links = set()
            js_endpoints = []

            if "html" in content_type:
                links = _extract_links(resp.text, url, hostname)
                # Also look for <script src="..."> JS files
                soup = BeautifulSoup(resp.text, "html.parser")
                for script in soup.find_all("script", src=True):
                    js_url = _normalise_url(script["src"], url, hostname)
                    if js_url:
                        links.add(js_url)

            elif "javascript" in content_type:
                js_endpoints = _extract_js_endpoints(resp.text, url, hostname)

            return url, resp, links, js_endpoints

        with ThreadPoolExecutor(max_workers=5) as pool:
            futures = {pool.submit(_fetch_page, url): url for url in batch}
            for future in as_completed(futures):
                url, resp, links, js_endpoints_found = future.result()
                visited.add(url)

                if resp is not None:
                    sitemap.append(url)
                    url_params = _extract_params(url)
                    if url_params:
                        params[url].update(url_params)

                queue.update(links - visited)
                js_eps.extend(js_endpoints_found)

        done_pct = min(50, int((len(visited) / max_pages) * 50))
        progress.update(
            task,
            description=f"[cyan]Spider:[/cyan] {len(visited)}/{max_pages} pages · {len(js_eps)} JS endpoints…",
            completed=done_pct,
        )

    result.sitemap     = sorted(set(sitemap))
    result.js_endpoints = sorted(set(js_eps))
    result.parameters  = {url: sorted(p) for url, p in params.items()}

# ─────────────────────────────────────────────────────────────────
# ░░  SECURITY SCORE CALCULATOR  ░░  (extended for v2)
# ─────────────────────────────────────────────────────────────────

def calculate_score(result: ScanResult) -> int:
    score = 100

    # Security headers
    critical_headers = [
        "strict-transport-security", "content-security-policy",
        "x-content-type-options", "x-frame-options", "referrer-policy",
    ]
    for h in critical_headers:
        if not result.security_headers.get(h, {}).get("present"):
            score -= 5

    for h in ("x-powered-by",):
        if result.security_headers.get(h, {}).get("present"):
            score -= 3

    # TLS
    tls = result.tls_info
    if "error" in tls:
        score -= 15
    elif tls.get("days_to_expiry", 999) < 30:
        score -= 10
    elif tls.get("days_to_expiry", 999) < 7:
        score -= 20

    # Fuzzing hits
    for f in result.fuzzing:
        if f["severity"] == "high":   score -= 10
        elif f["severity"] == "medium": score -= 3

    # Dangerous ports
    dangerous_ports = {21, 23, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 27017}
    for p in result.open_ports:
        if p["port"] in dangerous_ports:
            score -= 5

    # Forms without CSRF
    for form in result.forms:
        if form["method"] == "POST" and not form["has_csrf"]:
            score -= 8

    # NEW: CVE findings — deduct by severity
    for cve in result.cve_findings:
        sev = cve.get("severity", "LOW")
        if sev == "CRITICAL": score -= 15
        elif sev == "HIGH":   score -= 8
        elif sev == "MEDIUM": score -= 3

    # NEW: Breach data
    if any(e.get("pwned") for e in result.osint_breach.get("checked_emails", [])):
        score -= 10

    # NEW: Wayback exposed endpoints
    if len(result.osint_wayback) > 10:
        score -= 5

    return max(0, min(100, score))

# ─────────────────────────────────────────────────────────────────
# ░░  RICH DISPLAY FUNCTIONS  ░░
# ─────────────────────────────────────────────────────────────────

def _severity_style(sev: str) -> str:
    return {"high": C["bad"], "medium": C["warn"], "low": C["ok"], "info": C["info"],
            "critical": "bold red", "unknown": "dim"}.get(sev.lower(), "white")

# ── v1 display functions (unchanged) ──

def display_recon(result: ScanResult):
    console.print(Rule(f"[{C['accent']}]🌐  RECON RESULTS[/{C['accent']}]", style="magenta"))
    whois = result.whois
    t = Table(title="WHOIS / RDAP Info", box=box.ROUNDED, border_style="cyan",
              show_header=True, header_style=C["head"])
    t.add_column("Field", style=C["info"], width=20)
    t.add_column("Value", style="white")
    for k, v in whois.items():
        if k == "ip_geo": continue
        val = ", ".join(v) if isinstance(v, list) else str(v)
        t.add_row(k.replace("_", " ").title(), val)
    if "ip_geo" in whois:
        geo = whois["ip_geo"]
        t.add_row("IP Location", f"{geo.get('city','?')}, {geo.get('regionName','?')}, {geo.get('country','?')}")
        t.add_row("ISP / Org",   f"{geo.get('isp','?')} — {geo.get('org','?')}")
    console.print(t)
    console.print()

    dns_t = Table(title="DNS Records", box=box.SIMPLE_HEAVY, border_style="blue", header_style=C["head"])
    dns_t.add_column("Type",    style=C["accent"], width=8)
    dns_t.add_column("Records", style="white")
    for rtype, records in result.dns_records.items():
        if records:
            dns_t.add_row(rtype, "\n".join(records))
    console.print(dns_t)
    console.print()

    if result.subdomains:
        sub_t = Table(title=f"Subdomains ({len(result.subdomains)} found via crt.sh)",
                      box=box.MINIMAL_DOUBLE_HEAD, border_style="cyan", header_style=C["head"])
        sub_t.add_column("Subdomain", style=C["warn"])
        for sub in result.subdomains[:30]:
            sub_t.add_row(sub)
        if len(result.subdomains) > 30:
            sub_t.add_row(f"… and {len(result.subdomains)-30} more")
        console.print(sub_t)
    else:
        console.print("[dim]No subdomains found via crt.sh.[/dim]")
    console.print()

def display_waf(result: ScanResult):
    console.print(Rule(f"[{C['accent']}]🛡️   WAF / CDN / SERVER DETECTION[/{C['accent']}]", style="magenta"))
    if result.waf_cdn:
        for provider, headers in result.waf_cdn.items():
            console.print(f"  [bold green]✓ DETECTED:[/bold green] [bold white]{provider}[/bold white]  "
                          f"[dim](matched: {', '.join(headers)})[/dim]")
    else:
        console.print("  [dim]No known WAF/CDN fingerprints detected.[/dim]")
    console.print()

    interesting = ["server", "x-powered-by", "via", "x-cache", "age",
                   "cf-ray", "x-amz-cf-id", "x-served-by"]
    hdr_t = Table(title="Notable HTTP Response Headers", box=box.ROUNDED,
                  border_style="blue", header_style=C["head"])
    hdr_t.add_column("Header", style=C["info"], width=30)
    hdr_t.add_column("Value",  style="white")
    for h in interesting:
        val = result.headers.get(h) or result.headers.get(h.title()) or result.headers.get(h.upper())
        if val:
            hdr_t.add_row(h, escape(str(val)))
    console.print(hdr_t)
    console.print()

def display_headers(result: ScanResult):
    console.print(Rule(f"[{C['accent']}]📋  SECURITY HEADER ANALYSIS[/{C['accent']}]", style="magenta"))
    t = Table(box=box.DOUBLE_EDGE, border_style="cyan", header_style=C["head"], show_lines=True)
    t.add_column("Header",       style=C["info"],    width=28)
    t.add_column("Short",        style=C["subtle"],  width=14)
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
        tls_t.add_row("Protocol",   tls.get("protocol","?"))
        tls_t.add_row("Cipher",     tls.get("cipher","?"))
        tls_t.add_row("Issued By",  tls.get("issuer",{}).get("organizationName","?"))
        tls_t.add_row("Valid From", tls.get("not_before","?"))
        tls_t.add_row("Expires",    tls.get("not_after","?"))
        tls_t.add_row("Days Left",  f"[{expiry_style}]{tls.get('days_to_expiry','?')} days[/{expiry_style}]")
        alt = ", ".join(tls.get("alt_names",[])[:6])
        tls_t.add_row("SAN Entries", escape(alt[:100]) if alt else "N/A")
        console.print(tls_t)
    console.print()

def display_fuzzing(result: ScanResult):
    console.print(Rule(f"[{C['accent']}]🔍  DIRECTORY / ENDPOINT FUZZING RESULTS[/{C['accent']}]", style="magenta"))
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

def display_forms(result: ScanResult):
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

        inp_t = Table(box=box.MINIMAL, border_style="dim", show_header=True, header_style=C["subtle"])
        inp_t.add_column("Input name", style=C["info"])
        inp_t.add_column("Type",       style="white")
        for inp in form["inputs"]:
            inp_t.add_row(escape(inp["name"] or "(no name)"), inp["type"])

        console.print(Panel(Text.from_markup(panel_content),
                            title=f"[bold]Form #{form['form_num']}[/bold]",
                            border_style=risk_style))
        console.print(inp_t)
        console.print()

def display_ports(result: ScanResult):
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
        banner_str = escape(p.get("banner","")[:40]) or "[dim]—[/dim]"
        t.add_row(str(p["port"]), p["service"], f"[{C['ok']}]OPEN[/{C['ok']}]",
                  banner_str, risk_str)
    console.print(t)
    console.print()

# ── NEW v2 display functions ──

def display_osint(result: ScanResult):
    console.print(Rule(f"[{C['accent']}]🧠  OSINT INTELLIGENCE LAYER[/{C['accent']}]", style="magenta"))

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
                pwned_str = f"[{C['bad']}]YES[/{C['bad']}]" if e["pwned"] else f"[{C['ok']}]No[/{C['ok']}]"
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
        asn_t.add_row("AS Number",  asn.get("as_number","—"))
        asn_t.add_row("AS Name",    asn.get("as_name","—"))
        asn_t.add_row("Org",        asn.get("org","—"))
        asn_t.add_row("IPv4 Ranges", f"{asn.get('total_ipv4_ranges','?')} total — "
                                      f"showing {len(asn.get('ipv4_ranges',[]))}")
        console.print(asn_t)
        if asn.get("ipv4_ranges"):
            rng_t = Table(box=box.MINIMAL, border_style="dim", header_style=C["subtle"])
            rng_t.add_column("IPv4 Prefix", style=C["warn"])
            for prefix in asn.get("ipv4_ranges",[])[:15]:
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


def display_cve(result: ScanResult):
    console.print(Rule(f"[{C['accent']}]🔬  CVE INTELLIGENCE LAYER[/{C['accent']}]", style="magenta"))

    # ── CMS Detection
    console.print(Rule("[bold]CMS / Framework Fingerprinting[/bold]", style="dim"))
    if result.cms_detected:
        cms_t = Table(box=box.ROUNDED, border_style="cyan", header_style=C["head"])
        cms_t.add_column("CMS / Platform",  style=C["info"],   width=20)
        cms_t.add_column("Version Detected", style="white",    width=18)
        cms_t.add_column("Confidence",       style=C["warn"],  width=14)
        for cms, info in result.cms_detected.items():
            conf_str = f"{info.get('confidence', '?')}%"
            ver_str  = info.get("version", "unknown")
            cms_t.add_row(cms, ver_str, conf_str)
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

    cve_t = Table(box=box.DOUBLE_EDGE, border_style="red", header_style=C["head"], show_lines=True)
    cve_t.add_column("CVE ID",     style=C["bad"],    width=16)
    cve_t.add_column("Product",    style=C["info"],   width=14)
    cve_t.add_column("Version",    style="white",     width=10)
    cve_t.add_column("CVSS v3",    width=10, justify="center")
    cve_t.add_column("Severity",   width=12, justify="center")
    cve_t.add_column("Port",       width=6,  justify="right")
    cve_t.add_column("Description", style=C["dim"])

    for cve in result.cve_findings:
        sev    = cve.get("severity","UNKNOWN")
        sev_st = _severity_style(sev)
        cvss   = str(cve.get("cvss_v3","?")) if cve.get("cvss_v3") else "?"
        cve_t.add_row(
            escape(cve["cve_id"]),
            escape(cve.get("product","?")),
            escape(cve.get("version","?")),
            cvss,
            f"[{sev_st}]{sev}[/{sev_st}]",
            str(cve.get("port","?")),
            escape(cve["description"][:100]),
        )
    console.print(cve_t)
    console.print()


def display_spider(result: ScanResult):
    console.print(Rule(f"[{C['accent']}]🕸️   DEEP CRAWLER RESULTS[/{C['accent']}]", style="magenta"))

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
        js_t.add_column(f"Endpoints found in JS files ({len(result.js_endpoints)} unique)", style=C["accent"])
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


def display_score(result: ScanResult):
    score = result.score
    if score >= 80:   colour, grade, emoji = "green",       "A", "🟢"
    elif score >= 60: colour, grade, emoji = "yellow",      "B", "🟡"
    elif score >= 40: colour, grade, emoji = "dark_orange", "C", "🟠"
    else:             colour, grade, emoji = "red",         "D", "🔴"

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

# ─────────────────────────────────────────────────────────────────
# ░░  EXPORT: JSON + MARKDOWN  ░░  (extended for v2)
# ─────────────────────────────────────────────────────────────────

def export_results(result: ScanResult, target: str):
    os.makedirs("reports", exist_ok=True)
    
    safe_name = (target.replace("https://","").replace("http://","")
                 .replace("/","_").replace(":","_"))
    ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    base = os.path.join("reports", f"{safe_name}_{ts}")

    # JSON
    json_path = f"{base}.json"
    with open(json_path, "w") as fh:
        json.dump(asdict(result), fh, indent=2, default=str)

    # Markdown
    md_path = f"{base}.md"
    with open(md_path, "w") as fh:
        fh.write(f"# KENN-RECON Pro v2.0 Report\n\n")
        fh.write(f"**Target:** {result.target}  \n")
        fh.write(f"**Timestamp:** {result.timestamp}  \n")
        fh.write(f"**Security Score:** {result.score}/100\n\n---\n\n")

        fh.write("## WHOIS\n\n| Field | Value |\n|---|---|\n")
        for k, v in result.whois.items():
            fh.write(f"| {k} | {v} |\n")

        fh.write(f"\n## Subdomains ({len(result.subdomains)} found)\n\n")
        for s in result.subdomains:
            fh.write(f"- `{s}`\n")

        fh.write("\n## WAF / CDN Detection\n\n")
        for p, h in result.waf_cdn.items():
            fh.write(f"- **{p}** (matched: {', '.join(h)})\n")

        fh.write("\n## Security Headers\n\n| Header | Present | Value |\n|---|---|---|\n")
        for hdr, info in result.security_headers.items():
            fh.write(f"| {hdr} | {'✓' if info['present'] else '✗'} | {info.get('value','')} |\n")

        fh.write("\n## TLS / SSL\n\n| Field | Value |\n|---|---|\n")
        for k, v in result.tls_info.items():
            fh.write(f"| {k} | {v} |\n")

        fh.write(f"\n## Fuzzing Results ({len(result.fuzzing)} findings)\n\n")
        if result.fuzzing:
            fh.write("| Severity | Status | Path |\n|---|---|---|\n")
            for f in result.fuzzing:
                fh.write(f"| {f['severity'].upper()} | {f['status']} | `{f['path']}` |\n")

        fh.write(f"\n## Forms ({len(result.forms)} found)\n\n")
        for form in result.forms:
            fh.write(f"### Form #{form['form_num']} — {form['method']} → {form['action']}\n")
            fh.write(f"- CSRF token: {'✓ Present' if form['has_csrf'] else '✗ Missing'}\n")
            fh.write(f"- Risk: {form['risk'].upper()}\n")
            fh.write(f"- Inputs: {', '.join(i['name'] for i in form['inputs'] if i['name'])}\n\n")

        fh.write(f"\n## Open Ports ({len(result.open_ports)} found)\n\n")
        if result.open_ports:
            fh.write("| Port | Service | Banner | Note |\n|---|---|---|---|\n")
            dangerous_ports = {21,23,1433,3306,3389,5432,5900,6379,9200,27017}
            for p in result.open_ports:
                note = "⚠ Dangerous" if p["port"] in dangerous_ports else "OK"
                fh.write(f"| {p['port']} | {p['service']} | {p.get('banner','')[:60]} | {note} |\n")

        # ── v2 sections
        fh.write("\n## OSINT Intelligence\n\n")
        fh.write(f"### ASN\n\n")
        for k, v in result.osint_asn.items():
            fh.write(f"- **{k}**: {v}\n")

        fh.write(f"\n### Wayback Machine ({len(result.osint_wayback)} interesting URLs)\n\n")
        for url in result.osint_wayback:
            fh.write(f"- {url}\n")

        fh.write("\n### GitHub OSINT Dorks\n\n")
        for dork in result.osint_github:
            fh.write(f"- `{dork}`\n")

        fh.write(f"\n## CVE Intelligence\n\n### CMS / Framework Detection\n\n")
        for cms, info in result.cms_detected.items():
            fh.write(f"- **{cms}** — version: {info.get('version','?')} "
                     f"(confidence: {info.get('confidence','?')}%)\n")

        fh.write(f"\n### CVE Findings ({len(result.cve_findings)} matched)\n\n")
        if result.cve_findings:
            fh.write("| CVE ID | Product | Version | CVSS v3 | Severity | Port |\n|---|---|---|---|---|---|\n")
            for cve in result.cve_findings:
                fh.write(f"| {cve['cve_id']} | {cve['product']} | {cve['version']} | "
                         f"{cve.get('cvss_v3','?')} | {cve['severity']} | {cve.get('port','?')} |\n")

        fh.write(f"\n## Deep Crawler\n\n")
        fh.write(f"### Sitemap ({len(result.sitemap)} URLs)\n\n")
        for url in result.sitemap:
            fh.write(f"- {url}\n")

        fh.write(f"\n### JS-Discovered API Endpoints ({len(result.js_endpoints)})\n\n")
        for ep in result.js_endpoints:
            fh.write(f"- `{ep}`\n")

        fh.write(f"\n### Query Parameters Mined\n\n")
        for url, parms in result.parameters.items():
            fh.write(f"- **{url}** → {', '.join(parms)}\n")

    return json_path, md_path

# ─────────────────────────────────────────────────────────────────
# ░░  MAIN ORCHESTRATOR  ░░
# ─────────────────────────────────────────────────────────────────

def run_scan(target_raw: str, modules: list[str]):
    target_url, hostname = normalise_target(target_raw)

    result           = ScanResult()
    result.target    = target_url
    result.timestamp = datetime.datetime.now().isoformat()

    console.print()
    console.print(Panel(
        f"[bold white]Target :[/bold white] [cyan]{target_url}[/cyan]\n"
        f"[bold white]Host   :[/bold white] [cyan]{hostname}[/cyan]\n"
        f"[bold white]Modules:[/bold white] [yellow]{', '.join(modules)}[/yellow]",
        title="[bold magenta]Scan Configuration[/bold magenta]",
        border_style="magenta",
    ))
    console.print()

    MODULE_MAP = {
        "recon":   ("Auto Recon",       50, lambda p, t: run_recon(target_url, hostname, result, p, t)),
        "waf":     ("WAF Detection",    50, lambda p, t: run_waf_detection(target_url, result, p, t)),
        "headers": ("Header & TLS",     50, lambda p, t: run_header_analysis(target_url, hostname, result, p, t)),
        "fuzz":    ("Directory Fuzz",   50, lambda p, t: run_fuzzing(target_url, result, p, t)),
        "forms":   ("Form Audit",       50, lambda p, t: run_form_audit(target_url, result, p, t)),
        "ports":   ("Port Scan",        50, lambda p, t: run_port_scan(hostname, result, p, t)),
        # ── v2 new modules
        "osint":   ("OSINT Layer",      50, lambda p, t: run_osint(target_url, hostname, result, p, t)),
        "cve":     ("CVE Intelligence", 50, lambda p, t: run_cve_intelligence(target_url, hostname, result, p, t)),
        "spider":  ("Deep Crawler",     50, lambda p, t: run_deep_crawler(target_url, hostname, result, p, t)),
    }

    with Progress(
        SpinnerColumn(spinner_name="dots12", style="cyan"),
        TextColumn("[progress.description]{task.description}", style="white"),
        BarColumn(bar_width=35, style="cyan", complete_style="bold green"),
        TaskProgressColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        for mod_key in modules:
            if mod_key not in MODULE_MAP:
                continue
            name, total, runner = MODULE_MAP[mod_key]
            task = progress.add_task(f"[cyan]{name}[/cyan]", total=total)
            try:
                runner(progress, task)
                progress.update(task, completed=total,
                                description=f"[green]✓ {name} complete[/green]")
            except Exception as exc:
                progress.update(task, description=f"[red]✗ {name} failed: {exc}[/red]")

    result.score = calculate_score(result)

    console.print()
    console.print(Rule("[bold cyan]═══  SCAN RESULTS  ═══[/bold cyan]", style="cyan"))

    if "recon"   in modules: display_recon(result)
    if "waf"     in modules: display_waf(result)
    if "headers" in modules: display_headers(result)
    if "fuzz"    in modules: display_fuzzing(result)
    if "forms"   in modules: display_forms(result)
    if "ports"   in modules: display_ports(result)
    if "osint"   in modules: display_osint(result)
    if "cve"     in modules: display_cve(result)
    if "spider"  in modules: display_spider(result)

    display_score(result)

    console.print(Rule("[bold]Exporting Reports[/bold]", style="dim"))
    try:
        json_path, md_path = export_results(result, target_raw)
        console.print(f"  [{C['ok']}]✓ JSON report:[/{C['ok']}]     [cyan]{json_path}[/cyan]")
        console.print(f"  [{C['ok']}]✓ Markdown report:[/{C['ok']}] [cyan]{md_path}[/cyan]")
    except Exception as e:
        console.print(f"  [{C['bad']}]Export failed: {e}[/{C['bad']}]")

    console.print()
    console.print(Rule("[dim]KENN-RECON Pro v2.0 — Scan Complete[/dim]", style="dim"))
    console.print()

# ─────────────────────────────────────────────────────────────────
# ░░  ENTRY POINT  ░░
# ─────────────────────────────────────────────────────────────────

def interactive_main():
    if sys.platform == "win32":
        console.print("[yellow]⚠  Windows detected. For best TUI experience, use WSL or Linux.[/yellow]")

    show_banner()

    console.print(Panel(
        "[bold yellow]⚠  LEGAL DISCLAIMER[/bold yellow]\n\n"
        "This tool is for [bold]authorized security testing ONLY[/bold].\n"
        "You must have [bold]explicit written permission[/bold] from the target owner.\n"
        "Unauthorized scanning may violate local and international law.\n"
        "By continuing, you confirm you have the necessary authorization.",
        border_style="yellow",
        expand=False,
    ))
    console.print()

    agreed = Confirm.ask("[bold yellow]Do you have explicit authorization to scan the target?[/bold yellow]")
    if not agreed:
        console.print("[bold red]Aborted. Always obtain proper authorization before scanning.[/bold red]")
        sys.exit(0)

    # Optional: warn if API keys missing
    missing_keys = []
    if not HIBP_API_KEY:
        missing_keys.append("HIBP_API_KEY (for full HaveIBeenPwned email lookup)")
    if not SHODAN_API_KEY:
        missing_keys.append("SHODAN_API_KEY (reserved for future Shodan integration)")
    if missing_keys:
        console.print(Panel(
            "[bold yellow]Optional API Keys Not Set:[/bold yellow]\n"
            + "\n".join(f"  • {k}" for k in missing_keys)
            + "\n\n[dim]Set these as env vars to unlock full OSINT capability.[/dim]",
            border_style="dim yellow",
            expand=False,
        ))
        console.print()

    target, modules = interactive_menu()
    console.print()
    run_scan(target, modules)


def _build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="KENN-RECON Pro v2.0 — Advanced Recon & Security Auditor"
    )
    sub = parser.add_subparsers(dest="command")

    interactive = sub.add_parser("interactive", help="Run interactive scanner UI")
    interactive.set_defaults(command="interactive")

    phase01 = sub.add_parser("phase01", help="Run enterprise phase 0/1 passive recon")
    phase01.add_argument("target", help="Target domain or URL")
    phase01.add_argument("--out", default="phase01_output.json", help="Output JSON path")
    phase01.set_defaults(command="phase01")

    # ── new: quick CLI flag to run specific v2 modules non-interactively
    quick = sub.add_parser("quick", help="Quick non-interactive scan")
    quick.add_argument("target", help="Target domain or URL")
    quick.add_argument(
        "--modules", "-m",
        default="recon,waf,headers,ports,osint,cve,spider",
        help="Comma-separated module list (default: all)"
    )
    quick.add_argument("--rps", type=float, default=5.0, help="Requests per second (default 5)")
    quick.set_defaults(command="quick")

    return parser


def main() -> None:
    parser = _build_cli_parser()
    args   = parser.parse_args()
    command = args.command or "interactive"

    if command == "interactive":
        interactive_main()
        return

    if command == "phase01":
        from pentest.runners.phase01 import run as run_phase01
        output   = run_phase01(args.target, mode="passive")
        out_path = Path(args.out)
        out_path.write_text(json.dumps(output.to_dict(), indent=2), encoding="utf-8")
        console.print(f"[bold green]Phase01 complete[/bold green] target={output.target}")
        console.print(f"[bold cyan]Saved:[/bold cyan] {out_path}")
        return

    if command == "quick":
        rate_limiter.delay = 1.0 / args.rps
        modules = [m.strip() for m in args.modules.split(",") if m.strip()]
        run_scan(args.target, modules)
        return

    parser.print_help()

if __name__ == "__main__":
    main()