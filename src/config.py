"""
src/config.py — Shared globals config
"""

import os
import threading
import time
import random

import requests
import urllib3
from rich.console import Console

# ─────────────────────────────────────────────────────────────────
# Rich console
# ─────────────────────────────────────────────────────────────────
console = Console(highlight=False)

# ─────────────────────────────────────────────────────────────────
# Colour palette
# ─────────────────────────────────────────────────────────────────
C = {
    "banner":  "bold cyan",
    "accent":  "bold magenta",
    "ok":      "bold green",
    "warn":    "bold yellow",
    "bad":     "bold red",
    "info":    "bold blue",
    "dim":     "dim white",
    "head":    "bold white",
    "subtle":  "grey62",
}

# ─────────────────────────────────────────────────────────────────
# Rate-limiter : Token-bucket with Heuristic JITTER (Anti-Ban)
# ─────────────────────────────────────────────────────────────────
class RateLimiter:
    """Rate limiter with random delay (jitter) so you don't get caught as a bot."""

    def __init__(self, rps: float = 5.0, use_jitter: bool = True):
        self.base_delay = 1.0 / rps
        self.use_jitter = use_jitter
        self._lock = threading.Lock()
        self._last = time.monotonic()

    def wait(self):
        with self._lock:
            now = time.monotonic()
            
            # 🔥 JITTER ENGINE: Random delay from -50% to +50% of base_delay
            actual_delay = self.base_delay
            if self.use_jitter:
                actual_delay = self.base_delay * random.uniform(0.5, 1.5)
                
            gap = self._last + actual_delay - now
            if gap > 0:
                time.sleep(gap)
            self._last = time.monotonic()

# Global rate-limiter
rate_limiter = RateLimiter(rps=5.0, use_jitter=True)

# ─────────────────────────────────────────────────────────────────
# Stealth HTTP Session (Rotate User-Agent & IP)
# ─────────────────────────────────────────────────────────────────
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Popular browser User-Agents collection (Update 2026)
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Android 14; Mobile; rv:124.0) Gecko/124.0 Firefox/124.0",
]

class StealthSession(requests.Session):
    """Override default requests session so every shot has random headers!"""
    def request(self, method, url, **kwargs):
        headers = kwargs.get('headers', {})
        
        # 1. Rotate User Agent
        headers['User-Agent'] = random.choice(USER_AGENTS)
        
        # 2. Camouflage IP (Manipulate Forwarded Headers so WAF confused)
        fake_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        headers['X-Forwarded-For'] = fake_ip
        headers['X-Real-IP'] = fake_ip
        
        kwargs['headers'] = headers
        return super().request(method, url, **kwargs)

# Initialize Stealth Session
SESSION = StealthSession()
SESSION.headers.update({
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,id;q=0.8",
    "Upgrade-Insecure-Requests": "1",
})
SESSION.verify = False   # TLS errors are findings, not blockers

TIMEOUT = 8   # seconds per HTTP request

# ─────────────────────────────────────────────────────────────────
# Optional API keys
# ─────────────────────────────────────────────────────────────────
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")
HIBP_API_KEY   = os.environ.get("HIBP_API_KEY",   "")   # required for HIBP v3

# ─────────────────────────────────────────────────────────────────
# Scan module registry (key → display label)
# ─────────────────────────────────────────────────────────────────
SCAN_MODULES = [
    ("cve",     "CVE Intelligence     — Banner grab · NVD lookup · CMS fingerprint"),
    ("forms",   "Form & CSRF Audit    — Map inputs, detect missing CSRF tokens"),
    ("fuzzing", "Smart Directory Fuzz — Exposed endpoints scanner (rate-limited)"),
    ("headers", "Header Analysis      — Security headers · TLS/SSL certificate"),
    ("nuclei",  "Nuclei Scanner       — Full vulnerability wrapper (slow but brutal)"),
    ("osint",   "OSINT Intelligence   — HaveIBeenPwned · ASN/BGP · Wayback · GitHub"),
    ("ports",   "Port Scan            — Safe scan of top 25 common ports"),
    ("recon",   "Auto Recon           — WHOIS · Subdomains · DNS · IP Routing"),
    ("spider",  "Deep Crawler         — Recursive spider · JS endpoints · Param mining"),
    ("waf",     "WAF / CDN Detection  — Fingerprint protective layers"),
]