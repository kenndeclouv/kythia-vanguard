"""
src/modules/fuzzing.py — Module 4: Smart directory / endpoint fuzzing.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from src.config import rate_limiter, SESSION, TIMEOUT
from src.models import ScanResult

# ── Wordlist: load from file or fall back to a built-in set
try:
    with open("words.txt") as _f:
        FUZZ_WORDLIST: list[str] = [line.strip() for line in _f if line.strip()]
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

_HIGH_SEVERITY_KEYWORDS = {".git", ".env", "config", "backup", "dump", "phpinfo", "actuator"}


def _fuzz_single(base_url: str, path: str) -> Optional[dict]:
    url = base_url.rstrip("/") + path
    rate_limiter.wait()
    try:
        resp = SESSION.get(url, timeout=TIMEOUT, allow_redirects=True)
    except Exception:
        return None

    code = resp.status_code
    if code not in (200, 301, 302, 401, 403, 500):
        return None

    severity = "info"
    if code == 200:
        severity = "high" if any(kw in path for kw in _HIGH_SEVERITY_KEYWORDS) else "medium"
    elif code in (401, 403):
        severity = "low"

    return {
        "path":         path,
        "url":          url,
        "status":       code,
        "size":         len(resp.content),
        "content_type": resp.headers.get("Content-Type", ""),
        "severity":     severity,
    }


def run_fuzzing(target_url: str, result: ScanResult, progress, task) -> None:
    findings: list[dict] = []
    total = len(FUZZ_WORDLIST)

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(_fuzz_single, target_url, p): p for p in FUZZ_WORDLIST}
        done = 0
        for future in as_completed(futures):
            done += 1
            pct = int((done / total) * 50)
            progress.update(task,
                            description=f"[cyan]Fuzz:[/cyan] {done}/{total} paths…",
                            completed=pct)
            finding = future.result()
            if finding:
                findings.append(finding)

    rank = {"high": 0, "medium": 1, "low": 2, "info": 3}
    result.fuzzing = sorted(findings, key=lambda f: rank.get(f["severity"], 9))
