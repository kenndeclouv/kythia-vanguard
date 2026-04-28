"""
src/modules/spider.py — Deep Crawler + Secret Hunter (v2, high-speed).

Architecture: Pipeline-based concurrent crawl.
  - One persistent ThreadPoolExecutor (no per-batch creation overhead)
  - Spider-specific rate limiter (25 RPS) — separate from global 5 RPS
  - Producer-consumer queue: workers submit new URLs immediately as they land,
    no idle waiting for a full batch to finish
  - URL pre-filter: skip known static extensions before touching the network
  - Response cap: 512 KB HTML, 1 MB JS (was 5 MB flat)
  - BeautifulSoup parse only once per page (was calling it twice)
  - Hard wall-clock timeout: aborts cleanly after MAX_SECONDS seconds
"""

from __future__ import annotations

import re
import threading
import time
import urllib.parse
from collections import defaultdict
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Optional

from bs4 import BeautifulSoup
from rich import box
from rich.markup import escape
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

from src.config import RateLimiter, SESSION, TIMEOUT, C, console
from src.models import ScanResult
from src.scoring import score_and_report

# ─────────────────────────────────────────────────────────────────
# Spider-specific settings (intentionally more aggressive than global)
# ─────────────────────────────────────────────────────────────────

_SPIDER_RPS: float = 25.0  # requests per second ceiling
_MAX_WORKERS: int = 25  # concurrent threads
_MAX_PAGES: int = 120  # hard page cap
_MAX_SECONDS: int = 90  # wall-clock abort (seconds)
_HTML_CAP: int = 512_000  # 512 KB cap for HTML responses
_JS_CAP: int = 1_000_000  # 1 MB cap for JS responses
_REQUEST_TIMEOUT: int = 6  # per-request timeout (tighter than global 8 s)

# Spider gets its own rate limiter — doesn't pollute the global 5 RPS bucket
_spider_rl = RateLimiter(rps=_SPIDER_RPS, use_jitter=False)

# ─────────────────────────────────────────────────────────────────
# Static-asset pre-filter  (skip before touching the network)
# ─────────────────────────────────────────────────────────────────

_SKIP_EXTENSIONS = frozenset(
    [
        # Media
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".avif",
        ".ico",
        ".svg",
        ".mp4",
        ".webm",
        ".ogg",
        ".mp3",
        ".wav",
        # Documents / archives
        ".pdf",
        ".zip",
        ".tar",
        ".gz",
        ".rar",
        ".7z",
        ".dmg",
        ".exe",
        # Fonts
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".otf",
        # Data / compiled
        ".xml",
        ".rss",
        ".atom",
        ".swf",
        ".apk",
        ".ipa",
        # Stylesheets (no links/endpoints inside worth crawling)
        ".css",
    ]
)

# Content-type fragments to bail on immediately after headers arrive
_SKIP_CONTENT_TYPES = (
    "image/",
    "video/",
    "audio/",
    "font/",
    "application/zip",
    "application/pdf",
    "application/octet-stream",
    "application/x-tar",
    "application/gzip",
)

# ─────────────────────────────────────────────────────────────────
# Compiled regex patterns
# ─────────────────────────────────────────────────────────────────

_PARAM_PATTERN = re.compile(r"[?&]([a-zA-Z_][a-zA-Z0-9_]{0,30})=")

_JS_API_PATTERNS = [
    re.compile(p)
    for p in [
        r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|http\.(?:get|post))\s*\(["'`]([^"'`\s)]{5,100})["'`]""",
        r"""["'`](/api/[^\s"'`>)]{3,80})["'`]""",
        r"""["'`](/v\d+/[^\s"'`>)]{3,80})["'`]""",
        r"""["'`](/graphql[^\s"'`>)]{0,40})["'`]""",
        r"""["'`](/rest/[^\s"'`>)]{3,60})["'`]""",
        r"""["'`](/admin[^\s"'`>)]{0,60})["'`]""",
        r"""endpoint\s*[:=]\s*["'`]([^"'`\s]{5,100})["'`]""",
        r"""(?:url|path|route|href)\s*[:=]\s*["'`]([/][^"'`\s]{3,80})["'`]""",
        r"""["'`](https?://[^\s"'`>)]{10,120})["'`]""",
    ]
]

_SECRET_PATTERNS: dict[str, re.Pattern] = {
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS Secret Key": re.compile(
        r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"
    ),
    "Stripe Secret": re.compile(r"sk_live_[0-9a-zA-Z]{24}"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "GitHub Token": re.compile(r"ghp_[0-9a-zA-Z]{36}"),
    "GitHub OAuth": re.compile(r"gho_[0-9a-zA-Z]{36}"),
    "RSA Private Key": re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----"),
    "JWT Token": re.compile(
        r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"
    ),
    "Firebase URL": re.compile(r"https://[a-zA-Z0-9\-]+\.firebaseio\.com"),
    "Heroku API Key": re.compile(
        r"(?i)heroku.{0,30}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    ),
    "Mailgun API Key": re.compile(r"key-[0-9a-zA-Z]{32}"),
    "Twilio Account SID": re.compile(r"AC[0-9a-zA-Z]{32}"),
}

# ─────────────────────────────────────────────────────────────────
# URL helpers
# ─────────────────────────────────────────────────────────────────


def _is_internal(parsed_hostname: str | None, hostname: str) -> bool:
    if not parsed_hostname:
        return False
    return parsed_hostname == hostname or parsed_hostname.endswith("." + hostname)


def _normalise(raw: str, base: str, hostname: str) -> Optional[str]:
    """Resolve and validate a URL. Returns None if external or non-http(s)."""
    try:
        full = urllib.parse.urljoin(base, raw)
        p = urllib.parse.urlparse(full)
        if p.scheme not in ("http", "https"):
            return None
        if not _is_internal(p.hostname, hostname):
            return None
        # Drop fragment, normalise trailing slash
        return urllib.parse.urlunparse(p._replace(fragment=""))
    except Exception:
        return None


def _should_skip_url(url: str) -> bool:
    """True if the URL points to a static asset we never need to fetch."""
    try:
        path = urllib.parse.urlparse(url).path.lower()
        ext = "." + path.rsplit(".", 1)[-1] if "." in path else ""
        return ext in _SKIP_EXTENSIONS
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────
# Content extractors
# ─────────────────────────────────────────────────────────────────


def _extract_links_fast(html: str, base_url: str, hostname: str) -> set[str]:
    """Single BeautifulSoup parse — returns all internal URLs found in the page."""
    links: set[str] = set()
    try:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all(["a", "link", "script", "form", "iframe", "frame"]):
            for attr in ("href", "src", "action", "data-href", "data-url"):
                raw = tag.get(attr)
                if not raw or not isinstance(raw, str):
                    continue
                norm = _normalise(raw, base_url, hostname)
                if norm and not _should_skip_url(norm):
                    links.add(norm)
    except Exception:
        pass
    return links


def _extract_js_endpoints(js_text: str, base_url: str, hostname: str) -> list[str]:
    endpoints: set[str] = set()
    for pat in _JS_API_PATTERNS:
        for m in pat.finditer(js_text):
            ep = m.group(1)
            if len(ep) < 3 or ep.startswith("//"):
                continue
            # Skip strings that look like file paths with extensions (e.g. image.png)
            last_seg = ep.rsplit("/", 1)[-1]
            if "." in last_seg and last_seg.rsplit(".", 1)[-1].lower() in {
                "png",
                "jpg",
                "gif",
                "css",
                "ico",
                "woff",
                "ttf",
            }:
                continue
            norm = _normalise(ep, base_url, hostname)
            if norm:
                endpoints.add(norm)
            elif ep.startswith("/"):
                endpoints.add(ep)
    return list(endpoints)


def _check_secrets(text: str, url: str, progress) -> None:
    """Scan a block of text for leaked credentials and print an alert."""
    for name, pat in _SECRET_PATTERNS.items():
        m = pat.search(text)
        if m:
            # snippet = m.group(0)[:12] + "…[REDACTED]"
            progress.console.print(
                Panel(
                    f"[bold red]LEAKED SECRET DETECTED![/bold red]\n"
                    f"URL  : [cyan]{url}[/cyan]\n"
                    f"Type : [yellow]{name}[/yellow]\n"
                    f"Value: {m.group(0)}",
                    title="🔑 SECRET HUNTER",
                    border_style="red",
                )
            )


# ─────────────────────────────────────────────────────────────────
# Core fetch worker
# ─────────────────────────────────────────────────────────────────


def _fetch(url: str, hostname: str, progress) -> tuple[str, bool, set[str], list[str]]:
    """
    Fetch one URL, return:
      (url, success, new_links, js_endpoints_found)
    """
    _spider_rl.wait()
    try:
        resp = SESSION.get(
            url,
            timeout=_REQUEST_TIMEOUT,
            allow_redirects=True,
            stream=True,
        )
    except Exception:
        return url, False, set(), []

    try:
        ct = resp.headers.get("Content-Type", "").lower()

        # Bail immediately on binary content
        if any(ct.startswith(skip) for skip in _SKIP_CONTENT_TYPES):
            resp.close()
            return url, False, set(), []

        is_html = "html" in ct
        is_js = "javascript" in ct or "ecmascript" in ct

        if not (is_html or is_js):
            # Only crawl html + js
            resp.close()
            return url, False, set(), []

        cap = _HTML_CAP if is_html else _JS_CAP
        raw = resp.raw.read(cap, decode_content=True)
        text = raw.decode("utf-8", errors="ignore")
    except Exception:
        return url, False, set(), []
    finally:
        resp.close()

    # Secret scan (HTML + JS)
    _check_secrets(text, url, progress)

    new_links: set[str] = set()
    js_eps: list[str] = []

    if is_html:
        new_links = _extract_links_fast(text, url, hostname)
    elif is_js:
        js_eps = _extract_js_endpoints(text, url, hostname)

    return url, True, new_links, js_eps


# ─────────────────────────────────────────────────────────────────
# Module entry point
# ─────────────────────────────────────────────────────────────────


def run_spider(
    target_url: str,
    hostname: str,
    result: ScanResult,
    progress,
    task,
) -> None:
    """
    Pipeline-based deep crawler.

    Instead of processing fixed batches and waiting, we keep a persistent
    thread pool alive and immediately re-submit discovered URLs as futures —
    workers are never idle waiting for a batch boundary.
    """
    visited: set[str] = set()
    queued: set[str] = {target_url}
    sitemap: list[str] = []
    js_eps: set[str] = set()
    params: defaultdict[str, set[str]] = defaultdict(set)

    lock = threading.Lock()
    pending_futures: set[Future] = set()

    deadline = time.monotonic() + _MAX_SECONDS

    progress.update(
        task,
        description=f"[cyan]Spider:[/cyan] Launching pipeline ({_MAX_WORKERS} workers, {_SPIDER_RPS:.0f} RPS)…",
    )

    if getattr(result, "is_ip", False):
        progress.console.print(
            f"  [{C['warn']}]⚠ Spider: Scanning direct IP! This may hit a virtual host default page.[/{C['warn']}]"
        )

    def _handle_result(fut: Future) -> None:
        """Callback: process result and enqueue newly discovered URLs."""
        nonlocal queued
        try:
            url, ok, new_links, new_eps = fut.result()
        except Exception:
            return

        with lock:
            if ok:
                sitemap.append(url)
                url_params = _PARAM_PATTERN.findall(urllib.parse.urlparse(url).query)
                if url_params:
                    params[url].update(url_params)
            js_eps.update(new_eps)

            # Enqueue new internal links immediately (pipeline!)
            if time.monotonic() < deadline:
                for link in new_links:
                    if (
                        link not in visited
                        and link not in queued
                        and not _should_skip_url(link)
                    ):
                        if len(visited) + len(queued) < _MAX_PAGES * 2:
                            queued.add(link)

    with ThreadPoolExecutor(
        max_workers=_MAX_WORKERS, thread_name_prefix="spider"
    ) as pool:
        # Seed the pool with the first URL
        with lock:
            first = queued.pop()
            visited.add(first)
            fut = pool.submit(_fetch, first, hostname, progress)
            pending_futures.add(fut)
            fut.add_done_callback(lambda f: pending_futures.discard(f))
            fut.add_done_callback(_handle_result)

        while True:
            # Check hard limits
            if time.monotonic() >= deadline:
                progress.console.print(
                    f"  [{C['warn']}]⏱ Spider: wall-clock limit ({_MAX_SECONDS}s) reached — "
                    f"{len(visited)} pages crawled.[/{C['warn']}]"
                )
                break

            if len(visited) >= _MAX_PAGES:
                break

            # Submit all pending queued URLs
            with lock:
                to_submit = list(queued - visited)
                queued -= set(to_submit)
                for url in to_submit:
                    if len(visited) >= _MAX_PAGES:
                        break
                    visited.add(url)
                    fut = pool.submit(_fetch, url, hostname, progress)
                    pending_futures.add(fut)
                    fut.add_done_callback(lambda f: pending_futures.discard(f))
                    fut.add_done_callback(_handle_result)

            # Update progress
            done = len(sitemap)
            pct = min(50, int((done / _MAX_PAGES) * 50))
            progress.update(
                task,
                description=(
                    f"[cyan]Spider:[/cyan] {done}/{_MAX_PAGES} pages "
                    f"· {len(js_eps)} JS endpoints "
                    f"· {len(queued)} queued…"
                ),
                completed=pct,
            )

            # If nothing in flight and nothing queued, we're done
            with lock:
                nothing_queued = len(queued) == 0
            if nothing_queued and len(pending_futures) == 0:
                break

            time.sleep(0.05)  # Tiny poll sleep to avoid busy-waiting

    # Persist results
    result.sitemap = sorted(set(sitemap))
    result.js_endpoints = sorted(js_eps)
    result.parameters = {url: sorted(p) for url, p in params.items()}

    progress.update(task, completed=50)
    score_and_report(result, "spider")


# ─────────────────────────────────────────────────────────────────
# Backward-compat alias (main.py autoloader looks for any run_* func)
# ─────────────────────────────────────────────────────────────────
run_deep_crawler = run_spider


# ─────────────────────────────────────────────────────────────────
# Display function
# ─────────────────────────────────────────────────────────────────


def score_spider(result):
    return 100  # informational only


def display_spider(result: ScanResult) -> None:
    console.print(
        Rule(
            f"[{C['accent']}]🕸️   DEEP CRAWLER RESULTS[/{C['accent']}]", style="magenta"
        )
    )

    # ── Sitemap
    console.print(Rule("[bold]Crawled Internal URLs[/bold]", style="dim"))
    console.print(
        f"  Total unique internal pages discovered: [cyan]{len(result.sitemap)}[/cyan]"
    )
    if result.sitemap:
        sm_t = Table(box=box.MINIMAL, border_style="dim", header_style=C["subtle"])
        sm_t.add_column("URL", style=C["warn"])
        for url in result.sitemap[:40]:
            sm_t.add_row(escape(url))
        if len(result.sitemap) > 40:
            sm_t.add_row(
                f"[dim]… and {len(result.sitemap) - 40} more in JSON report[/dim]"
            )
        console.print(sm_t)
    console.print()

    # ── JS API Endpoints
    console.print(Rule("[bold]JS-Discovered API Endpoints[/bold]", style="dim"))
    if result.js_endpoints:
        js_t = Table(box=box.MINIMAL, border_style="dim", header_style=C["subtle"])
        js_t.add_column(
            f"Endpoints found in JS files ({len(result.js_endpoints)} unique)",
            style=C["accent"],
        )
        for ep in result.js_endpoints[:50]:
            js_t.add_row(escape(ep))
        if len(result.js_endpoints) > 50:
            js_t.add_row(
                f"[dim]… and {len(result.js_endpoints) - 50} more in JSON report[/dim]"
            )
        console.print(js_t)
    else:
        console.print("  [dim]No hidden API endpoints discovered in JS files.[/dim]")
    console.print()

    # ── Parameter Mining
    console.print(Rule("[bold]Discovered Query Parameters[/bold]", style="dim"))
    if result.parameters:
        pm_t = Table(box=box.MINIMAL, border_style="dim", header_style=C["subtle"])
        pm_t.add_column("URL", style=C["warn"], width=65)
        pm_t.add_column("Parameters", style=C["accent"])
        for url, parms in list(result.parameters.items())[:25]:
            pm_t.add_row(escape(url[:65]), ", ".join(parms))
        console.print(pm_t)
    else:
        console.print("  [dim]No query parameters found.[/dim]")
    console.print()


def export_spider(result: ScanResult, W: callable) -> None:
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
