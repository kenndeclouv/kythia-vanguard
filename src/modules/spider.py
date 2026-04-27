"""
src/modules/spider.py — Module 9: Recursive deep crawler.

Discovers:
  - All internal URLs (sitemap)
  - Hidden API endpoints extracted from JS files
  - Query parameters for fuzzing hints
"""

import re
import urllib.parse
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from bs4 import BeautifulSoup

from src.config import rate_limiter, SESSION, TIMEOUT
from src.models import ScanResult

# Regex patterns to find API endpoint strings inside JS files
JS_API_PATTERNS: list[str] = [
    r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|http\.(?:get|post))\s*\(["'`]([^"'`\s)]{5,100})["'`]""",
    r"""["'`](/api/[^\s"'`>)]{3,80})["'`]""",
    r"""["'`](/v\d+/[^\s"'`>)]{3,80})["'`]""",
    r"""["'`](/graphql[^\s"'`>)]{0,40})["'`]""",
    r"""["'`](/rest/[^\s"'`>)]{3,60})["'`]""",
    r"""endpoint\s*[:=]\s*["'`]([^"'`\s]{5,100})["'`]""",
    r"""url\s*[:=]\s*["'`]([/][^"'`\s]{3,80})["'`]""",
]

PARAM_PATTERN = re.compile(r"[?&]([a-zA-Z_][a-zA-Z0-9_]{0,30})=")


# ─────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────

def _is_internal(url: str, hostname: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.hostname is not None and (
            parsed.hostname == hostname
            or parsed.hostname.endswith("." + hostname)
        )
    except Exception:
        return False


def _normalise_url(url: str, base_url: str, hostname: str) -> Optional[str]:
    """Resolve relative URLs; return None if external or non-HTTP(S)."""
    try:
        full   = urllib.parse.urljoin(base_url, url)
        parsed = urllib.parse.urlparse(full)
        if parsed.scheme not in ("http", "https"):
            return None
        if not _is_internal(full, hostname):
            return None
        return urllib.parse.urlunparse(parsed._replace(fragment=""))
    except Exception:
        return None


def _extract_links(html: str, base_url: str, hostname: str) -> set[str]:
    links: set[str] = set()
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
    endpoints: list[str] = []
    for pat in JS_API_PATTERNS:
        for m in re.finditer(pat, js_text):
            ep = m.group(1)
            if len(ep) < 3 or ep.startswith("//") or "." in ep.split("/")[-1][-5:]:
                continue
            norm = _normalise_url(ep, base_url, hostname)
            if norm:
                endpoints.append(norm)
            elif ep.startswith("/"):
                endpoints.append(ep)   # keep as relative path
    return list(set(endpoints))


def _extract_params(url: str) -> list[str]:
    parsed = urllib.parse.urlparse(url)
    return PARAM_PATTERN.findall(parsed.query)


# ─────────────────────────────────────────────────────────────────
# Public runner
# ─────────────────────────────────────────────────────────────────

def run_deep_crawler(
    target_url: str,
    hostname: str,
    result: ScanResult,
    progress,
    task,
    max_pages: int = 80,
) -> None:
    visited:  set[str]               = set()
    queue:    set[str]               = {target_url}
    sitemap:  list[str]              = []
    js_eps:   list[str]              = []
    params:   defaultdict[str, set]  = defaultdict(set)

    progress.update(task, description="[cyan]Spider:[/cyan] Starting recursive crawl…")

    def _fetch_page(url: str):
        rate_limiter.wait()
        try:
            resp = SESSION.get(url, timeout=TIMEOUT, allow_redirects=True)
        except Exception:
            return url, None, set(), []

        if not resp.ok:
            return url, None, set(), []

        content_type = resp.headers.get("Content-Type", "")
        links:        set[str]   = set()
        js_endpoints: list[str]  = []

        if "html" in content_type:
            links = _extract_links(resp.text, url, hostname)
            soup  = BeautifulSoup(resp.text, "html.parser")
            for script in soup.find_all("script", src=True):
                js_url = _normalise_url(script["src"], url, hostname)
                if js_url:
                    links.add(js_url)
        elif "javascript" in content_type:
            js_endpoints = _extract_js_endpoints(resp.text, url, hostname)

        return url, resp, links, js_endpoints

    while queue and len(visited) < max_pages:
        batch = list(queue - visited)[:10]
        queue -= set(batch)

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
            description=(
                f"[cyan]Spider:[/cyan] {len(visited)}/{max_pages} pages "
                f"· {len(js_eps)} JS endpoints…"
            ),
            completed=done_pct,
        )

    result.sitemap      = sorted(set(sitemap))
    result.js_endpoints = sorted(set(js_eps))
    result.parameters   = {url: sorted(p) for url, p in params.items()}
