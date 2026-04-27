"""
src/modules/spider.py — Module 9: Recursive deep crawler + FAST SECRET HUNTER.
"""

import re
import urllib.parse

from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
from typing import Optional

from rich import box
from rich.markup import escape
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

from src.config import console, C, rate_limiter, SESSION, TIMEOUT
from src.models import ScanResult

# 🔥 Pre-Compile Regex biar 100x lebih ngebut!
JS_API_PATTERNS = [
    re.compile(p)
    for p in [
        r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|http\.(?:get|post))\s*\(["'`]([^"'`\s)]{5,100})["'`]""",
        r"""["'`](/api/[^\s"'`>)]{3,80})["'`]""",
        r"""["'`](/v\d+/[^\s"'`>)]{3,80})["'`]""",
        r"""["'`](/graphql[^\s"'`>)]{0,40})["'`]""",
        r"""["'`](/rest/[^\s"'`>)]{3,60})["'`]""",
        r"""endpoint\s*[:=]\s*["'`]([^"'`\s]{5,100})["'`]""",
        r"""url\s*[:=]\s*["'`]([/][^"'`\s]{3,80})["'`]""",
    ]
]

PARAM_PATTERN = re.compile(r"[?&]([a-zA-Z_][a-zA-Z0-9_]{0,30})=")

SECRET_PATTERNS = {
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Stripe Secret": re.compile(r"sk_live_[0-9a-zA-Z]{24}"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z-_]{35}"),
    "GitHub Token": re.compile(r"ghp_[0-9a-zA-Z]{36}"),
    "RSA Private Key": re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),
}


def _is_internal(url: str, hostname: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.hostname is not None and (
            parsed.hostname == hostname or parsed.hostname.endswith("." + hostname)
        )
    except Exception:
        return False


def _normalise_url(url: str, base_url: str, hostname: str) -> Optional[str]:
    try:
        full = urllib.parse.urljoin(base_url, url)
        parsed = urllib.parse.urlparse(full)
        if parsed.scheme not in ("http", "https") or not _is_internal(full, hostname):
            return None
        return urllib.parse.urlunparse(parsed._replace(fragment=""))
    except Exception:
        return None


def _extract_links(html: str, base_url: str, hostname: str) -> set[str]:
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
    endpoints = []
    for pat in JS_API_PATTERNS:
        for m in pat.finditer(js_text):
            ep = m.group(1)
            if len(ep) < 3 or ep.startswith("//") or "." in ep.split("/")[-1][-5:]:
                continue
            norm = _normalise_url(ep, base_url, hostname)
            if norm:
                endpoints.append(norm)
            elif ep.startswith("/"):
                endpoints.append(ep)
    return list(set(endpoints))


def _extract_params(url: str) -> list[str]:
    return PARAM_PATTERN.findall(urllib.parse.urlparse(url).query)


def run_deep_crawler(
    target_url: str,
    hostname: str,
    result: ScanResult,
    progress,
    task,
    max_pages: int = 80,
) -> None:
    visited, queue, sitemap, js_eps, params = (
        set(),
        {target_url},
        [],
        [],
        defaultdict(set),
    )
    progress.update(task, description="[cyan]Spider:[/cyan] Starting recursive crawl…")

    def _fetch_page(url: str):
        rate_limiter.wait()
        try:
            resp = SESSION.get(url, timeout=TIMEOUT, allow_redirects=True, stream=True)
        except Exception:
            return url, None, set(), []

        if not resp.ok:
            return url, None, set(), []

        content_type = resp.headers.get("Content-Type", "").lower()

        if any(
            ext in content_type
            for ext in [
                "image",
                "video",
                "audio",
                "zip",
                "pdf",
                "octet-stream",
                "tar",
                "rar",
            ]
        ):
            resp.close()
            return url, None, set(), []

        try:
            # 5MB MAX,
            raw_content = resp.raw.read(5000000, decode_content=True)
            text_to_scan = raw_content.decode("utf-8", errors="ignore")
        except Exception:
            text_to_scan = ""
        finally:
            resp.close()

        links, js_endpoints = set(), []

        if "html" in content_type or "javascript" in content_type:
            for s_name, s_pat in SECRET_PATTERNS.items():
                matches = set(s_pat.findall(text_to_scan))
                if matches:
                    progress.console.print(
                        Panel(
                            f"[bold red]LEAKED SECRET DETECTED![/bold red]\n"
                            f"URL   : [cyan]{url}[/cyan]\n"
                            f"Type  : [yellow]{s_name}[/yellow]\n"
                            f"Value : {list(matches)[0][:10]}...[REDACTED]",
                            title="SECRET HUNTER",
                            border_style="red",
                        )
                    )

        if "html" in content_type:
            links = _extract_links(text_to_scan, url, hostname)
            try:
                # Parsing HTML pake BeautifulSoup
                soup = BeautifulSoup(text_to_scan, "html.parser")
                for script in soup.find_all("script", src=True):
                    js_url = _normalise_url(script["src"], url, hostname)
                    if js_url:
                        links.add(js_url)
            except Exception:
                pass
        elif "javascript" in content_type:
            js_endpoints = _extract_js_endpoints(text_to_scan, url, hostname)

        return url, resp, links, js_endpoints

    while queue and len(visited) < max_pages:
        batch = list(queue - visited)[:15]  # Gedein batch biar lebih ganas
        queue -= set(batch)

        with ThreadPoolExecutor(max_workers=15) as pool:
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

    result.sitemap = sorted(set(sitemap))
    result.js_endpoints = sorted(set(js_eps))
    result.parameters = {url: sorted(p) for url, p in params.items()}


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
        for url in result.sitemap[:30]:
            sm_t.add_row(escape(url))
        if len(result.sitemap) > 30:
            sm_t.add_row(
                f"[dim]… and {len(result.sitemap) - 30} more in JSON report[/dim]"
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
        for ep in result.js_endpoints[:40]:
            js_t.add_row(escape(ep))
        if len(result.js_endpoints) > 40:
            js_t.add_row(
                f"[dim]… and {len(result.js_endpoints) - 40} more in JSON report[/dim]"
            )
        console.print(js_t)
    else:
        console.print("  [dim]No hidden API endpoints discovered in JS files.[/dim]")
    console.print()

    # ── Parameter Mining
    console.print(Rule("[bold]Discovered Query Parameters[/bold]", style="dim"))
    if result.parameters:
        pm_t = Table(box=box.MINIMAL, border_style="dim", header_style=C["subtle"])
        pm_t.add_column("URL", style=C["warn"], width=60)
        pm_t.add_column("Parameters", style=C["accent"])
        for url, parms in list(result.parameters.items())[:20]:
            pm_t.add_row(escape(url[:60]), ", ".join(parms))
        console.print(pm_t)
    else:
        console.print("  [dim]No query parameters found.[/dim]")
    console.print()
