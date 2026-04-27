"""
src/modules/waf.py — Module 2: WAF / CDN fingerprinting.
"""

from rich import box
from rich.markup import escape
from rich.rule import Rule
from rich.table import Table

from src.config import console, C, rate_limiter, SESSION, TIMEOUT
from src.models import ScanResult

WAF_SIGNATURES: dict[str, dict] = {
    "Cloudflare": {"server": "cloudflare", "cf-ray": ""},
    "AWS WAF / CloudFront": {
        "x-amz-cf-id": "",
        "x-amzn-requestid": "",
        "x-amz-cf-pop": "",
    },
    "Akamai": {"x-akamai-transformed": "", "x-check-cacheable": ""},
    "Sucuri": {"x-sucuri-id": "", "server": "sucuri"},
    "Fastly": {"x-served-by": "cache", "fastly-restarts": ""},
    "Imperva / Incapsula": {"x-iinfo": "", "x-cdn": "incapsula"},
    "Nginx (proxy)": {"server": "nginx"},
    "Apache": {"server": "apache"},
    "Microsoft Azure": {"x-msedge-ref": "", "x-azure-ref": ""},
    "Varnish": {"x-varnish": "", "via": "varnish"},
    "Vercel": {"x-vercel-id": ""},
    "Netlify": {"x-nf-request-id": "", "server": "netlify"},
}


def run_waf_detection(target_url: str, result: ScanResult, progress, task) -> None:
    progress.update(task, description="[cyan]WAF:[/cyan] Fetching headers…")
    rate_limiter.wait()

    detected: dict = {}
    raw_headers: dict = {}

    try:
        resp = SESSION.get(target_url, timeout=TIMEOUT, allow_redirects=True)
        raw_headers = dict(resp.headers)
        lower_headers = {k.lower(): v.lower() for k, v in resp.headers.items()}

        for provider, sigs in WAF_SIGNATURES.items():
            matched = []
            for h_key, h_val in sigs.items():
                if h_key in lower_headers:
                    if h_val == "" or h_val in lower_headers[h_key]:
                        matched.append(h_key)
            if matched:
                detected[provider] = matched
    except Exception:
        pass

    result.headers = raw_headers
    result.waf_cdn = detected
    progress.advance(task, 50)


def display_waf(result: ScanResult) -> None:
    console.print(
        Rule(
            f"[{C['accent']}]🛡️   WAF / CDN / SERVER DETECTION[/{C['accent']}]",
            style="magenta",
        )
    )
    if result.waf_cdn:
        for provider, headers in result.waf_cdn.items():
            console.print(
                f"  [bold green]✓ DETECTED:[/bold green] [bold white]{provider}[/bold white]  "
                f"[dim](matched: {', '.join(headers)})[/dim]"
            )
    else:
        console.print("  [dim]No known WAF/CDN fingerprints detected.[/dim]")
    console.print()

    interesting = [
        "server",
        "x-powered-by",
        "via",
        "x-cache",
        "age",
        "cf-ray",
        "x-amz-cf-id",
        "x-served-by",
    ]
    hdr_t = Table(
        title="Notable HTTP Response Headers",
        box=box.ROUNDED,
        border_style="blue",
        header_style=C["head"],
    )
    hdr_t.add_column("Header", style=C["info"], width=30)
    hdr_t.add_column("Value", style="white")
    for h in interesting:
        val = (
            result.headers.get(h)
            or result.headers.get(h.title())
            or result.headers.get(h.upper())
        )
        if val:
            hdr_t.add_row(h, escape(str(val)))
    console.print(hdr_t)
    console.print()
