"""
src/modules/waf.py — Module 2: WAF / CDN fingerprinting.
"""

from src.config import rate_limiter, SESSION, TIMEOUT
from src.models import ScanResult

WAF_SIGNATURES: dict[str, dict] = {
    "Cloudflare":           {"server": "cloudflare", "cf-ray": ""},
    "AWS WAF / CloudFront": {"x-amz-cf-id": "", "x-amzn-requestid": "", "x-amz-cf-pop": ""},
    "Akamai":               {"x-akamai-transformed": "", "x-check-cacheable": ""},
    "Sucuri":               {"x-sucuri-id": "", "server": "sucuri"},
    "Fastly":               {"x-served-by": "cache", "fastly-restarts": ""},
    "Imperva / Incapsula":  {"x-iinfo": "", "x-cdn": "incapsula"},
    "Nginx (proxy)":        {"server": "nginx"},
    "Apache":               {"server": "apache"},
    "Microsoft Azure":      {"x-msedge-ref": "", "x-azure-ref": ""},
    "Varnish":              {"x-varnish": "", "via": "varnish"},
    "Vercel":               {"x-vercel-id": ""},
    "Netlify":              {"x-nf-request-id": "", "server": "netlify"},
}


def run_waf_detection(target_url: str, result: ScanResult, progress, task) -> None:
    progress.update(task, description="[cyan]WAF:[/cyan] Fetching headers…")
    rate_limiter.wait()

    detected:    dict = {}
    raw_headers: dict = {}

    try:
        resp = SESSION.get(target_url, timeout=TIMEOUT, allow_redirects=True)
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
    except Exception:
        pass

    result.headers = raw_headers
    result.waf_cdn = detected
    progress.advance(task, 50)
