"""
src/modules/cf_bypass.py — Cloudflare WAF Bypass Research Module.

Vectors researched (based on public pentesting knowledge):

  1. Origin IP Discovery
     - DNS history via SecurityTrails-compatible APIs (crt.sh, hackertarget)
     - SPF record parsing (often leaks real mail server IP)
     - Certificate Transparency logs (crt.sh) — IPs of subdomains before CF
     - Direct A-record probe for common non-proxied subdomains (ftp, mail, etc.)

  2. Header Injection Bypass
     - Spoof CF-Connecting-IP, X-Forwarded-For, True-Client-IP to "127.0.0.1"
       in case origin trusts these headers without verifying they come from CF
     - Test CF-Visitor, X-Original-Forwarded-For injection

  3. Direct Origin Reachability Test
     - If candidate origin IPs found, probe them directly with HTTP Host header
       set to the target domain — if response matches, CF is bypassable

  4. Misconfiguration Checks
     - Does origin server accept non-Cloudflare IP ranges directly?
     - Exposed subdomains not behind CF (direct A record instead of proxied)
"""

from __future__ import annotations

import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from rich import box
from rich.markup import escape
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

from src.config import C, console
from src.export import md_table
from src.models import ScanResult
from src.scoring import score_and_report

# ─────────────────────────────────────────────────────────────────
# Cloudflare IP ranges — fetched live from https://www.cloudflare.com/ips-v4
# Fallback to hardcoded list if the request fails (e.g. offline)
# ─────────────────────────────────────────────────────────────────
_CF_IPV4_FALLBACK = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
]


def _fetch_cf_ranges() -> list[str]:
    """Fetch live Cloudflare IPv4 ranges. Falls back to hardcoded list."""
    try:
        r = requests.get(
            "https://www.cloudflare.com/ips-v4/",
            timeout=5,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if r.status_code == 200:
            ranges = [line.strip() for line in r.text.splitlines() if line.strip()]
            if len(ranges) >= 10:  # sanity check
                return ranges
    except Exception:
        pass
    return _CF_IPV4_FALLBACK


# Fetched once at module load — reused for the entire scan session
_CF_IPV4_RANGES: list[str] = _fetch_cf_ranges()

# Common subdomains that owners forget to proxy through CF
_LEAK_SUBDOMAINS = [
    "mail",
    "smtp",
    "pop",
    "imap",
    "ftp",
    "sftp",
    "cpanel",
    "whm",
    "webmail",
    "direct",
    "origin",
    "backend",
    "api",
    "vpn",
    "remote",
    "staging",
    "dev",
    "test",
    "old",
    "legacy",
    "admin",
    "dashboard",
    "git",
    "svn",
    "jenkins",
    "ci",
    "cdn",
    "static",
    "assets",
    "media",
    "img",
    "images",
    "upload",
    "files",
    "ns1",
    "ns2",
]

# Headers to inject for bypass attempt
_BYPASS_HEADERS = [
    {"CF-Connecting-IP": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1, 173.245.48.1"},  # CF range prefix
    {"CF-Visitor": '{"scheme":"https"}', "X-Forwarded-For": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
]


# ─────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────


def _is_cloudflare_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        for cidr in _CF_IPV4_RANGES:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
    except ValueError:
        pass
    return False


def _resolve(hostname: str) -> list[str]:
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_INET)
        return list({r[4][0] for r in results})
    except Exception:
        return []


def _http_probe(url: str, headers: dict | None = None, timeout: int = 6) -> dict:
    """Fire a single GET and return status + server header."""
    try:
        r = requests.get(
            url,
            headers=headers or {},
            timeout=timeout,
            allow_redirects=True,
            verify=False,
        )
        return {
            "status": r.status_code,
            "server": r.headers.get("Server", ""),
            "cf_ray": r.headers.get("CF-RAY", ""),
            "content_length": len(r.content),
        }
    except Exception as e:
        return {"status": 0, "server": "", "cf_ray": "", "error": str(e)}


# ─────────────────────────────────────────────────────────────────
# Phase 1 — Detect if target is behind Cloudflare
# ─────────────────────────────────────────────────────────────────


def _detect_cloudflare(target_url: str, hostname: str) -> dict:
    probe = _http_probe(target_url)
    ips = _resolve(hostname)

    behind_cf = False
    signals = []

    if probe.get("cf_ray"):
        behind_cf = True
        signals.append(f"CF-RAY header present: {probe['cf_ray']}")

    if "cloudflare" in probe.get("server", "").lower():
        behind_cf = True
        signals.append("Server header: cloudflare")

    for ip in ips:
        if _is_cloudflare_ip(ip):
            behind_cf = True
            signals.append(f"Resolved IP {ip} is in Cloudflare's range")

    return {
        "behind_cloudflare": behind_cf,
        "resolved_ips": ips,
        "signals": signals,
        "probe": probe,
    }


# ─────────────────────────────────────────────────────────────────
# Phase 2 — Origin IP Discovery via cert transparency + subdomain probe
# ─────────────────────────────────────────────────────────────────


def _crtsh_ips(hostname: str) -> list[dict]:
    """Query crt.sh cert transparency for all SANs, resolve each."""
    found = []
    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{hostname}&output=json",
            timeout=12,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if r.status_code != 200:
            return found
        entries = r.json()
        seen_names = set()
        for e in entries:
            names = e.get("name_value", "").split("\n")
            for name in names:
                name = name.strip().lstrip("*.")
                if name and name not in seen_names and hostname in name:
                    seen_names.add(name)
    except Exception:
        return found

    def _resolve_and_check(name: str) -> dict | None:
        ips = _resolve(name)
        for ip in ips:
            if not _is_cloudflare_ip(ip):
                return {"subdomain": name, "ip": ip, "source": "crt.sh"}
        return None

    with ThreadPoolExecutor(max_workers=20) as pool:
        futs = {pool.submit(_resolve_and_check, n): n for n in list(seen_names)[:80]}
        for fut in as_completed(futs):
            res = fut.result()
            if res:
                found.append(res)
    return found


def _subdomain_probe(hostname: str) -> list[dict]:
    """Probe common non-proxied subdomains for direct IPs."""
    found = []

    def _check(sub: str) -> dict | None:
        fqdn = f"{sub}.{hostname}"
        ips = _resolve(fqdn)
        for ip in ips:
            if not _is_cloudflare_ip(ip):
                return {"subdomain": fqdn, "ip": ip, "source": "direct-subdomain-probe"}
        return None

    with ThreadPoolExecutor(max_workers=30) as pool:
        futs = {pool.submit(_check, s): s for s in _LEAK_SUBDOMAINS}
        for fut in as_completed(futs):
            res = fut.result()
            if res:
                found.append(res)
    return found


def _spf_ips(hostname: str) -> list[dict]:
    """Parse SPF TXT record — often contains mail server IP (not proxied)."""
    found = []
    try:
        import dns.resolver  # type: ignore

        answers = dns.resolver.resolve(hostname, "TXT")
        for rdata in answers:
            txt = b"".join(rdata.strings).decode(errors="ignore")
            if "v=spf1" in txt:
                for token in txt.split():
                    if token.startswith("ip4:"):
                        ip = token[4:].split("/")[0]
                        if not _is_cloudflare_ip(ip):
                            found.append(
                                {
                                    "subdomain": f"(SPF ip4) {hostname}",
                                    "ip": ip,
                                    "source": "SPF record",
                                }
                            )
                    elif (
                        token.startswith("include:")
                        or token.startswith("a:")
                        or token.startswith("mx:")
                    ):
                        ref = token.split(":", 1)[1]
                        ips = _resolve(ref)
                        for ip in ips:
                            if not _is_cloudflare_ip(ip):
                                found.append(
                                    {
                                        "subdomain": f"(SPF ref) {ref}",
                                        "ip": ip,
                                        "source": "SPF record",
                                    }
                                )
    except Exception:
        pass
    return found


# ─────────────────────────────────────────────────────────────────
# Phase 3 — Verify origin IP (direct host header bypass)
# ─────────────────────────────────────────────────────────────────


def _verify_origin(candidate: dict, hostname: str, baseline_len: int) -> dict:
    """
    Send HTTP request directly to candidate IP with Host: hostname.
    If we get a valid response that resembles the real site, CF is bypassed.
    """
    ip = candidate["ip"]
    for scheme in ("https", "http"):
        url = f"{scheme}://{ip}"
        try:
            r = requests.get(
                url,
                headers={"Host": hostname, "User-Agent": "Mozilla/5.0"},
                timeout=6,
                verify=False,
                allow_redirects=True,
            )
            behind_cf = bool(r.headers.get("CF-RAY"))
            similar = False
            if baseline_len > 0:
                ratio = abs(len(r.content) - baseline_len) / max(baseline_len, 1)
                similar = ratio < 0.30  # within 30% content size = likely same site
            return {
                **candidate,
                "verified": r.status_code not in (0, 400, 521, 522, 523, 524)
                and not behind_cf,
                "status": r.status_code,
                "scheme": scheme,
                "content_similar": similar,
                "behind_cf": behind_cf,
                "server": r.headers.get("Server", ""),
            }
        except Exception:
            continue
    return {
        **candidate,
        "verified": False,
        "status": 0,
        "scheme": "?",
        "content_similar": False,
    }


# ─────────────────────────────────────────────────────────────────
# Phase 4 — Header injection bypass probe
# ─────────────────────────────────────────────────────────────────


def _header_bypass_probe(target_url: str, baseline_status: int) -> list[dict]:
    """
    Try each bypass header combo — compare response to baseline.
    A different status code or content means the server processed it differently.
    """
    results = []
    for hdrs in _BYPASS_HEADERS:
        probe = _http_probe(target_url, headers=hdrs)
        bypassed = (
            probe.get("status") not in (0, 403, 429, 503)
            and probe.get("status") != baseline_status
            and not probe.get("cf_ray")
        )
        results.append(
            {
                "headers": hdrs,
                "status": probe.get("status"),
                "cf_ray": probe.get("cf_ray", ""),
                "server": probe.get("server", ""),
                "bypass_suspected": bypassed,
            }
        )
        time.sleep(0.3)
    return results


# ─────────────────────────────────────────────────────────────────
# Main runner
# ─────────────────────────────────────────────────────────────────


def run_cf_bypass(
    target_url: str, hostname: str, result: ScanResult, progress, task
) -> None:
    total_steps = 5
    step = 0

    def _step(msg: str):
        nonlocal step
        step += 1
        progress.update(
            task,
            description=f"[cyan]CF Bypass:[/cyan] {msg}",
            completed=int(step / total_steps * 48) + 1,
        )

    _step("Detecting Cloudflare presence…")
    cf_info = _detect_cloudflare(target_url, hostname)

    if not cf_info["behind_cloudflare"]:
        progress.console.print(
            Panel(
                "[bold yellow]Target does not appear to be behind Cloudflare.\n"
                "CF Bypass module is most useful against CF-protected targets.[/bold yellow]",
                title="[yellow]⚠ NOT BEHIND CLOUDFLARE[/yellow]",
                border_style="yellow",
            )
        )
        result.cf_bypass_findings = {
            "behind_cloudflare": False,
            "cf_signals": [],
            "origin_candidates": [],
            "verified_origins": [],
            "header_bypass": [],
        }
        progress.update(task, completed=50)
        return

    progress.console.print(
        Panel(
            "[bold red]🛡 Cloudflare DETECTED[/bold red]\n\n"
            + "\n".join(f"  • {s}" for s in cf_info["signals"])
            + "\n\n[dim]Starting origin IP discovery and bypass research…[/dim]",
            title="[bold red]☁ CLOUDFLARE DETECTED — BYPASS RESEARCH STARTING[/bold red]",
            border_style="red",
        )
    )

    # Get baseline for comparison
    baseline_probe = _http_probe(target_url)
    baseline_len = baseline_probe.get("content_length", 0)
    baseline_status = baseline_probe.get("status", 200)

    _step("Querying cert transparency (crt.sh)…")
    crt_ips = _crtsh_ips(hostname)

    _step("Probing common non-proxied subdomains…")
    sub_ips = _subdomain_probe(hostname)

    _step("Parsing SPF records for mail server IPs…")
    spf_ips = _spf_ips(hostname)

    # Deduplicate candidates by IP
    all_candidates: list[dict] = []
    seen_ips: set[str] = set()
    for c in crt_ips + sub_ips + spf_ips:
        if c["ip"] not in seen_ips:
            seen_ips.add(c["ip"])
            all_candidates.append(c)

    _step(f"Verifying {len(all_candidates)} candidate origin IPs…")
    verified = []
    if all_candidates:
        with ThreadPoolExecutor(max_workers=10) as pool:
            futs = {
                pool.submit(_verify_origin, c, hostname, baseline_len): c
                for c in all_candidates
            }
            for fut in as_completed(futs):
                res = fut.result()
                if res.get("verified") or res.get("content_similar"):
                    verified.append(res)
                    progress.console.print(
                        Panel(
                            f"[bold red]ORIGIN IP FOUND AND VERIFIED[/bold red]\n\n"
                            f"  Subdomain : [cyan]{escape(res['subdomain'])}[/cyan]\n"
                            f"  Real IP   : [bold red]{res['ip']}[/bold red]\n"
                            f"  HTTP      : {res.get('scheme', '?')}://{res['ip']} → Status {res.get('status')}\n"
                            f"  Source    : {res['source']}\n\n"
                            "[bold yellow]This IP is NOT behind Cloudflare — direct attack possible![/bold yellow]",
                            title="[bold red]💀 CF BYPASS — REAL ORIGIN EXPOSED[/bold red]",
                            border_style="red",
                        )
                    )

    # Header bypass probe
    header_results = _header_bypass_probe(target_url, baseline_status)
    header_bypasses = [h for h in header_results if h.get("bypass_suspected")]

    result.cf_bypass_findings = {
        "behind_cloudflare": True,
        "cf_signals": cf_info["signals"],
        "resolved_cf_ips": cf_info["resolved_ips"],
        "origin_candidates": all_candidates,
        "verified_origins": verified,
        "header_bypass": header_results,
        "header_bypasses_suspected": header_bypasses,
        "baseline_status": baseline_status,
    }

    progress.update(task, completed=50)

    if verified:
        progress.console.print(
            f"  [{C['bad']}]💀 {len(verified)} verified origin IP(s) found — Cloudflare is BYPASSABLE![/{C['bad']}]"
        )
    elif all_candidates:
        progress.console.print(
            f"  [{C['warn']}]⚠ {len(all_candidates)} candidate IP(s) found but could not verify directly.[/{C['warn']}]"
        )
    else:
        progress.console.print(
            f"  [{C['ok']}]✅ No origin IP leaks detected.[/{C['ok']}]"
        )

    if header_bypasses:
        progress.console.print(
            f"  [{C['bad']}]⚠ {len(header_bypasses)} header injection(s) may have bypassed CF.[/{C['bad']}]"
        )
        score_and_report(result, "cf_bypass")


# ─────────────────────────────────────────────────────────────────
# Display
# ─────────────────────────────────────────────────────────────────


def score_cf_bypass(result):
    cf = result.cf_bypass_findings
    if not cf or not cf.get("behind_cloudflare"):
        return 100
    score = 100
    if cf.get("verified_origins"):
        score -= 60
    if cf.get("header_bypasses_suspected"):
        score -= 25
    return max(0, score)


def display_cf_bypass(result: ScanResult) -> None:
    console.print(
        Rule(f"[{C['bad']}]☁  CLOUDFLARE BYPASS RESEARCH[/{C['bad']}]", style="red")
    )

    findings = getattr(result, "cf_bypass_findings", None)
    if not findings:
        console.print("  [dim]CF Bypass module was not run.[/dim]\n")
        return

    if not findings.get("behind_cloudflare"):
        console.print(
            "  [dim]Target is not behind Cloudflare — bypass module skipped.[/dim]\n"
        )
        return

    # CF signals
    console.print(f"\n  [{C['warn']}]🛡 Cloudflare Signals:[/{C['warn']}]")
    for sig in findings.get("cf_signals", []):
        console.print(f"    • {escape(sig)}")

    # Verified origins
    verified = findings.get("verified_origins", [])
    if verified:
        tbl = Table(
            "Subdomain",
            "Real Origin IP",
            "HTTP",
            "Status",
            "Source",
            box=box.ROUNDED,
            border_style="red",
            header_style="bold red",
            show_lines=True,
        )
        for v in verified:
            tbl.add_row(
                escape(v.get("subdomain", "?")),
                f"[bold red]{v['ip']}[/bold red]",
                v.get("scheme", "?"),
                str(v.get("status", "?")),
                v.get("source", "?"),
            )
        console.print()
        console.print(
            Panel(
                tbl,
                title="[bold red]💀 VERIFIED ORIGIN IPs — CLOUDFLARE BYPASSABLE[/bold red]",
                border_style="red",
            )
        )
    else:
        candidates = findings.get("origin_candidates", [])
        if candidates:
            console.print(
                f"\n  [{C['warn']}]⚠ {len(candidates)} unverified candidate IPs found — check manually:[/{C['warn']}]"
            )
            for c in candidates[:10]:
                console.print(
                    f"    • [cyan]{c['ip']}[/cyan] ← {c['subdomain']} ({c['source']})"
                )
        else:
            console.print(
                f"\n  [{C['ok']}]✅ No origin IP leaks discovered.[/{C['ok']}]"
            )

    # Header bypass
    hdr_bypasses = findings.get("header_bypasses_suspected", [])
    if hdr_bypasses:
        console.print(
            f"\n  [{C['bad']}]⚠ Header injection bypass suspected ({len(hdr_bypasses)} combos):[/{C['bad']}]"
        )
        for h in hdr_bypasses:
            hdr_str = ", ".join(f"{k}: {v}" for k, v in h["headers"].items())
            console.print(
                f"    • [{C['warn']}]{escape(hdr_str)}[/{C['warn']}] → HTTP {h['status']}"
            )
    else:
        console.print(
            f"\n  [{C['ok']}]✅ No header injection bypasses detected.[/{C['ok']}]"
        )

    console.print()


# ─────────────────────────────────────────────────────────────────
# Export
# ─────────────────────────────────────────────────────────────────


def export_cf_bypass(result: ScanResult, W: callable) -> None:
    findings = getattr(result, "cf_bypass_findings", None)
    if not findings:
        return

    W("## ☁️ Cloudflare Bypass Research\n\n")

    if not findings.get("behind_cloudflare"):
        W("- Target is not behind Cloudflare.\n\n")
        return

    W("### 🛡 Detection Signals\n\n")
    for sig in findings.get("cf_signals", []):
        W(f"- {sig}\n")
    W("\n")

    verified = findings.get("verified_origins", [])
    if verified:
        W(f"### 💀 Verified Origin IPs ({len(verified)} found — CF BYPASSABLE)\n\n")
        W(
            "> [!CAUTION]\n> Real origin IPs exposed! Attacker can bypass Cloudflare by targeting these directly.\n\n"
        )
        rows = [
            [
                v.get("subdomain", "?"),
                v["ip"],
                v.get("scheme", "?"),
                str(v.get("status", "?")),
                v.get("source", "?"),
            ]
            for v in verified
        ]
        W(md_table(["Subdomain", "Real IP", "Proto", "Status", "Source"], rows))
        W("\n")
    else:
        candidates = findings.get("origin_candidates", [])
        if candidates:
            W(f"### ⚠️ Unverified Candidate IPs ({len(candidates)} found)\n\n")
            rows = [
                [c.get("subdomain", "?"), c["ip"], c.get("source", "?")]
                for c in candidates[:20]
            ]
            W(md_table(["Subdomain", "Candidate IP", "Source"], rows))
            W("\n")
        else:
            W("- ✅ No origin IP leaks discovered.\n\n")

    hdr_bypasses = findings.get("header_bypasses_suspected", [])
    if hdr_bypasses:
        W(f"### ⚠️ Header Injection Bypass ({len(hdr_bypasses)} suspected)\n\n")
        rows = [
            [
                ", ".join(f"{k}: {v}" for k, v in h["headers"].items()),
                str(h.get("status", "?")),
            ]
            for h in hdr_bypasses
        ]
        W(md_table(["Headers Injected", "Response Status"], rows))
        W("\n")
    else:
        W("- ✅ No header injection bypasses detected.\n\n")
