"""
src/modules/stress.py — HTTP Stress Tester / Load Simulator.

Phase 1 — Protection Check:
  Before sending any load, verify the target is NOT behind:
    - Cloudflare / DDoS protection (cf-ray header, __cf_bm cookie)
    - Rate limiting (429 responses on a fast probe burst)
    - Active WAF (from result.waf_cdn populated by waf.py)
  If protection is detected, the test is aborted with a warning.

Phase 2 — Ramp-Up Load Test:
  Simulates concurrent users in progressive waves:
    Wave 1 →  100 VUs  (virtual users) — baseline
    Wave 2 →  250 VUs
    Wave 3 →  500 VUs
    Wave 4 → 1000 VUs  — peak load
  Each VU sends one GET request to target_url (and optionally a random
  sitemap page if Spider has run). Workers use a dedicated thread pool.

Phase 3 — Metrics Collection (per wave):
  - Total requests sent
  - Success rate (2xx)
  - Error breakdown (4xx, 5xx, timeout, connection error)
  - Min / Mean / Median / P95 / P99 / Max response time (ms)
  - Requests-per-second throughput

Phase 4 — Crash / Degradation Detection:
  - If P99 latency degrades >200% between waves → DEGRADATION flag
  - If error rate exceeds 20% → SERVER STRUGGLING flag
  - If error rate exceeds 50% → POTENTIAL DoS flag
"""

from __future__ import annotations
from src.export import md_table

import os
import signal
import statistics
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from rich import box
from rich.markup import escape
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

from src.config import SESSION, TIMEOUT, console, C
from src.models import ScanResult
from src.scoring import score_and_report

# ─────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────

_WAVES: list[int] = [100, 250, 500, 1000]  # virtual users per wave
_REQUEST_TIMEOUT: int = 10  # per-request timeout (s)
_MAX_WORKERS: int = 200  # max concurrent threads
_PROTECTION_PROBE_N: int = 20  # requests for rate-limit probe
_GLOBAL_STOP_FLAG = threading.Event()
_BRUTAL_VUS: int = 1000  # VUs locked in brutal mode
_DOOMSDAY_VUS: int = 10000  # VUs locked in doomsday mode
_BRUTAL_DEAD_THRESHOLD: int = 3  # consecutive 100%-error waves before auto-stop

# ─────────────────────────────────────────────────────────────────
# Protection detection
# ─────────────────────────────────────────────────────────────────

_CF_HEADERS = {"cf-ray", "cf-cache-status", "__cfduid", "cf-request-id"}
_CF_COOKIES = {"__cf_bm", "__cfruid", "_cfuvid", "cf_clearance"}

_WAF_KEYWORDS = {
    "cloudflare",
    "akamai",
    "imperva",
    "sucuri",
    "incapsula",
    "aws shield",
    "azure front door",
    "fastly",
    "f5 big-ip",
    "barracuda",
    "fortiweb",
    "modsecurity",
    "wallarm",
}


def _detect_protection(target_url: str, waf_cdn: dict) -> dict:
    """
    Check for Cloudflare/WAF/rate-limiting before launching load.
    Returns {'protected': bool, 'reason': str, 'details': dict}
    """
    details: dict = {}

    # 1. Check WAF result from waf.py (already scanned)
    if waf_cdn:
        detected = waf_cdn.get("detected", [])
        if isinstance(detected, list) and detected:
            waf_names = [str(w).lower() for w in detected]
            for waf in waf_names:
                for kw in _WAF_KEYWORDS:
                    if kw in waf:
                        return {
                            "protected": True,
                            "reason": f"WAF/CDN detected by waf.py: {', '.join(str(w) for w in detected)}",
                            "details": {"waf": detected},
                        }

    # 2. Fresh header probe
    try:
        resp = SESSION.get(target_url, timeout=TIMEOUT, allow_redirects=True)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        cookies = {c.name.lower() for c in resp.cookies}
        details["status"] = resp.status_code
        details["server"] = headers.get("server", "")
    except Exception as e:
        return {"protected": False, "reason": f"Probe failed: {e}", "details": {}}

    # Cloudflare headers
    cf_hdrs = _CF_HEADERS & set(headers.keys())
    if cf_hdrs:
        return {
            "protected": True,
            "reason": f"Cloudflare detected (headers: {', '.join(cf_hdrs)})",
            "details": {"cf_headers": list(cf_hdrs)},
        }

    # Cloudflare cookies
    cf_cks = _CF_COOKIES & cookies
    if cf_cks:
        return {
            "protected": True,
            "reason": f"Cloudflare detected (cookies: {', '.join(cf_cks)})",
            "details": {"cf_cookies": list(cf_cks)},
        }

    # Server header fingerprint
    server = headers.get("server", "").lower()
    for kw in _WAF_KEYWORDS:
        if kw in server:
            return {
                "protected": True,
                "reason": f"WAF/CDN detected via Server header: {headers.get('server', '')}",
                "details": {"server": headers.get("server", "")},
            }

    # 3. Rate-limit burst probe (send N rapid requests, check for 429)
    rate_limit_hits = 0
    lock = threading.Lock()

    def _burst() -> int:
        try:
            r = SESSION.get(target_url, timeout=5)
            return r.status_code
        except Exception:
            return 0

    with ThreadPoolExecutor(max_workers=_PROTECTION_PROBE_N) as pool:
        futs = [pool.submit(_burst) for _ in range(_PROTECTION_PROBE_N)]
        for fut in as_completed(futs):
            if fut.result() == 429:
                with lock:
                    rate_limit_hits += 1

    if rate_limit_hits >= 3:
        return {
            "protected": True,
            "reason": f"Rate limiting active ({rate_limit_hits}/{_PROTECTION_PROBE_N} probes returned 429)",
            "details": {"rate_limit_hits": rate_limit_hits},
        }

    return {
        "protected": False,
        "reason": "No active protection detected",
        "details": details,
    }


# ─────────────────────────────────────────────────────────────────
# Single request worker
# ─────────────────────────────────────────────────────────────────


def _fire(url: str, origin_ip: str | None = None, hostname: str | None = None) -> dict:
    """Send one GET request and return timing + status.
    If origin_ip is set, send directly to that IP with Host header (CF vhost bypass).
    """
    if _GLOBAL_STOP_FLAG.is_set():
        return {"ok": False, "status": 0, "category": "aborted", "ms": 0}
    t0 = time.monotonic()
    try:
        extra_headers = {}
        if origin_ip and hostname:
            extra_headers["Host"] = hostname
        resp = SESSION.get(
            url,
            timeout=_REQUEST_TIMEOUT,
            allow_redirects=True,
            stream=True,
            headers=extra_headers if extra_headers else None,
        )
        resp.raw.read(65536, decode_content=False)  # drain 64KB only
        resp.close()
        elapsed_ms = (time.monotonic() - t0) * 1000
        code = resp.status_code
        if 200 <= code < 300:
            category = "2xx"
        elif 300 <= code < 400:
            category = "3xx"
        elif code == 429:
            category = "429"
        elif 400 <= code < 500:
            category = "4xx"
        else:
            category = "5xx"
        return {
            "ok": 200 <= code < 400,
            "status": code,
            "category": category,
            "ms": elapsed_ms,
        }
    except TimeoutError:
        elapsed_ms = (time.monotonic() - t0) * 1000
        return {"ok": False, "status": 0, "category": "timeout", "ms": elapsed_ms}
    except Exception:
        elapsed_ms = (time.monotonic() - t0) * 1000
        return {"ok": False, "status": 0, "category": "conn_error", "ms": elapsed_ms}


# ─────────────────────────────────────────────────────────────────
# Wave runner
# ─────────────────────────────────────────────────────────────────


def _run_wave(
    target_url: str,
    vu_count: int,
    sitemap: list[str],
    origin_ip: str | None = None,
    hostname: str | None = None,
) -> dict:
    """
    Fire vu_count requests concurrently.
    Each VU picks a URL: half target homepage, half random sitemap page.
    If origin_ip is provided, requests go directly to the IP with Host header
    (Virtual Host bypass — routes around Cloudflare to the real server).
    Returns aggregated metrics dict.
    """
    import random
    import string

    urls = []
    for i in range(vu_count):
        cb = "".join(random.choices(string.ascii_letters + string.digits, k=8))

        if origin_ip:
            # Direct-IP mode: send to the real origin, not through CF
            base = f"http://{origin_ip}"
        elif sitemap and i % 2 == 1:
            base = random.choice(sitemap)
        else:
            base = target_url

        separator = "&" if "?" in base else "?"
        urls.append((f"{base}{separator}kvanguard_bypass={cb}", origin_ip, hostname))

    results: list[dict] = []
    t_start = time.monotonic()

    with ThreadPoolExecutor(max_workers=min(_MAX_WORKERS, vu_count)) as pool:
        for fut in as_completed(
            {pool.submit(_fire, u[0], u[1], u[2]): u for u in urls}
        ):
            results.append(fut.result())

    t_total = time.monotonic() - t_start

    times = [r["ms"] for r in results]
    ok = sum(1 for r in results if r["ok"])
    cats = {}
    for r in results:
        cats[r["category"]] = cats.get(r["category"], 0) + 1

    sorted_times = sorted(times)
    n = len(sorted_times)

    def _pct(p: float) -> float:
        idx = int(n * p / 100)
        return sorted_times[min(idx, n - 1)]

    return {
        "vu_count": vu_count,
        "total": len(results),
        "ok": ok,
        "error_rate": round((len(results) - ok) / max(len(results), 1) * 100, 1),
        "rps": round(len(results) / max(t_total, 0.001), 1),
        "duration_s": round(t_total, 2),
        "categories": cats,
        "ms_min": round(min(times), 1) if times else 0,
        "ms_mean": round(statistics.mean(times), 1) if times else 0,
        "ms_median": round(statistics.median(times), 1) if times else 0,
        "ms_p95": round(_pct(95), 1),
        "ms_p99": round(_pct(99), 1),
        "ms_max": round(max(times), 1) if times else 0,
    }


# ─────────────────────────────────────────────────────────────────
# Shared wave-result panel renderer
# ─────────────────────────────────────────────────────────────────


def _wave_panel(
    metrics: dict,
    wave_label: str,
    prev_p99: Optional[float],
    flags: list[str],
    brutal: bool = False,
) -> tuple[Panel, str, float]:
    """
    Build a Rich Panel for one wave result.
    Returns (panel, wave_status_str, p99).
    """
    err_rate = metrics["error_rate"]
    p99 = metrics["ms_p99"]
    rps = metrics["rps"]
    cats_str = "  ".join(f"{k}:{v}" for k, v in sorted(metrics["categories"].items()))

    if err_rate >= 95:
        wave_status = "[bold red blink]💀 SERVER DEAD[/bold red blink]"
        flags.append(f"{wave_label}: {err_rate}% errors — SERVER DEAD")
    elif err_rate >= 50:
        wave_status = "[bold red]🔴 POTENTIAL DoS[/bold red]"
        flags.append(f"{wave_label}: {err_rate}% errors — POTENTIAL DoS")
    elif err_rate >= 20:
        wave_status = "[bold yellow]🟡 SERVER STRUGGLING[/bold yellow]"
        flags.append(f"{wave_label}: {err_rate}% errors — Server struggling")
    elif prev_p99 and p99 > prev_p99 * 2.0 and prev_p99 > 0:
        wave_status = "[bold yellow]🟡 LATENCY DEGRADATION[/bold yellow]"
        flags.append(
            f"{wave_label}: P99 {prev_p99:.0f}ms → {p99:.0f}ms (>200% increase)"
        )
    else:
        wave_status = "[bold green]🟢 STABLE[/bold green]"

    brutal_badge = "  [bold red blink]☠ BRUTAL[/bold red blink]" if brutal else ""
    err_col = "red" if err_rate >= 20 else "yellow" if err_rate >= 5 else "green"
    p99_col = "red" if p99 > 5000 else "yellow" if p99 > 2000 else "cyan"

    panel = Panel(
        f"[bold]{wave_label}[/bold]{brutal_badge}   [{wave_status}]\n\n"
        f"  Requests : [cyan]{metrics['total']}[/cyan]  "
        f"Success: [green]{metrics['ok']}[/green]  "
        f"Errors: [red]{metrics['total'] - metrics['ok']}[/red]  "
        f"Error Rate: [{err_col}]{err_rate}%[/{err_col}]\n"
        f"  Throughput: [cyan]{rps} req/s[/cyan]   Duration: {metrics['duration_s']}s\n"
        f"  Latency  : min={metrics['ms_min']}ms  mean={metrics['ms_mean']}ms  "
        f"median={metrics['ms_median']}ms\n"
        f"             P95=[yellow]{metrics['ms_p95']}ms[/yellow]  "
        f"P99=[{p99_col}]{p99}ms[/{p99_col}]  "
        f"max={metrics['ms_max']}ms\n"
        f"  Breakdown: [dim]{cats_str}[/dim]",
        title=f"[bold]{wave_label} — {metrics['vu_count']} VUs[/bold]",
        border_style="red"
        if err_rate >= 20
        else "yellow"
        if err_rate >= 5
        else "green",
    )
    return panel, wave_status, p99


# ─────────────────────────────────────────────────────────────────
# Brutal mode: infinite 1000-VU loop
# ─────────────────────────────────────────────────────────────────


def _brutal_loop(
    target_url: str,
    sitemap: list[str],
    progress,
    task,
) -> list[dict]:
    """
    Fire 1000 VUs endlessly until:
      a) User hits Ctrl+C  → graceful stop
      b) Server returns >=95% errors for _BRUTAL_DEAD_THRESHOLD consecutive rounds
    Returns list of wave metric dicts.
    """
    wave_results: list[dict] = []
    flags: list[str] = []
    prev_p99: Optional[float] = None
    consecutive_dead = 0
    wave_num = 0
    stopped_by: str = "user"

    is_doomsday = os.environ.get("DOOMSDAY", "").strip() in ("1", "true", "yes")
    active_vus = _DOOMSDAY_VUS if is_doomsday else _BRUTAL_VUS
    mode_name = "DOOMSDAY" if is_doomsday else "BRUTAL"
    mode_icon = "☢" if is_doomsday else "☠"

    progress.console.print(
        Panel(
            f"[bold white on red blink] {mode_icon} {mode_name} MODE ACTIVE [/bold white on red blink]\n\n"
            f"  VUs per wave  : [bold red]{active_vus}[/bold red]\n"
            "  Stop condition: [bold]Ctrl+C[/bold]  OR  "
            f"server dead for {_BRUTAL_DEAD_THRESHOLD} consecutive waves\n\n"
            f"  [dim]Each wave fires a fresh burst of {active_vus} concurrent requests.\n"
            "  Metrics are printed after every wave in real-time.[/dim]",
            title=f"[bold white on red blink] {mode_icon} KYTHIA-VANGUARD {mode_name} MODE {mode_icon} [/bold white on red blink]",
            border_style="red",
        )
    )

    try:
        while not _GLOBAL_STOP_FLAG.is_set():
            wave_num += 1
            progress.update(
                task,
                description=f"[bold red]{mode_icon} {mode_name}:[/bold red] Wave {wave_num} — {active_vus} VUs firing…",
                completed=min(49, wave_num % 50),
            )

            metrics = _run_wave(target_url, active_vus, sitemap)
            wave_results.append(metrics)

            panel, _, p99 = _wave_panel(
                metrics,
                f"{mode_name} Wave {wave_num}",
                prev_p99,
                flags,
                brutal=True,
            )
            progress.console.print(panel)
            prev_p99 = p99

            # Dead-server detection
            if metrics["error_rate"] >= 95:
                consecutive_dead += 1
                progress.console.print(
                    f"  [bold red]💀 Dead wave {consecutive_dead}/{_BRUTAL_DEAD_THRESHOLD}[/bold red]"
                )
                if consecutive_dead >= _BRUTAL_DEAD_THRESHOLD:
                    stopped_by = "server_dead"
                    progress.console.print(
                        Panel(
                            f"[bold red]Server stopped responding after {wave_num} waves.\n"
                            f"Total requests fired: {sum(w['total'] for w in wave_results):,}[/bold red]",
                            title="[bold red]💀 SERVER CONFIRMED DOWN — BRUTAL MODE STOPPED[/bold red]",
                            border_style="red",
                        )
                    )
                    break
            else:
                consecutive_dead = 0

    except KeyboardInterrupt:
        pass  # Already handled by SIGINT handler

    total_req = sum(w["total"] for w in wave_results)
    total_ok = sum(w["ok"] for w in wave_results)

    if stopped_by == "user":
        progress.console.print(
            Panel(
                f"[bold yellow]Brutal mode stopped by user after [cyan]{wave_num}[/cyan] waves.\n"
                f"Total requests: [cyan]{total_req:,}[/cyan]  "
                f"Success: [green]{total_ok:,}[/green]  "
                f"Errors: [red]{total_req - total_ok:,}[/red]",
                title="[bold yellow]⚡ BRUTAL MODE ENDED — USER STOPPED[/bold yellow]",
                border_style="yellow",
            )
        )

    return wave_results


def run_stress(
    target_url: str, hostname: str, result: ScanResult, progress, task
) -> None:
    _GLOBAL_STOP_FLAG.clear()
    original_sigint = signal.getsignal(signal.SIGINT)

    def _handle_sigint(sig, frame):  # noqa: ARG001
        _GLOBAL_STOP_FLAG.set()

    signal.signal(signal.SIGINT, _handle_sigint)
    try:
        _internal_run_stress(target_url, hostname, result, progress, task)
    except KeyboardInterrupt:
        pass
    finally:
        signal.signal(signal.SIGINT, original_sigint)
        _GLOBAL_STOP_FLAG.set()
        score_and_report(result, "stress")


def _internal_run_stress(
    target_url: str, hostname: str, result: ScanResult, progress, task
) -> None:
    """
    Stress test with two modes:

    Normal mode (default):
      Progressive waves 100 → 250 → 500 → 1000 VUs.

    Brutal mode (set BRUTAL=1 env-var OR result.brutal_mode = True):
      Infinite 1000-VU waves until Ctrl+C or server confirmed dead.
      Protection check is still run first — set BRUTAL_FORCE=1 to skip it.
    """
    brutal = os.environ.get("BRUTAL", "").strip() in ("1", "true", "yes") or getattr(
        result, "brutal_mode", False
    )
    force_skip_protection = os.environ.get("BRUTAL_FORCE", "").strip() in (
        "1",
        "true",
        "yes",
    )

    # ── Phase 1: Protection check
    if not force_skip_protection:
        progress.update(
            task, description="[cyan]Stress Test:[/cyan] Checking protection…"
        )
        waf_cdn = getattr(result, "waf_cdn", {})
        protection = _detect_protection(target_url, waf_cdn)
    else:
        protection = {
            "protected": False,
            "reason": "Protection check skipped (BRUTAL_FORCE=1)",
            "details": {},
        }

    if protection["protected"]:
        # ── Check if cf_bypass already found a real origin IP ────
        cf_bypass = getattr(result, "cf_bypass_findings", {})
        verified_origins = cf_bypass.get("verified_origins", []) if cf_bypass else []

        if verified_origins:
            origin = verified_origins[0]
            origin_ip = origin["ip"]
            progress.console.print(
                Panel(
                    f"[bold red]☁ CF DETECTED — but origin IP found via CF Bypass module![/bold red]\n\n"
                    f"  Real Origin IP : [bold red]{origin_ip}[/bold red]\n"
                    f"  Subdomain Leak : [cyan]{origin.get('subdomain', '?')}[/cyan]\n\n"
                    "[bold yellow]Firing stress test DIRECTLY at origin IP with Virtual Host header.\n"
                    "Cloudflare is being bypassed — traffic goes through the back door![/bold yellow]",
                    title="[bold red]💀 CF BYPASS + ORIGIN DIRECT ATTACK[/bold red]",
                    border_style="red",
                )
            )
            # Inject origin_ip into result for _run_wave to pick up
            result._stress_origin_ip = origin_ip
            # Fall through to normal/brutal mode below — protection overridden
        elif brutal:
            progress.console.print(
                Panel(
                    f"[bold red]⚠ PROTECTION DETECTED — but BRUTAL mode is active.\n\n"
                    f"Reason: {escape(protection['reason'])}\n\n"
                    "[bold yellow]Set BRUTAL_FORCE=1 to skip protection check.[/bold yellow]",
                    title="[bold yellow]🛡 PROTECTION DETECTED — BRUTAL ABORTED[/bold yellow]",
                    border_style="yellow",
                )
            )
            result.stress_findings = {
                "aborted": True,
                "reason": protection["reason"],
                "waves": [],
            }
            progress.update(task, completed=50)
            return
        else:
            progress.console.print(
                Panel(
                    f"[bold yellow]⚠ STRESS TEST ABORTED[/bold yellow]\n\n"
                    f"[bold]Reason:[/bold] {escape(protection['reason'])}\n\n"
                    "Target is protected by a WAF, CDN, or rate limiter.\n"
                    "Stress testing would be ineffective and may trigger IP ban.\n\n"
                    "[dim]Tip: Run CF Bypass module first — if it finds the real origin IP,\n"
                    "the stress test will automatically bypass Cloudflare.[/dim]",
                    title="[bold yellow]🛡 PROTECTION DETECTED — TEST SKIPPED[/bold yellow]",
                    border_style="yellow",
                )
            )
            result.stress_findings = {
                "aborted": True,
                "reason": protection["reason"],
                "waves": [],
            }
            progress.update(task, completed=50)
            return

    sitemap = getattr(result, "sitemap", [])
    # Origin IP set by CF bypass integration — None means normal mode
    _origin_ip: str | None = getattr(result, "_stress_origin_ip", None)

    # ── Brutal mode path
    if brutal:
        wave_results = _brutal_loop(target_url, sitemap, progress, task)
        result.stress_findings = {
            "aborted": False,
            "brutal": True,
            "target": target_url,
            "protection": protection,
            "waves": wave_results,
            "flags": [],
        }
        progress.update(task, completed=50)
        return

    # ── Normal mode path
    progress.console.print(
        Panel(
            f"[bold green]No WAF/rate-limiter detected.[/bold green]\n"
            f"[dim]{escape(protection['reason'])}[/dim]\n\n"
            f"[bold]Target:[/bold] [cyan]{escape(target_url)}[/cyan]\n"
            f"[bold]Waves :[/bold] {' → '.join(str(v) + ' VUs' for v in _WAVES)}\n\n"
            "[dim]Tip: set [bold]BRUTAL=1[/bold] env-var to enable infinite 1000-VU mode.[/dim]",
            title="[bold red]⚡ STRESS TEST STARTING[/bold red]",
            border_style="red",
        )
    )

    wave_results: list[dict] = []
    prev_p99: Optional[float] = None
    flags: list[str] = []
    total_waves = len(_WAVES)

    for wi, vu_count in enumerate(_WAVES):
        progress.update(
            task,
            description=f"[cyan]Stress:[/cyan] Wave {wi + 1}/{total_waves} — {vu_count} VUs firing…",
            completed=int((wi / total_waves) * 45) + 3,
        )

        if _GLOBAL_STOP_FLAG.is_set():
            progress.console.print(
                "  [bold yellow]⚡ STRESS TEST ENDED — USER STOPPED (Ctrl+C)[/bold yellow]"
            )
            break

        metrics = _run_wave(
            target_url, vu_count, sitemap, origin_ip=_origin_ip, hostname=hostname
        )
        wave_results.append(metrics)

        panel, _, p99 = _wave_panel(
            metrics,
            f"Wave {wi + 1}/{total_waves}",
            prev_p99,
            flags,
        )
        progress.console.print(panel)
        prev_p99 = p99

        if metrics["error_rate"] >= 80:
            progress.console.print(
                f"  [{C['bad']}]🛑 Server appears down ({metrics['error_rate']}% errors). "
                f"Stopping test early.[/{C['bad']}]"
            )
            flags.append("Test stopped early — server appears to be down/overloaded")
            break

    result.stress_findings = {
        "aborted": False,
        "brutal": False,
        "target": target_url,
        "protection": protection,
        "waves": wave_results,
        "flags": flags,
    }
    progress.update(task, completed=50)


# ─────────────────────────────────────────────────────────────────
# Display function
# ─────────────────────────────────────────────────────────────────


def score_stress(result):
    findings = result.stress_findings
    if not findings or findings.get("aborted"):
        return 100
    waves = findings.get("waves", [])
    if not waves:
        return 100
    last_wave = waves[-1]
    err_rate = last_wave.get("error_rate", 0)
    if err_rate >= 95:
        return 0
    elif err_rate >= 50:
        return 30
    elif err_rate >= 20:
        return 60
    return 100


def display_stress(result: ScanResult) -> None:
    console.print(
        Rule(f"[{C['bad']}]⚡   HTTP STRESS TEST RESULTS[/{C['bad']}]", style="red")
    )

    findings = getattr(result, "stress_findings", {})
    if not findings:
        console.print("  [dim]Stress test was not run.[/dim]\n")
        return

    if findings.get("aborted"):
        console.print(
            Panel(
                f"[bold yellow]Test aborted — {escape(findings.get('reason', '?'))}[/bold yellow]",
                title="[yellow]🛡 STRESS TEST SKIPPED[/yellow]",
                border_style="yellow",
            )
        )
        console.print()
        return

    waves = findings.get("waves", [])
    flags = findings.get("flags", [])

    if flags:
        console.print(
            f"  [{C['bad']}]⚠  {len(flags)} critical finding(s):[/{C['bad']}]"
        )
        for flag in flags:
            console.print(f"    [bold red]•[/bold red] {escape(flag)}")
        console.print()

    # Summary table
    tbl = Table(
        box=box.ROUNDED, border_style="red", header_style=C["head"], show_lines=True
    )
    tbl.add_column("Wave", justify="center", min_width=6)
    tbl.add_column("VUs", justify="right", min_width=6)
    tbl.add_column("Req/s", justify="right", min_width=8)
    tbl.add_column("Success%", justify="right", min_width=9)
    tbl.add_column("Error%", justify="right", min_width=8)
    tbl.add_column("P50 (ms)", justify="right", min_width=9)
    tbl.add_column("P95 (ms)", justify="right", min_width=9)
    tbl.add_column("P99 (ms)", justify="right", min_width=9)
    tbl.add_column("Status", justify="center", min_width=16)

    for wi, w in enumerate(waves):
        err = w["error_rate"]
        p99 = w["ms_p99"]

        if err >= 50:
            status = "[bold red]POTENTIAL DoS[/bold red]"
        elif err >= 20:
            status = "[bold yellow]STRUGGLING[/bold yellow]"
        elif err >= 5:
            status = "[yellow]DEGRADED[/yellow]"
        else:
            status = "[green]STABLE[/green]"

        err_col = "red" if err >= 20 else "yellow" if err >= 5 else "green"
        p99_col = "red" if p99 > 5000 else "yellow" if p99 > 2000 else "cyan"
        ok_pct = round(100 - err, 1)

        tbl.add_row(
            str(wi + 1),
            str(w["vu_count"]),
            str(w["rps"]),
            f"[green]{ok_pct}%[/green]",
            f"[{err_col}]{err}%[/{err_col}]",
            str(w["ms_median"]),
            str(w["ms_p95"]),
            f"[{p99_col}]{w['ms_p99']}[/{p99_col}]",
            status,
        )

    console.print(tbl)
    console.print()

    # Throughput summary
    if waves:
        peak_rps = max(w["rps"] for w in waves)
        peak_vu = waves[[-w["rps"] for w in waves].index(-peak_rps)]["vu_count"]
        total_req = sum(w["total"] for w in waves)
        console.print(
            f"  [bold]Total requests fired:[/bold] [cyan]{total_req:,}[/cyan]   "
            f"[bold]Peak throughput:[/bold] [cyan]{peak_rps} req/s[/cyan] at {peak_vu} VUs\n"
        )


def export_stress(result: ScanResult, W: callable) -> None:
    W("### 📈 Stress Test (Load Testing)\n\n")
    sf = result.stress_findings
    if sf:
        if sf.get("aborted"):
            W(
                f"> [!NOTE]\n> **Stress test was automatically aborted.**\n> **Reason:** {sf.get('reason', 'Unknown')}\n\n"
            )
        else:
            summary = sf.get("summary", {})
            if summary:
                W(
                    md_table(
                        ["Metric", "Value"],
                        [
                            ["Total Waves", summary.get("total_waves", "?")],
                            [
                                "Total Requests",
                                f"{summary.get('total_requests', 0):,}",
                            ],
                            ["Peak VUs", summary.get("peak_vus", "?")],
                            [
                                "Overall Error Rate",
                                f"{summary.get('error_rate_pct', 0):.1f}%",
                            ],
                            [
                                "Avg P99 Latency",
                                f"{summary.get('avg_p99_ms', 0):.0f}ms",
                            ],
                            [
                                "Max P99 Latency",
                                f"{summary.get('max_p99_ms', 0):.0f}ms",
                            ],
                            ["Flags", ", ".join(sf.get("flags", [])) or "None"],
                        ],
                    )
                )
            waves = sf.get("waves", [])
            if waves:
                W("\n#### Wave-by-Wave Breakdown\n\n")
                rows = [
                    [
                        w.get("vu_count", "?"),
                        f"{w.get('rps', 0):.1f}",
                        f"{w.get('error_rate', 0):.1f}%",
                        f"{w.get('ms_p99', 0)}ms",
                        w.get("status", "?"),
                    ]
                    for w in waves
                ]
                W(md_table(["VUs", "RPS", "Error Rate", "P99 Latency", "Status"], rows))
    else:
        W("- Stress test was not run.\n")
    W("\n")
