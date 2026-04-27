"""
src/modules/jwt_cracker.py — JWT & Token Analyzer + Weak-Secret Cracker.

Phase 1 — Discovery:
  Sniff all Set-Cookie and response headers from result.headers (from
  headers.py) plus the raw sitemap pages looking for JWT tokens (eyJ…).

Phase 2 — Decode:
  Base64-decode the header + payload and pretty-print the claims
  (sub, iss, exp, iat, role, email, etc.) so testers can read user data.

Phase 3 — Crack:
  Attempt HMAC-SHA256 signature verification with a built-in wordlist
  of 200 common weak secrets. If the secret is found, the token can be
  forged — full admin impersonation.

Phase 4 — Flag:
  - alg:none attack surface (unsigned token accepted?)
  - Expired tokens still accepted by the server
  - Weak algorithm (HS256 vs RS256)
  - Sensitive PII in payload (email, password, role=admin)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time as _time
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.markup import escape
from rich.panel import Panel
from rich.rule import Rule

from src.config import SESSION, RateLimiter, TIMEOUT, console, C
from src.models import ScanResult

_rl = RateLimiter(rps=10.0, use_jitter=False)

# ─────────────────────────────────────────────────────────────────
# JWT regex — matches standard 3-part base64url tokens
# ─────────────────────────────────────────────────────────────────

_JWT_RE = re.compile(
    r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"
)

# ─────────────────────────────────────────────────────────────────
# Common weak JWT secrets wordlist (200 entries)
# ─────────────────────────────────────────────────────────────────


try:
    with open("src/wordlists/jwt_secret.txt") as _f:
        _WEAK_SECRETS = [line.strip() for line in _f if line.strip()]
except FileNotFoundError:
    _WEAK_SECRETS = [
        "",
        "secret",
        "password",
        "12345",
        "123456",
        "1234567890",
        "admin",
        "administrator",
        "root",
        "test",
    ]


# ─────────────────────────────────────────────────────────────────
# JWT helpers
# ─────────────────────────────────────────────────────────────────


def _b64_decode(s: str) -> bytes:
    """Decode base64url with padding."""
    s = s.replace("-", "+").replace("_", "/")
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.b64decode(s)


def _decode_jwt(token: str) -> tuple[dict, dict, str] | None:
    """Return (header, payload, signature_b64) or None on failure."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header = json.loads(_b64_decode(parts[0]))
        payload = json.loads(_b64_decode(parts[1]))
        return header, payload, parts[2]
    except Exception:
        return None


def _crack_hs(token: str, header: dict, payload: dict) -> str | None:
    """Try to recover the HMAC-SHA* signing secret."""
    alg = header.get("alg", "").upper()
    if alg not in ("HS256", "HS384", "HS512"):
        return None

    hash_map = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }
    hash_fn = hash_map[alg]

    parts = token.split(".")
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    sig_bytes = _b64_decode(parts[2])

    for secret in _WEAK_SECRETS:
        candidate = hmac.new(secret.encode(), signing_input, hash_fn).digest()
        if hmac.compare_digest(candidate, sig_bytes):
            return secret
    return None


def _analyze_claims(payload: dict) -> list[str]:
    """Flag dangerous or sensitive claims."""
    flags: list[str] = []
    now = int(_time.time())

    exp = payload.get("exp")
    iat = payload.get("iat")

    if exp and exp < now:
        flags.append(f"EXPIRED (exp={exp}, now={now})")
    if not exp:
        flags.append("No expiration (exp missing) — token lives forever")
    if iat and (now - iat) > 86400 * 30:
        flags.append("Token issued >30 days ago")

    role = payload.get("role") or payload.get("roles") or payload.get("scope", "")
    if isinstance(role, str) and "admin" in role.lower():
        flags.append(f"ADMIN role detected: {role}")

    for sensitive in ("password", "passwd", "secret", "credit_card", "ssn", "dob"):
        if sensitive in payload:
            flags.append(f"Sensitive field '{sensitive}' in payload")

    if payload.get("email") or payload.get("email_address"):
        flags.append("PII: email address present in payload")

    return flags


# ─────────────────────────────────────────────────────────────────
# Discovery: fetch pages and extract JWTs
# ─────────────────────────────────────────────────────────────────


def _collect_tokens_from_headers(result: ScanResult) -> list[tuple[str, str]]:
    """Extract JWT tokens from stored HTTP headers (Set-Cookie, Authorization, etc.)."""
    found: list[tuple[str, str]] = []
    headers_dict = getattr(result, "headers", {})
    for hdr_name, hdr_val in headers_dict.items():
        if not isinstance(hdr_val, str):
            continue
        for m in _JWT_RE.finditer(hdr_val):
            found.append((m.group(0), f"Header: {hdr_name}"))
    return found


def _collect_tokens_from_pages(sources: list[str]) -> list[tuple[str, str]]:
    """Fetch pages and hunt for JWTs in the response body."""
    found: list[tuple[str, str]] = []

    def _fetch_and_scan(url: str) -> list[tuple[str, str]]:
        _rl.wait()
        try:
            resp = SESSION.get(url, timeout=TIMEOUT, allow_redirects=True, stream=True)
            body = resp.raw.read(500_000, decode_content=True).decode(
                "utf-8", errors="ignore"
            )
            resp.close()
            # Also check response headers for this specific request
            hdrs_text = " ".join(resp.headers.values())
            text = body + " " + hdrs_text
            return [(m.group(0), url) for m in _JWT_RE.finditer(text)]
        except Exception:
            return []

    with ThreadPoolExecutor(max_workers=10) as pool:
        for future in as_completed(
            {pool.submit(_fetch_and_scan, u): u for u in sources}
        ):
            found.extend(future.result())

    return found


# ─────────────────────────────────────────────────────────────────
# Module entry point
# ─────────────────────────────────────────────────────────────────


def run_jwt_cracker(target_url: str, result: ScanResult, progress, task) -> None:
    """Discover, decode, and crack JWT tokens found in headers and pages."""

    progress.update(task, description="[cyan]JWT Cracker:[/cyan] Collecting tokens…")

    # Phase 1: collect from stored headers
    tokens_raw: list[tuple[str, str]] = _collect_tokens_from_headers(result)

    # Phase 2: scan a sample of pages
    sources = list(dict.fromkeys(getattr(result, "sitemap", []) + [target_url]))[
        :30
    ]  # limit to 30 pages for speed

    progress.update(
        task,
        description=f"[cyan]JWT Cracker:[/cyan] Scanning {len(sources)} pages…",
        completed=5,
    )
    tokens_raw.extend(_collect_tokens_from_pages(sources))

    # Deduplicate by token value
    seen: set[str] = set()
    unique_tokens: list[tuple[str, str]] = []
    for token, source in tokens_raw:
        if token not in seen:
            seen.add(token)
            unique_tokens.append((token, source))

    progress.update(
        task,
        description=f"[cyan]JWT Cracker:[/cyan] Analyzing {len(unique_tokens)} token(s)…",
        completed=20,
    )

    findings: list[dict] = []

    for i, (token, source) in enumerate(unique_tokens):
        decoded = _decode_jwt(token)
        if not decoded:
            continue
        header, payload, sig = decoded

        alg = header.get("alg", "?")
        typ = header.get("typ", "JWT")  # noqa: F841

        # Phase 3: crack
        cracked_secret: str | None = None
        if alg.startswith("HS"):
            cracked_secret = _crack_hs(token, header, payload)

        # Phase 4: analyze claims
        flags = _analyze_claims(payload)

        # alg:none check
        if alg.lower() == "none" or alg == "":
            flags.append("ALG:NONE — signature not verified!")

        severity = "low"
        if cracked_secret is not None:
            severity = "critical"
        elif any("ADMIN" in f or "EXPIRED" in f or "ALG:NONE" in f for f in flags):
            severity = "high"
        elif flags:
            severity = "medium"

        finding = {
            "token_preview": token[:40] + "…",
            "source": source,
            "header": header,
            "payload": payload,
            "algorithm": alg,
            "cracked_secret": cracked_secret,
            "flags": flags,
            "severity": severity,
        }
        findings.append(finding)

        if cracked_secret is not None:
            progress.console.print(
                Panel(
                    f"[bold red]JWT SECRET CRACKED![/bold red]\n"
                    f"[bold]Source :[/bold] [cyan]{escape(source)}[/cyan]\n"
                    f"[bold]Secret :[/bold] [yellow]{escape(cracked_secret)}[/yellow]\n"
                    f"[bold]Alg    :[/bold] {escape(alg)}\n"
                    f"[bold]Subject:[/bold] {escape(str(payload.get('sub', '?')))}\n"
                    f"[bold]Role   :[/bold] {escape(str(payload.get('role', payload.get('roles', '?'))))}",
                    title="[bold red]🔓 JWT CRACKED — TOKEN FORGERY POSSIBLE[/bold red]",
                    border_style="red",
                )
            )
        elif severity in ("high", "medium"):
            progress.console.print(
                Panel(
                    f"[bold]Source :[/bold] [cyan]{escape(source)}[/cyan]\n"
                    f"[bold]Alg    :[/bold] {escape(alg)}\n"
                    f"[bold]Flags  :[/bold] "
                    + " | ".join(escape(f) for f in flags[:3]),
                    title=f"[bold yellow]⚠ JWT ISSUE — {escape(alg)}[/bold yellow]",
                    border_style="yellow",
                )
            )

        pct = 20 + int(((i + 1) / max(len(unique_tokens), 1)) * 30)
        progress.update(task, completed=min(50, pct))

    result.jwt_findings = findings
    progress.update(task, completed=50)


# ─────────────────────────────────────────────────────────────────
# Display function
# ─────────────────────────────────────────────────────────────────


def display_jwt_cracker(result: ScanResult) -> None:
    console.print(
        Rule(f"[{C['bad']}]🔓   JWT & TOKEN CRACKER[/{C['bad']}]", style="red")
    )

    findings = getattr(result, "jwt_findings", [])
    if not findings:
        console.print("  [dim]No JWT tokens discovered.[/dim]\n")
        return

    cracked = [f for f in findings if f["cracked_secret"] is not None]
    console.print(
        f"  Found [bold yellow]{len(findings)}[/bold yellow] token(s) — "
        f"[bold red]{len(cracked)} cracked[/bold red]\n"
    )

    for f in findings:
        sev_col = (
            "red"
            if f["severity"] == "critical"
            else "yellow"
            if f["severity"] == "high"
            else "dim"
        )

        payload_lines = "\n".join(
            f"  [dim]{escape(k)}[/dim]: {escape(str(v)[:80])}"
            for k, v in list(f["payload"].items())[:8]
        )
        flags_line = "\n".join(
            f"  ⚠ [yellow]{escape(flag)}[/yellow]" for flag in f["flags"]
        )
        crack_line = (
            f"\n[bold green]✓ SECRET CRACKED: [yellow]{escape(f['cracked_secret'])}[/yellow][/bold green]"
            if f["cracked_secret"] is not None
            else ""
        )

        console.print(
            Panel(
                f"[bold]Source    :[/bold] [cyan]{escape(f['source'])}[/cyan]\n"
                f"[bold]Algorithm :[/bold] {escape(f['algorithm'])}\n"
                f"[bold]Token     :[/bold] [dim]{escape(f['token_preview'])}[/dim]\n\n"
                f"[bold]Payload Claims:[/bold]\n{payload_lines}\n"
                + (f"\n[bold]Flags:[/bold]\n{flags_line}" if flags_line else "")
                + crack_line,
                title=f"[bold {sev_col}]JWT — {escape(f['algorithm'])} [{f['severity'].upper()}][/bold {sev_col}]",
                border_style=sev_col,
            )
        )

    console.print()
