"""
src/modules/forms.py — Module 5: HTML form enumeration + CSRF token detection.
"""

from bs4 import BeautifulSoup

from src.config import rate_limiter, SESSION, TIMEOUT
from src.models import ScanResult

CSRF_TOKEN_NAMES = {
    "csrf", "csrftoken", "_token", "authenticity_token",
    "__requestverificationtoken", "xsrf", "anti-csrf",
    "_csrf_token", "csrf_token", "token",
}

# Normalised set (strip hyphens/underscores) for looser matching
_CSRF_NORMALISED = {t.replace("-", "").replace("_", "") for t in CSRF_TOKEN_NAMES}


def run_form_audit(target_url: str, result: ScanResult, progress, task) -> None:
    progress.update(task, description="[cyan]Forms:[/cyan] Scraping HTML…")
    rate_limiter.wait()

    forms_found: list[dict] = []

    try:
        resp = SESSION.get(target_url, timeout=TIMEOUT, allow_redirects=True)
        if resp.ok:
            soup = BeautifulSoup(resp.text, "html.parser")
            for i, form in enumerate(soup.find_all("form"), start=1):
                action   = form.get("action", "(current page)")
                method   = form.get("method", "GET").upper()
                inputs   = []
                has_csrf = False

                for inp in form.find_all(["input", "textarea", "select"]):
                    name  = inp.get("name", "")
                    itype = inp.get("type", inp.name)
                    inputs.append({"name": name, "type": itype})
                    if name.lower().replace("-", "").replace("_", "") in _CSRF_NORMALISED:
                        has_csrf = True

                forms_found.append({
                    "form_num": i,
                    "action":   action,
                    "method":   method,
                    "inputs":   inputs,
                    "has_csrf": has_csrf,
                    "risk":     ("low" if has_csrf
                                 else ("high" if method == "POST" else "medium")),
                })
    except Exception:
        pass

    result.forms = forms_found
    progress.advance(task, 50)
