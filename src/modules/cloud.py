"""cloud.py – Cloud & Bucket Sniper module

Provides `run_cloud` which enumerates potential bucket names for a target and checks
for public accessibility (unauthenticated only). Findings are appended to ``ScanResult.cloud_findings``.
"""

from __future__ import annotations

from rich.markup import escape
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text

import re
from typing import List

from src.config import SESSION, rate_limiter, TIMEOUT, console, C
from src.models import ScanResult
from src.scoring import score_and_report

# Simple built‑in wordlist – can be extended via optional external list
_BUILTIN_BUCKET_WORDS = [
    "{target}",
    "{target}-backup",
    "{target}-dev",
    "{target}-static",
    "{target}-assets",
    "{target}-files",
    "{target}-media",
    "{target}-prod",
]

# Provider URL templates
_AWS_TEMPLATE = "https://{bucket}.s3.amazonaws.com/"
_FIREBASE_TEMPLATE = "https://{bucket}.firebaseapp.com/"
_DO_SPACES_TEMPLATE = "https://{bucket}.nyc3.digitaloceanspaces.com/"


def _probe_bucket(url: str) -> dict:
    """Perform a HEAD request to ``url`` and return a dict with status info.
    The bucket is considered public if the response is 200 and contains the
    ``x-amz-bucket-region`` header (AWS) or returns a valid page for Firebase/DO.
    """
    try:
        resp = SESSION.head(url, timeout=TIMEOUT, allow_redirects=True)
    except Exception:
        return {"url": url, "public": False, "error": "request_failed"}

    public = resp.status_code == 200 and (
        "x-amz-bucket-region" in resp.headers
        or resp.headers.get("content-type", "").startswith("text/html")
    )
    return {"url": url, "public": public, "status": resp.status_code}


def _list_bucket_objects(bucket_url: str) -> List[str]:
    """Retrieve a short listing of objects for a public bucket using the S3 List API.
    The function caps the number of objects to 20 and the total download size to 5 MB.
    """
    # Use the S3 XML API – works for S3‑compatible providers as well.
    list_url = f"{bucket_url.rstrip('/')}/?list-type=2&max-keys=20"
    try:
        resp = SESSION.get(list_url, timeout=TIMEOUT)
        if resp.status_code != 200:
            return []
        # Very lightweight parsing – extract <Key> entries.
        keys = re.findall(r"<Key>([^<]+)</Key>", resp.text)
        return [f"{bucket_url}{key}" for key in keys]
    except Exception:
        return []


def run_cloud(hostname: str, result: ScanResult, progress, task) -> None:
    """Enumerate potential bucket names for ``hostname`` and check public accessibility."""
    # Build the candidate list
    patterns = _BUILTIN_BUCKET_WORDS.copy()
    candidates = [p.format(target=hostname) for p in patterns]

    # Provider suffixes – each candidate is tested against three providers.
    provider_templates = [_AWS_TEMPLATE, _FIREBASE_TEMPLATE, _DO_SPACES_TEMPLATE]
    findings = []

    total = len(candidates) * len(provider_templates)
    done = 0

    for bucket in candidates:
        for tmpl in provider_templates:
            url = tmpl.format(bucket=bucket)
            rate_limiter.wait()
            info = _probe_bucket(url)
            if info.get("public"):
                # Retrieve a tiny object listing for reporting purposes.
                objects = _list_bucket_objects(url)
                info["objects"] = objects
                findings.append(info)
                progress.console.print(
                    Panel(
                        f"[bold green]Public Bucket Found![/bold green]\nURL: {url}",
                        title="Cloud Bucket Sniper",
                        border_style="green",
                    )
                )

            done += 1
            # Assuming module gets 50% max from the loop (similar to fuzzing)
            progress.update(
                task,
                description=f"[cyan]Cloud:[/cyan] {done}/{total} buckets…",
                completed=int((done / total) * 50),
            )

    result.cloud_findings = findings


# Display function
    score_and_report(result, "cloud")


def score_cloud(result):
    if not result.cloud_findings:
        return 100
    return max(0, 100 - min(len(result.cloud_findings) * 20, 80))


def display_cloud(result: ScanResult) -> None:
    console.print(
        Rule(
            f"[{C['accent']}]☁️   CLOUD & BUCKET SNIPER[/{C['accent']}]", style="magenta"
        )
    )
    if not result.cloud_findings:
        console.print("  [dim]No public cloud buckets discovered.[/dim]")
        console.print()
        return

    for bucket in result.cloud_findings:
        if bucket.get("public"):
            panel_content = "[bold green]Public Bucket Found[/bold green]\n"
            panel_content += f"URL: [cyan]{escape(bucket.get('url', ''))}[/cyan]\n"

            objects = bucket.get("objects", [])
            if objects:
                panel_content += (
                    f"\n[bold]Files Found ({len(objects)} max 20):[/bold]\n"
                )
                for obj in objects:
                    panel_content += f" - {escape(obj)}\n"
            else:
                panel_content += "\n[dim]No accessible files listed.[/dim]\n"

            console.print(Panel(Text.from_markup(panel_content), border_style="green"))
    console.print()


def export_cloud(result: ScanResult, W: callable) -> None:
    W("## ☁️ Cloud & Bucket Sniper\n\n")
    if not result.cloud_findings:
        W("- ✅ No public cloud buckets discovered.\n\n")
        return

    for bucket in result.cloud_findings:
        if bucket.get("public"):
            W(f"### Public Bucket Found: `{bucket.get('url', '')}`\n\n")
            objects = bucket.get("objects", [])
            if objects:
                W(f"**Files Found ({len(objects)} max 20):**\n")
                for obj in objects:
                    W(f"- {obj}\n")
            else:
                W("- *No accessible files listed.*\n")
    W("\n")
