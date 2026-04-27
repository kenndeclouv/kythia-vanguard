"""
src/modules/git_dumper.py — Git Source Code Dumper.

When a /.git/ directory is publicly accessible, this module reconstructs
the source code repository by:
  1. Fetching /.git/HEAD to confirm exposure
  2. Downloading /.git/COMMIT_EDITMSG, config, description, packed-refs
  3. Parsing /.git/index to enumerate tracked files
  4. Downloading loose and packed objects to reassemble blobs
  5. Writing reconstructed files to reports/git_dump/<hostname>/
"""

from __future__ import annotations

import re
import struct
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urljoin

from rich import box
from rich.markup import escape
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

from src.config import SESSION, rate_limiter, TIMEOUT, console, C
from src.models import ScanResult
from src.scoring import score_and_report

# ─────────────────────────────────────────────────────────────────
# Known static git files to always fetch
# ─────────────────────────────────────────────────────────────────

_STATIC_FILES = [
    "HEAD",
    "config",
    "description",
    "COMMIT_EDITMSG",
    "packed-refs",
    "ORIG_HEAD",
    "FETCH_HEAD",
    "info/refs",
    "info/exclude",
    "logs/HEAD",
    "refs/heads/master",
    "refs/heads/main",
    "refs/remotes/origin/HEAD",
    "refs/remotes/origin/master",
    "refs/remotes/origin/main",
]

_OBJECT_RE = re.compile(r"\b([0-9a-f]{40})\b")
_PACK_RE = re.compile(r"pack-([0-9a-f]{40})\.(idx|pack)")
_INDEX_FILENAME_RE = re.compile(rb"((?:[a-zA-Z0-9_./-]+)+\.[a-zA-Z0-9]{1,10})")


# ─────────────────────────────────────────────────────────────────
# Fetch helpers
# ─────────────────────────────────────────────────────────────────


def _fetch_raw(base_git_url: str, path: str, timeout: int = TIMEOUT) -> bytes | None:
    """Download a single /.git/<path> file, return raw bytes or None."""
    url = urljoin(base_git_url, path)
    rate_limiter.wait()
    try:
        resp = SESSION.get(url, timeout=timeout, allow_redirects=False, stream=True)
        if resp.status_code != 200:
            return None
        # Cap at 10 MB per object
        return resp.raw.read(10_000_000, decode_content=True)
    except Exception:
        return None


def _fetch_text(base_git_url: str, path: str) -> str | None:
    raw = _fetch_raw(base_git_url, path)
    if raw is None:
        return None
    return raw.decode("utf-8", errors="replace")


# ─────────────────────────────────────────────────────────────────
# Object store helpers
# ─────────────────────────────────────────────────────────────────


def _object_url(sha: str) -> str:
    """Convert a sha1 to its relative objects path."""
    return f"objects/{sha[:2]}/{sha[2:]}"


def _decompress_object(data: bytes) -> tuple[str, bytes]:
    """Decompress a zlib-compressed git object and return (type, content)."""
    try:
        raw = zlib.decompress(data)
    except Exception:
        return "unknown", data

    # Header format: "<type> <size>\0<content>"
    null = raw.index(b"\x00")
    header = raw[:null].decode("ascii", errors="replace")
    content = raw[null + 1 :]
    obj_type = header.split(" ")[0]
    return obj_type, content


def _extract_sha1s(text: str) -> set[str]:
    """Pull all 40-char hex SHA-1 strings from a block of text."""
    return set(_OBJECT_RE.findall(text))


# ─────────────────────────────────────────────────────────────────
# Index parser — pulls filenames from the binary git index
# ─────────────────────────────────────────────────────────────────


def _parse_index_filenames(data: bytes) -> list[str]:
    """
    Minimal parser for the git index (v2) to extract tracked file paths.
    Reference: https://git-scm.com/docs/index-format
    """
    filenames: list[str] = []
    if len(data) < 12 or data[:4] != b"DIRC":
        return filenames

    try:
        num_entries = struct.unpack(">I", data[8:12])[0]
        offset = 12
        for _ in range(num_entries):
            if offset + 62 > len(data):
                break
            # Skip fixed-size fields (62 bytes), then read NUL-terminated filename
            name_start = offset + 62
            nul = data.find(b"\x00", name_start)
            if nul == -1:
                break
            name = data[name_start:nul].decode("utf-8", errors="replace")
            filenames.append(name)
            # Entry size is padded to multiple of 8 bytes
            entry_size = nul + 1 - offset
            padded = (entry_size + 7) & ~7
            offset += padded
    except Exception:
        pass

    return filenames


# ─────────────────────────────────────────────────────────────────
# Blob reconstruction
# ─────────────────────────────────────────────────────────────────


def _write_blob(out_dir: Path, filename: str, content: bytes) -> None:
    """Write a reconstructed file blob to the output directory."""
    target = out_dir / filename
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        target.write_bytes(content)
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────
# Module entry point
# ─────────────────────────────────────────────────────────────────


def run_git_dumper(
    target_url: str, hostname: str, result: ScanResult, progress, task
) -> None:
    """Detect and dump an exposed /.git/ directory, reconstructing source code."""

    base_git = target_url.rstrip("/") + "/.git/"
    progress.update(
        task, description="[cyan]Git Dumper:[/cyan] Checking /.git/ exposure…"
    )

    # ── Step 1: Confirm exposure via HEAD
    head_content = _fetch_text(base_git, "HEAD")
    if not head_content or "ref:" not in head_content:
        result.git_findings = {
            "exposed": False,
            "files": [],
            "filenames": [],
            "dump_path": "",
        }
        progress.update(task, completed=50)
        return

    progress.console.print(
        Panel(
            f"[bold red]/.git/ IS PUBLICLY ACCESSIBLE![/bold red]\n"
            f"Target  : [cyan]{escape(target_url)}[/cyan]\n"
            f"HEAD    : [yellow]{escape(head_content.strip())}[/yellow]\n\n"
            f"[bold]Initiating full repository reconstruction…[/bold]",
            title="[bold red]💀 GIT REPO EXPOSED[/bold red]",
            border_style="red",
        )
    )

    # Output directory
    hostname_clean = re.sub(r"[^\w\-.]", "_", hostname)
    out_dir = Path("reports") / "git_dump" / hostname_clean
    out_dir.mkdir(parents=True, exist_ok=True)

    fetched_files: list[str] = []
    sha1_queue: set[str] = set()
    processed_sha1s: set[str] = set()
    filenames_found: list[str] = []

    # ── Step 2: Download static git files
    progress.update(
        task,
        description="[cyan]Git Dumper:[/cyan] Downloading static git files…",
        completed=5,
    )

    def _save_static(path: str):
        raw = _fetch_raw(base_git, path)
        if raw:
            dest = out_dir / ".git" / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(raw)
            return path, raw.decode("utf-8", errors="replace")
        return path, None

    static_results: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(_save_static, p): p for p in _STATIC_FILES}
        for future in as_completed(futures):
            path, text = future.result()
            if text:
                fetched_files.append(path)
                static_results[path] = text
                # Harvest SHA1s from every text file
                sha1_queue.update(_extract_sha1s(text))

    # Extract branch SHA1 from HEAD reference
    head_ref = head_content.strip()  # e.g. "ref: refs/heads/main"
    if head_ref.startswith("ref: "):
        ref_path = head_ref[5:]
        ref_text = static_results.get(ref_path) or _fetch_text(base_git, ref_path)
        if ref_text:
            sha1_queue.update(_extract_sha1s(ref_text))

    # Extract SHA1s from packed-refs
    if "packed-refs" in static_results:
        sha1_queue.update(_extract_sha1s(static_results["packed-refs"]))

    progress.update(task, completed=15)

    # ── Step 3: Parse git index to enumerate filenames
    index_raw = _fetch_raw(base_git, "index")
    if index_raw:
        dest = out_dir / ".git" / "index"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(index_raw)
        filenames_found = _parse_index_filenames(index_raw)
        fetched_files.append("index")

    progress.update(
        task,
        description=f"[cyan]Git Dumper:[/cyan] {len(filenames_found)} tracked files found…",
        completed=20,
    )

    # ── Step 4: Check for pack files
    info_packs = _fetch_text(base_git, "objects/info/packs")
    if info_packs:
        for m in _PACK_RE.finditer(info_packs):
            pack_sha = m.group(1)
            for ext in ("idx", "pack"):
                pack_path = f"objects/pack/pack-{pack_sha}.{ext}"
                raw = _fetch_raw(base_git, pack_path, timeout=20)
                if raw:
                    dest = out_dir / ".git" / pack_path
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(raw)
                    fetched_files.append(pack_path)

    progress.update(task, completed=25)

    # ── Step 5: Download loose objects
    progress.update(
        task,
        description=f"[cyan]Git Dumper:[/cyan] Fetching {len(sha1_queue)} objects…",
        completed=25,
    )

    blobs_written = 0
    max_objects = 500  # prevent runaway downloads

    def _fetch_object(sha: str) -> tuple[str, bytes | None]:
        return sha, _fetch_raw(base_git, _object_url(sha))

    rounds = 0
    while sha1_queue - processed_sha1s and rounds < 6:
        batch = list(sha1_queue - processed_sha1s)[:max_objects]
        rounds += 1

        with ThreadPoolExecutor(max_workers=12) as pool:
            futures = {pool.submit(_fetch_object, sha): sha for sha in batch}
            for future in as_completed(futures):
                sha, raw = future.result()
                processed_sha1s.add(sha)

                if not raw:
                    continue

                # Save raw object
                obj_path = out_dir / ".git" / _object_url(sha)
                obj_path.parent.mkdir(parents=True, exist_ok=True)
                obj_path.write_bytes(raw)
                fetched_files.append(_object_url(sha))

                # Decompress and harvest child SHA1s
                obj_type, content = _decompress_object(raw)

                if obj_type == "blob":
                    blobs_written += 1
                elif obj_type in ("tree", "commit"):
                    # Trees and commits reference other SHA1s
                    child_shas = _extract_sha1s(raw.decode("utf-8", errors="replace"))
                    sha1_queue.update(child_shas - processed_sha1s)

        pct = min(48, 25 + int((len(processed_sha1s) / max(len(sha1_queue), 1)) * 23))
        progress.update(
            task,
            description=f"[cyan]Git Dumper:[/cyan] {len(processed_sha1s)} objects fetched…",
            completed=pct,
        )

    # ── Step 6: Reconstruct blobs to readable files using index filenames
    progress.update(
        task,
        description="[cyan]Git Dumper:[/cyan] Reconstructing source files…",
        completed=48,
    )

    reconstructed: list[str] = []
    # We match blobs to filenames heuristically since we don't resolve the tree fully
    # This writes all blob contents alongside their object IDs for manual inspection
    blob_dir = out_dir / "blobs"
    blob_dir.mkdir(parents=True, exist_ok=True)

    for sha in list(processed_sha1s):
        obj_path = out_dir / ".git" / _object_url(sha)
        if obj_path.exists():
            raw = obj_path.read_bytes()
            obj_type, content = _decompress_object(raw)
            if obj_type == "blob" and content:
                blob_file = blob_dir / sha
                blob_file.write_bytes(content)
                reconstructed.append(sha)

    # Write filenames manifest
    if filenames_found:
        manifest = out_dir / "TRACKED_FILES.txt"
        manifest.write_text("\n".join(filenames_found), encoding="utf-8")

    result.git_findings = {
        "exposed": True,
        "head": head_content.strip(),
        "files_fetched": len(fetched_files),
        "objects_downloaded": len(processed_sha1s),
        "blobs_reconstructed": len(reconstructed),
        "tracked_filenames": filenames_found,
        "dump_path": str(out_dir.resolve()),
    }

    progress.console.print(
        Panel(
            f"[bold green]Repository dump complete![/bold green]\n"
            f"Files fetched    : [cyan]{len(fetched_files)}[/cyan]\n"
            f"Objects downloaded: [cyan]{len(processed_sha1s)}[/cyan]\n"
            f"Blobs extracted  : [cyan]{len(reconstructed)}[/cyan]\n"
            f"Tracked filenames: [cyan]{len(filenames_found)}[/cyan]\n"
            f"Output directory : [yellow]{escape(str(out_dir.resolve()))}[/yellow]",
            title="[bold green]✅ GIT DUMP COMPLETE[/bold green]",
            border_style="green",
        )
    )
    progress.update(task, completed=50)
    score_and_report(result, "git_dumper")


# ─────────────────────────────────────────────────────────────────
# Display function
# ─────────────────────────────────────────────────────────────────


def score_git_dumper(result):
    return 0 if result.git_findings else 100


def display_git_dumper(result: ScanResult) -> None:
    console.print(
        Rule(f"[{C['bad']}]📂   GIT SOURCE CODE DUMPER[/{C['bad']}]", style="red")
    )

    findings = getattr(result, "git_findings", {})
    if not findings or not findings.get("exposed"):
        console.print("  [dim]/.git/ directory is not publicly accessible.[/dim]\n")
        return

    # Summary panel
    console.print(
        Panel(
            f"[bold red]/.git/ WAS PUBLICLY EXPOSED AND DUMPED![/bold red]\n\n"
            f"[bold]HEAD           :[/bold] [yellow]{escape(findings.get('head', '?'))}[/yellow]\n"
            f"[bold]Git files fetched :[/bold] [cyan]{findings.get('files_fetched', 0)}[/cyan]\n"
            f"[bold]Objects downloaded:[/bold] [cyan]{findings.get('objects_downloaded', 0)}[/cyan]\n"
            f"[bold]Blobs extracted   :[/bold] [cyan]{findings.get('blobs_reconstructed', 0)}[/cyan]\n"
            f"[bold]Output path       :[/bold] [green]{escape(findings.get('dump_path', '?'))}[/green]",
            title="[bold red]💀 GIT REPOSITORY EXPOSED[/bold red]",
            border_style="red",
        )
    )
    console.print()

    # Tracked filenames table
    filenames = findings.get("tracked_filenames", [])
    if filenames:
        console.print(Rule("[bold]Tracked Files (from git index)[/bold]", style="dim"))
        tbl = Table(box=box.MINIMAL, border_style="dim", header_style=C["subtle"])
        tbl.add_column("File Path", style=C["warn"])
        for fn in filenames[:60]:
            tbl.add_row(escape(fn))
        if len(filenames) > 60:
            tbl.add_row(
                f"[dim]… and {len(filenames) - 60} more in {findings.get('dump_path', '')}[/dim]"
            )
        console.print(tbl)

    console.print()


def export_git_dumper(result: ScanResult, W: callable) -> None:
    if result.git_findings:
        W("## 📦 Git Dumper\n\n")
        for k, v in result.git_findings.items():
            W(f"- **{k}**: {v}\n")
        W("\n")
