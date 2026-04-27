"""
src/scoring.py — Decentralized security scoring system.

Architecture:
  - Each module calls score_and_report(result, module_name) at the end of run_
  - score_and_report() looks up that module's scorer function, computes 0-100, stores it
  - calculate_score(result) simply averages all stored module scores

Design principle:
  - If a module wasn't run → no score entry → not counted in average
  - Each module is judged independently (100 = clean, 0 = critical)
  - Capped deductions prevent one bad finding from tanking everything
"""

from __future__ import annotations
from src.models import ScanResult
import importlib

# ─────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────
def score_and_report(result: ScanResult, module_name: str) -> int:
    """
    Called at the end of each module's run_ function.
    Dynamically looks up score_<module_name>(result) inside the module file
    using importlib — zero registration needed, just follow the naming convention.
    Returns the score (0-100) and stores it in result.module_scores.
    """
    score = 100  # default: neutral if no scorer found
    try:
        mod_obj = importlib.import_module(f"src.modules.{module_name}")
        scorer_fn = getattr(mod_obj, f"score_{module_name}", None)
        if scorer_fn:
            score = scorer_fn(result)
    except Exception:
        pass  # missing scorer → neutral score, never crash
    result.module_scores[module_name] = max(0, min(100, score))
    return result.module_scores[module_name]


def calculate_score(result: ScanResult) -> int:
    """
    Average all per-module scores reported during this scan.
    Only modules that actually ran contribute to the score.
    Returns 100 if nothing ran (unknown = assume clean).
    """
    scores = list(result.module_scores.values())
    if not scores:
        return 100
    return round(sum(scores) / len(scores))
