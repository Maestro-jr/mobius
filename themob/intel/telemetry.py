"""Opt-in, anonymised telemetry: a projection of the local corpus, safe to share.

This is the one part of the intelligence layer that may leave the machine, and it
only ever does so on an explicit, revocable opt-in. It carries **categories and
counts, never content or identifiers**: the canonical weakness keys and their
prevalence and verdict mix, the severity and platform distributions, and
co-occurrence. It names no app, carries no package or bundle id, no path, no
sample hash, no evidence, no endpoint or secret, no operator or engagement.

``preview`` returns exactly what would be sent, so the operator can read it first.
``export`` refuses without ``consent=True`` and writes the payload to a file; it
does not transmit anything itself (themob never phones home), so the operator
collects and forwards the file deliberately.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .. import __version__
from . import corpus as corpus_mod

SCHEMA = "themob.telemetry/1"

# The only keys the payload is allowed to carry. A test asserts the payload is a
# subset of this, so a future change cannot quietly add an identifier.
_ALLOWED_TOP = frozenset({
    "schema", "themob_version", "generated_at", "projects", "findings",
    "by_platform", "by_severity", "weaknesses", "co_occurrence"})
_ALLOWED_WEAKNESS = frozenset({
    "key", "severity", "masvs_category", "mobile_top10", "apps", "occurrences",
    "confirmed", "false_positive", "accepted_risk", "new"})


@dataclass
class ExportResult:
    ok: bool = False
    path: str = ""
    findings: int = 0
    error: str = ""


def build_payload(corpus: corpus_mod.Corpus) -> dict:
    """The anonymised projection of a corpus. Categories and counts only."""
    return {
        "schema": SCHEMA,
        "themob_version": __version__,
        "generated_at": corpus.generated_at,
        "projects": corpus.projects,
        "findings": corpus.findings,
        "by_platform": dict(corpus.by_platform),
        "by_severity": dict(corpus.by_severity),
        "weaknesses": [
            {"key": w.key, "severity": w.severity,
             "masvs_category": w.masvs_category, "mobile_top10": w.mobile_top10,
             "apps": w.apps, "occurrences": w.occurrences,
             "confirmed": w.confirmed, "false_positive": w.false_positive,
             "accepted_risk": w.accepted_risk, "new": w.new}
            for w in corpus.weaknesses],
        "co_occurrence": [{"a": a, "b": b, "apps": n}
                          for a, b, n in corpus.co_occurrence],
    }


def preview(home=None, *, top: int = 50) -> dict:
    """Exactly what export would write, so the operator can read it before opting in."""
    return build_payload(corpus_mod.summarize(home, top=top))


def export(home=None, out: str = "themob-telemetry.json", *,
           consent: bool = False, top: int = 50) -> ExportResult:
    """Write the anonymised payload to *out*, only when ``consent`` is True.

    It writes a file; it transmits nothing. The operator forwards the file if and
    when they choose. Off by default: no consent, no file.
    """
    if not consent:
        return ExportResult(error="telemetry export needs explicit consent "
                                  "(consent=True); nothing was written")
    payload = preview(home, top=top)
    try:
        path = Path(out).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True),
                        encoding="utf-8")
    except OSError as exc:
        return ExportResult(error=f"could not write {out}: {exc}")
    return ExportResult(ok=True, path=str(path), findings=payload["findings"])
