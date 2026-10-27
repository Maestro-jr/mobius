"""The machine-readable export.

Written for something else to consume: a ticket tracker, a diff between two
versions of an app, TOPRECON. So it is explicit rather than compact, keys are
stable, and the shape is declared by ``format`` at the top so a reader can tell
what it is holding without guessing from the contents.

Sorted throughout. Two exports of an unchanged project differ only in
``generated_at``, because the first thing anyone does with two reports is diff
them, and a diff full of reordering noise is a diff nobody reads.
"""
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from ..model.findings import Finding
from .model import FORMAT, Report, ReportedFinding


def to_dict(report: Report) -> dict[str, Any]:
    """The whole report as plain data."""
    return {
        "format": FORMAT,
        "provenance": asdict(report.provenance),
        "summary": {
            "total": report.total,
            "by_severity": report.counts,
            "worst": report.worst.value if report.worst else None,
            "suppressed": len(report.suppressed),
            "entities": report.entity_counts,
        },
        "sections": [
            {
                "key": section.key,
                "title": section.title,
                "description": section.description,
                "entity_count": section.entity_count,
                "findings": [_finding(f) for f in section.findings],
            }
            for section in report.sections
        ],
        # Present and separate. Dropping them would make the export unauditable;
        # mixing them into the sections would misrepresent what was reported.
        "suppressed": [_finding(f) for f in report.suppressed],
    }


def _finding(reported: ReportedFinding) -> dict[str, Any]:
    finding: Finding = reported.finding
    return {
        "fingerprint": finding.fingerprint,
        "weakness": finding.weakness_key,
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity.value,
        "base_severity": (finding.base_severity.value
                          if finding.base_severity else None),
        "score_rationale": finding.score_rationale,
        "risk": finding.risk,
        "confidence": finding.confidence,
        "status": finding.status.value,
        "verdict": reported.verdict,
        "section": reported.section,
        "externally_reachable": reported.exposed,
        "exposure_path": reported.exposure_path,
        "standards": {
            "masvs_category": (finding.masvs_category.value
                               if finding.masvs_category else None),
            "masvs_control": finding.masvs_control,
            # Null rather than absent: the field exists and has no verified
            # value, which is not the same as themob having no opinion.
            "maswe_id": finding.maswe_id,
            "mobile_top10": finding.mobile_top10,
            "cwe": finding.cwe,
        },
        "location": (finding.location.model_dump(by_alias=True)
                     if finding.location else None),
        # Evidence values are already redacted by the workers: a secret's
        # digest and a masked preview travel, never the value.
        "evidence": [
            {"kind": e.kind.value, "value": e.value,
             "artifact_path": e.artifact_path}
            for e in finding.evidence
        ],
        "remediation": (finding.remediation.summary
                        if finding.remediation else None),
        "reported_by": reported.tools,
        "notes": [
            {"author": n.author, "text": n.text, "created_at": n.created_at}
            for n in reported.notes
        ],
    }


def write(report: Report, path: str | Path) -> Path:
    """Write the export, creating the parent directory if it is missing."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(to_dict(report), indent=2, sort_keys=True, ensure_ascii=False)
        + "\n",
        encoding="utf-8")
    return target
