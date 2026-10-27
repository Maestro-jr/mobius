"""Report export: the assessment as a document somebody can be handed.

``build`` assembles the report once, and the two writers only lay it out. HTML
for a person, JSON for a machine, both from the same object so their numbers
cannot disagree.

``export`` is the entry point that also records the export in the audit trail,
because a report leaving the tool is an event: it is the moment findings about
someone's app become a file that can be forwarded.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..audit.attestation import Action, AuditTrail
from ..storage.repositories import Repositories
from . import html_report, json_report, manifest, sarif, signing
from .model import (FORMAT, Provenance, Report, ReportedFinding, ReportSection,
                    SUPPRESSED, build, failed_stages)

__all__ = [
    "FORMAT", "Export", "Provenance", "Report", "ReportSection",
    "ReportedFinding", "SUPPRESSED", "build", "export", "failed_stages",
    "html_report", "json_report", "manifest", "sarif", "signing",
]


@dataclass
class Export:
    """What was written, and the document that was written.

    The report travels back with the paths so a caller can say what it contains
    without assembling it a second time. Two builds would carry two generation
    timestamps, and the confirmation on screen would then describe a slightly
    different document from the one on disk.
    """

    files: dict[str, Path] = field(default_factory=dict)
    report: Report | None = None


def export(repos: Repositories, audit: AuditTrail, project_id: str,
           directory: str | Path, *, operator: str = "",
           stem: str = "themob-report", sarif_report: bool = True,
           workspace=None, sign_key: bytes | None = None) -> Export:
    """Write every format, a tamper-evident manifest, and record the export.

    Returns the paths written, keyed by format, alongside the report itself.
    The audit entry names the files and the finding counts: "what left the tool,
    and when" is part of the trail for the same reason the authorization
    attestation is.

    A ``manifest.json`` is always written: it lists every deliverable file with
    its SHA-256 and ties the bundle to the audit chain's head, so an edit after
    export is detectable. ``sign_key`` (an Ed25519 private key in PEM) adds a
    detached signature on top; without it the manifest stands on its checksums.
    """
    report = build(repos, project_id, audit)
    root = Path(directory)
    written = {
        "html": html_report.write(report, root / f"{stem}.html"),
        "json": json_report.write(report, root / f"{stem}.json"),
    }
    # SARIF is what a CI pipeline reads, so it is written by default; the one
    # caller that does not want it (a person clicking Export who will never feed
    # it to code scanning) can turn it off, but a spare machine-readable file is
    # cheap and a missing one is a whole integration nobody set up.
    if sarif_report:
        written["sarif"] = sarif.write(report, root / f"{stem}.sarif.json")

    # The manifest covers exactly the files just written, and, when the
    # workspace is known, a digest of the raw evidence they cite.
    raw_root = getattr(workspace, "raw_root", None)
    doc = manifest.build(report, root,
                         files=[p.name for p in written.values()],
                         raw_root=raw_root, audit=audit)
    written["manifest"] = manifest.write(doc, root / "manifest.json")

    signed = False
    if sign_key is not None:
        paths = signing.sign_manifest(doc, root, sign_key)
        written["signature"] = paths["signature"]
        written["public_key"] = paths["public_key"]
        signed = True

    audit.record(
        Action.REPORT_EXPORTED,
        project_id=project_id,
        target_sha256=report.provenance.sha256,
        actor=operator or None,
        files=sorted(str(p) for p in written.values()),
        findings=report.total,
        suppressed=len(report.suppressed),
        audit_chain_ok=report.provenance.audit_chain_ok,
        signed=signed,
    )
    return Export(files=written, report=report)
