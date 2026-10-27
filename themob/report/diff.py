"""What changed between two versions of an app.

The single most-asked question in a real mobile programme is not "what is wrong",
which the report already answers, but "what changed since the last release". A
team that has triaged a hundred findings does not want to re-read them; they want
the three that are new and the two that got fixed.

The stable fingerprint makes this cheap. A finding is keyed by its canonical
weakness plus location, so "the same finding" across two scans is "the same
fingerprint", and the delta is a set operation:

* **new**: in the current scan, not the baseline. The list that gates a build.
* **resolved**: in the baseline, not the current. Worth showing, because a fix
  is a result too, and because a finding that vanished because a whole *stage*
  failed is not a fix, which the coverage warning catches separately.
* **persisting**: in both. Usually the bulk, usually not what anyone re-reads.

Two ways in. :func:`compare_projects` diffs two projects in the same database,
with full fidelity including the attack surface (new endpoints, new permissions).
:func:`new_against_baseline` diffs a fresh report against a baseline *file*, which
is what a CI job has: last release's report committed in the repo, this build's
report just produced. That second path is what lets a pipeline fail on newly
introduced findings while ignoring inherited debt, the pattern every code
scanner settled on because blocking a build on someone else's old bug helps
nobody.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..model.enums import Severity
from .model import Report, ReportedFinding

_SEVERITY_RANK = {
    Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
    Severity.HIGH: 3, Severity.CRITICAL: 4,
}


@dataclass(frozen=True)
class FindingDelta:
    """One finding as a diff shows it: enough to name it, not the whole thing."""

    fingerprint: str
    title: str
    severity: str
    weakness_key: str | None = None

    @classmethod
    def of(cls, reported: ReportedFinding) -> "FindingDelta":
        f = reported.finding
        return cls(fingerprint=f.fingerprint, title=f.title,
                   severity=f.severity.value, weakness_key=f.weakness_key)


@dataclass
class SurfaceDelta:
    """Entities that appeared or disappeared, keyed by their stable identity."""

    added: list[str] = field(default_factory=list)      # "type:key"
    removed: list[str] = field(default_factory=list)


@dataclass
class Delta:
    """The whole comparison of two scans."""

    baseline: str = ""                    # a label: package/version or a path
    current: str = ""
    new: list[FindingDelta] = field(default_factory=list)
    resolved: list[FindingDelta] = field(default_factory=list)
    persisting: list[FindingDelta] = field(default_factory=list)
    surface: SurfaceDelta = field(default_factory=SurfaceDelta)

    @property
    def clean(self) -> bool:
        """Nothing new. The condition a build wants to hear."""
        return not self.new

    def new_at_or_above(self, threshold: Severity) -> list[FindingDelta]:
        floor = _SEVERITY_RANK[threshold]
        return [d for d in self.new
                if _SEVERITY_RANK[Severity(d.severity)] >= floor]

    @property
    def summary(self) -> str:
        return (f"{len(self.new)} new, {len(self.resolved)} resolved, "
                f"{len(self.persisting)} unchanged")


def _worst_first(items: list[FindingDelta]) -> list[FindingDelta]:
    return sorted(items, key=lambda d: (-_SEVERITY_RANK[Severity(d.severity)],
                                        d.title))


def compare_reports(baseline: Report, current: Report) -> Delta:
    """Diff two assembled reports. Findings only; surface needs the graph."""
    base = {r.finding.fingerprint: r for r in baseline.reported}
    curr = {r.finding.fingerprint: r for r in current.reported}

    delta = Delta(
        baseline=baseline.provenance.package or baseline.provenance.project_name,
        current=current.provenance.package or current.provenance.project_name,
        new=_worst_first([FindingDelta.of(r) for fp, r in curr.items()
                          if fp not in base]),
        resolved=_worst_first([FindingDelta.of(r) for fp, r in base.items()
                               if fp not in curr]),
        persisting=_worst_first([FindingDelta.of(r) for fp, r in curr.items()
                                 if fp in base]),
    )
    return delta


def compare_projects(repos, baseline_id: str, current_id: str,
                     audit=None) -> Delta:
    """Diff two projects in the same database, surface included."""
    from .model import build

    baseline = build(repos, baseline_id, audit)
    current = build(repos, current_id, audit)
    delta = compare_reports(baseline, current)
    delta.surface = _surface_delta(repos, baseline_id, current_id)
    return delta


def _surface_delta(repos, baseline_id: str, current_id: str) -> SurfaceDelta:
    from ..correlate.graph import build_snapshot

    def keys(project_id: str) -> set[str]:
        snapshot = build_snapshot(repos, project_id)
        return {f"{e.type.value}:{e.key}" for e in snapshot.entities}

    base = keys(baseline_id)
    curr = keys(current_id)
    return SurfaceDelta(added=sorted(curr - base), removed=sorted(base - curr))


# ------------------------------------------------------------ file-based baseline

def read_baseline_fingerprints(path: str | Path) -> set[str]:
    """Every finding fingerprint in a themob JSON report, body and suppressed.

    Suppressed included on purpose: a finding dismissed last release and seen
    again this release is not new, it is a return of something already judged.
    Gating on it would re-litigate a decision the baseline already recorded.
    """
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("not a themob report")

    fingerprints: set[str] = set()
    for section in document.get("sections") or []:
        for finding in (section or {}).get("findings") or []:
            fp = finding.get("fingerprint")
            if isinstance(fp, str) and fp:
                fingerprints.add(fp)
    for finding in document.get("suppressed") or []:
        fp = finding.get("fingerprint")
        if isinstance(fp, str) and fp:
            fingerprints.add(fp)
    if not fingerprints and "sections" not in document:
        raise ValueError("this file is not a themob JSON report")
    return fingerprints


def read_report_deltas(path: str | Path) -> dict[str, "FindingDelta"]:
    """The body findings of a themob JSON report as FindingDelta, by fingerprint.

    Suppressed findings are left out here: this feeds the file-to-file diff, and
    a diff shows what is in each report's body, which is what a reader compares.
    """
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(document, dict) or "sections" not in document:
        raise ValueError("this file is not a themob JSON report")
    out: dict[str, FindingDelta] = {}
    for section in document.get("sections") or []:
        for finding in (section or {}).get("findings") or []:
            fp = finding.get("fingerprint")
            if not isinstance(fp, str) or not fp:
                continue
            out[fp] = FindingDelta(
                fingerprint=fp,
                title=str(finding.get("title") or "untitled"),
                severity=str(finding.get("severity") or "info"),
                weakness_key=finding.get("weakness"))
    return out


def compare_files(baseline_path: str | Path,
                  current_path: str | Path) -> Delta:
    """Diff two themob JSON report files. What a CI job has to work with."""
    base = read_report_deltas(baseline_path)
    curr = read_report_deltas(current_path)
    return Delta(
        baseline=str(baseline_path),
        current=str(current_path),
        new=_worst_first([d for fp, d in curr.items() if fp not in base]),
        resolved=_worst_first([d for fp, d in base.items() if fp not in curr]),
        persisting=_worst_first([d for fp, d in curr.items() if fp in base]),
    )


def new_against_baseline(current: Report,
                         baseline_fingerprints: set[str]) -> list[FindingDelta]:
    """Findings in *current* not seen in the baseline, worst first."""
    return _worst_first([FindingDelta.of(r) for r in current.reported
                         if r.finding.fingerprint not in baseline_fingerprints])


# ------------------------------------------------------------------- rendering

def to_dict(delta: Delta) -> dict[str, Any]:
    def rows(items: list[FindingDelta]) -> list[dict]:
        return [{"fingerprint": d.fingerprint, "title": d.title,
                 "severity": d.severity, "weakness": d.weakness_key}
                for d in items]

    return {
        "baseline": delta.baseline,
        "current": delta.current,
        "summary": {"new": len(delta.new), "resolved": len(delta.resolved),
                    "unchanged": len(delta.persisting)},
        "new": rows(delta.new),
        "resolved": rows(delta.resolved),
        "surface": {"added": delta.surface.added,
                    "removed": delta.surface.removed},
    }


def render_text(delta: Delta) -> str:
    """A plain-text delta for a terminal or a CI log."""
    lines = [f"Comparing {delta.baseline or 'baseline'} -> "
             f"{delta.current or 'current'}", delta.summary, ""]
    if delta.new:
        lines.append("New:")
        lines += [f"  + [{d.severity}] {d.title}" for d in delta.new]
    if delta.resolved:
        lines.append("Resolved:")
        lines += [f"  - [{d.severity}] {d.title}" for d in delta.resolved]
    if delta.surface.added:
        lines.append(f"New attack surface ({len(delta.surface.added)}):")
        lines += [f"  + {k}" for k in delta.surface.added[:50]]
    if not (delta.new or delta.resolved or delta.surface.added):
        lines.append("No change.")
    return "\n".join(lines)


def write(delta: Delta, path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(to_dict(delta), indent=2) + "\n",
                      encoding="utf-8")
    return target
