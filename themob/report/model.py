"""The report as a document, before it is a format.

HTML and JSON are two renderings of one thing, and building each from the
database separately is how they drift until the numbers on the page stop
matching the numbers in the export. So this assembles the document once and the
writers only lay it out.

Three things this refuses to do, each because a report is a document somebody
may have to defend months later.

**It never carries a secret value.** The workers redact before anything leaves
the container, so themob does not hold plaintext to leak; the report asserts
that rather than assuming it, because "we do not store it" and "it cannot be in
the export" are different claims and only the second one matters here.

**Suppressed findings are counted, not dropped.** A finding marked a false
positive does not belong in the body, and a report that silently omits it is
one nobody can audit. The count and the reasons are in their own section, so
"we found 14, and 3 were dismissed for these reasons" is on the page.

**The provenance header says whether the audit chain still verifies.** A report
whose own trail has been tampered with should say so on its first page rather
than read as though nothing happened.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .. import __version__
from ..audit.attestation import AuditTrail
from ..correlate import GraphSnapshot, SectionView, build_snapshot, project
from ..correlate.pivots import Exposure, entry_points, exposure
from ..model.enums import EntityType, FindingStatus, JobStatus, Severity
from ..model.findings import Finding
from ..orchestrator.validation import VERDICT_LABELS
from ..storage.repositories import Note, Project, Repositories

# The document's own version, so a consumer can tell what shape it is reading.
FORMAT = "themob.report/1"

# grype's database updates daily. A week is the point past which "no vulnerable
# dependencies" starts to mean "no recent data" more than "nothing wrong", so it
# is where the report begins to warn. Not a hard failure: an air-gapped lab runs
# on a deliberately pinned feed, and that is a choice, not a bug.
VULN_DB_STALE_AFTER_DAYS = 7

# Verdicts that keep a finding out of the body of the report.
SUPPRESSED = (FindingStatus.FALSE_POSITIVE, FindingStatus.ACCEPTED_RISK)

_SEVERITY_RANK = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
                  Severity.LOW: 3, Severity.INFO: 4}


@dataclass
class Provenance:
    """What was assessed, under what authority, and with what."""

    package: str = ""
    project_name: str = ""
    sha256: str = ""
    platform: str = ""
    version_name: str | None = None
    version_code: str | None = None
    authorization_ref: str | None = None
    authorized_by: str | None = None
    authorized_at: str | None = None
    generated_at: str = ""
    # Which themob produced this. The tool versions below say what found each
    # finding; this says what correlated, scored and wrote them up, and the two
    # are different questions when a report is disputed a year later.
    themob_version: str = ""
    stages: list[dict[str, Any]] = field(default_factory=list)
    tools: dict[str, str] = field(default_factory=dict)
    audit_entries: int = 0
    audit_chain_ok: bool = True
    audit_chain_message: str = ""
    # When the vulnerability database the dependency scan matched against was
    # built, and how old that made it at scan time. None when no dependency
    # scan ran. A clean dependency result against a stale feed is a false
    # negative waiting to happen, so the report states the feed's age.
    vuln_db_built: str | None = None
    vuln_db_age_days: int | None = None

    @property
    def vuln_db_stale(self) -> bool:
        return (self.vuln_db_age_days is not None
                and self.vuln_db_age_days > VULN_DB_STALE_AFTER_DAYS)

    @property
    def authorized(self) -> bool:
        return bool(self.authorized_at and self.authorized_by)


@dataclass
class ReportedFinding:
    """One finding as the report shows it, with its context resolved."""

    finding: Finding
    section: str
    exposed: bool = False
    exposure_path: list[str] = field(default_factory=list)
    notes: list[Note] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)

    @property
    def suppressed(self) -> bool:
        return self.finding.status in SUPPRESSED

    @property
    def verdict(self) -> str:
        return VERDICT_LABELS.get(self.finding.status, "")


@dataclass
class ReportSection:
    """A section of the report, mirroring the console's own nav."""

    key: str
    title: str
    description: str
    findings: list[ReportedFinding] = field(default_factory=list)
    entity_count: int = 0


@dataclass
class Report:
    """Everything a rendering needs, and nothing a format cares about."""

    provenance: Provenance
    sections: list[ReportSection] = field(default_factory=list)
    suppressed: list[ReportedFinding] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    entity_counts: dict[str, int] = field(default_factory=dict)

    @property
    def reported(self) -> list[ReportedFinding]:
        """Every finding in the body, worst first."""
        out = [f for section in self.sections for f in section.findings]
        return sorted(out, key=_worst_first)

    @property
    def total(self) -> int:
        return len(self.reported)

    @property
    def worst(self) -> Severity | None:
        reported = self.reported
        return reported[0].finding.severity if reported else None


def vuln_db_age_days(built_iso: str, now: datetime | None = None) -> int | None:
    """Days between a database build date and *now*. None if unparseable.

    Tolerant of the shapes grype emits: a trailing Z, an offset, or neither.
    A date it cannot read returns None rather than a wrong number, because a
    made-up age is worse than a missing one on a page about staleness.
    """
    text = (built_iso or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        built = datetime.fromisoformat(text)
    except ValueError:
        return None
    if built.tzinfo is None:
        built = built.replace(tzinfo=timezone.utc)
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    return max((current - built).days, 0)


def _worst_first(reported: ReportedFinding):
    finding = reported.finding
    return (_SEVERITY_RANK[finding.severity], -(finding.risk or 0.0),
            finding.title)


def build(repos: Repositories, project_id: str,
          audit: AuditTrail | None = None) -> Report:
    """Assemble the report for one project from what is stored."""
    stored = repos.projects.get(project_id)
    if stored is None:
        raise ValueError(f"no project {project_id!r}")

    snapshot = build_snapshot(repos, project_id)
    findings = repos.findings.list(project_id, limit=10_000)
    provenance = _provenance(repos, stored, snapshot, audit)

    entries = entry_points(snapshot)
    cache: dict[str, Exposure] = {}

    sections: list[ReportSection] = []
    suppressed: list[ReportedFinding] = []

    for view in project(snapshot, findings):
        section = ReportSection(key=view.key, title=view.title,
                                description=view.section.description,
                                entity_count=len(view.entities))
        for finding in view.findings:
            reported = _resolve(repos, snapshot, finding, view, entries, cache)
            if reported.suppressed:
                suppressed.append(reported)
            else:
                section.findings.append(reported)
        section.findings.sort(key=_worst_first)
        sections.append(section)

    counts = {s.value: 0 for s in Severity}
    for section in sections:
        for reported in section.findings:
            counts[reported.finding.severity.value] += 1

    return Report(
        provenance=provenance,
        sections=sections,
        suppressed=sorted(suppressed, key=_worst_first),
        counts=counts,
        entity_counts={t.value: n for t, n in snapshot.counts_by_type().items()
                       if n},
    )


def _resolve(repos: Repositories, snapshot: GraphSnapshot, finding: Finding,
             view: SectionView, entries, cache) -> ReportedFinding:
    reached: Exposure | None = None
    for entity_id in finding.entity_ids:
        if entity_id not in cache:
            cache[entity_id] = exposure(snapshot, entity_id, entries)
        candidate = cache[entity_id]
        if candidate.reachable and (reached is None
                                    or candidate.hops < reached.hops):
            reached = candidate

    path: list[str] = []
    if reached is not None:
        for node_id in reached.path:
            entity = snapshot.get(node_id)
            path.append(entity.label or entity.key if entity else node_id)

    return ReportedFinding(
        finding=finding,
        section=view.key,
        exposed=reached is not None,
        exposure_path=path,
        notes=repos.findings.notes(finding.id),
        tools=sorted({tool for tool, _c in repos.findings.source_votes(finding.id)}),
    )


def _provenance(repos: Repositories, stored: Project, snapshot: GraphSnapshot,
                audit: AuditTrail | None) -> Provenance:
    app = next(iter(snapshot.of_type(EntityType.APP)), None)
    attributes = app.attributes if app else {}

    stages: list[dict[str, Any]] = []
    for job in repos.jobs.list(stored.id):
        stages.append({
            "stage": job.stage.value,
            "analyzer": job.analyzer,
            "status": job.status.value,
            "started_at": job.started_at,
            "finished_at": job.finished_at,
            # Recorded rather than hidden: a report that omits the analyzer
            # that crashed is claiming coverage it does not have.
            "error": job.error,
        })

    chain_ok, chain_message = (audit.verify_chain() if audit is not None
                               else (True, "not verified"))

    built, age = _vuln_db_freshness(attributes)

    return Provenance(
        package=str(attributes.get("package") or (app.key if app else "")),
        project_name=stored.name,
        sha256=stored.source_sha256,
        platform=stored.target_platform.value,
        version_name=attributes.get("version_name"),
        version_code=attributes.get("version_code"),
        authorization_ref=stored.authorization_ref,
        authorized_by=stored.authorized_by,
        authorized_at=stored.authorized_at,
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        themob_version=__version__,
        stages=stages,
        tools=_tool_versions(attributes),
        audit_entries=len(repos.audit.list(stored.id, limit=10_000)),
        vuln_db_built=built,
        vuln_db_age_days=age,
        audit_chain_ok=chain_ok,
        audit_chain_message=chain_message,
    )


def _vuln_db_freshness(attributes: dict[str, Any]) -> tuple[str | None, int | None]:
    """The vulnerability database's build date and age, from the App node.

    The sbom adapter stores it under ``dependency_scan.vuln_db.built``. Absent
    when no dependency scan ran, which is the honest "we do not know" rather
    than a fabricated freshness.
    """
    scan = attributes.get("dependency_scan")
    if not isinstance(scan, dict):
        return None, None
    db = scan.get("vuln_db")
    if not isinstance(db, dict):
        return None, None
    built = db.get("built")
    if not isinstance(built, str) or not built:
        return None, None
    return built, vuln_db_age_days(built)


def _tool_versions(attributes: dict[str, Any]) -> dict[str, str]:
    """Which version of each tool produced this, from what the adapters stored.

    A finding is only reproducible against the tool that made it, so a report
    that names its tools without their versions is not reproducible at all.
    """
    tools: dict[str, str] = {}
    for key, name in (("analyzer_version", "androguard"),
                      ("apktool_version", "apktool"),
                      ("jadx_version", "jadx")):
        value = attributes.get(key)
        if value:
            tools[name] = str(value)
    for scan_key in ("secret_scan", "sast_scan", "dependency_scan",
                     "endpoint_scan", "mobsf_scan"):
        scan = attributes.get(scan_key)
        if not isinstance(scan, dict):
            continue
        version = scan.get("tool_version")
        if isinstance(version, dict):
            tools.update({k: str(v) for k, v in version.items() if v})
        elif version:
            tools[scan_key.replace("_scan", "")] = str(version)
    return tools


def failed_stages(report: Report) -> list[dict[str, Any]]:
    """Analyzers that did not complete, so the reader knows what was not covered."""
    return [s for s in report.provenance.stages
            if s.get("status") == JobStatus.FAILED.value]
