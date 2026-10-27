"""themob's capabilities as plain, MCP-agnostic functions.

Each function opens the project store, does one job through the same engine the
CLI and the window use, and returns a JSON-serialisable dict. Nothing here
imports the MCP SDK or PyQt6, so :mod:`themob.mcp.server` can wrap these as MCP
tools while the unit tests call them directly.

Expected failures (no project yet, an unknown section, a sample that is not a
package, Docker not running) come back as ``{"error": "..."}`` so the calling
agent always gets a readable message and the server never crashes on them.

The authorization gate is not softened for being driven by an agent. The gated
functions (:func:`authorize_target`, :func:`scan`) refuse unless the caller
passes ``attested=True`` with an operator and an engagement, exactly as the
CLI's ``--yes`` does, and each appends to the same hash-chained audit trail.
:func:`analyze` refuses a project that was never authorized. There is no path
here that runs an analyzer without an attestation on the project.
"""
from __future__ import annotations

import logging
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from ..audit.attestation import (AuditTrail, AuthorizationError,
                                  current_operator, require_authorization)
from ..correlate import queries as _queries
from ..correlate.graph import build_snapshot
from ..correlate.sections import SECTIONS
from ..correlate.sections import project as _project_sections
from ..model.enums import EntityType, FindingStatus, Severity, Stage
from ..storage.db import open_database
from ..storage.repositories import Repositories
from ..storage.workspace import Workspace, default_root

logger = logging.getLogger(__name__)

# A verdict word the agent may pass, accepting either spelling, mapped to the
# FindingStatus value (not the enum member name).
_VERDICT_STATUS = {
    "confirmed": "confirmed",
    "false-positive": "false_positive",
    "false_positive": "false_positive",
    "accepted-risk": "accepted_risk",
    "accepted_risk": "accepted_risk",
}


def resolve_home(home: str | Path | None) -> Path:
    """The project store this call works against (``THEMOB_HOME`` by default)."""
    return Path(home).expanduser() if home else default_root()


@contextmanager
def _session(home: str | Path | None) -> Iterator[tuple[Repositories, AuditTrail]]:
    """Open the database for one call and always close it."""
    database = open_database(resolve_home(home) / "themob.db")
    try:
        repos = Repositories(database)
        yield repos, AuditTrail(repos.audit)
    finally:
        database.close_all()


def _resolve_project(repos: Repositories, token: str):
    """``(project, error)``: a project by id, id-prefix or exact name.

    With no token the most recently created project is used. Exactly one of the
    pair is set, so a caller checks the error and returns it.
    """
    projects = repos.projects.list(limit=500)
    if not projects:
        return None, "no projects yet. Call authorize_target or scan on a sample first"
    if not token:
        return projects[0], ""
    for project in projects:
        if project.id == token:
            return project, ""
    prefix = [p for p in projects if p.id.startswith(token)]
    named = [p for p in projects if p.name == token]
    if len(prefix) == 1 and not named:
        return prefix[0], ""
    if len(named) == 1 and not prefix:
        return named[0], ""
    if len(prefix) + len(named) > 1:
        return None, f"{token!r} matches more than one project; use a longer id prefix"
    if named:
        return named[0], ""
    return None, f"no project matches {token!r}"


# --------------------------------------------------------------- serialisation

def _finding_summary(f) -> dict:
    return {
        "fingerprint": f.fingerprint,
        "severity": f.severity.value,
        "confidence": round(f.confidence, 4),
        "status": f.status.value,
        "title": f.title,
        "weakness_key": f.weakness_key,
        "masvs": f.masvs_control,
        "risk": f.risk,
    }


def _finding_full(f, notes) -> dict:
    data = _finding_summary(f)
    data.update({
        "description": f.description,
        "score_rationale": f.score_rationale,
        "standards": {
            "weakness_key": f.weakness_key,
            "masvs": f.masvs_control,
            "maswe": f.maswe_id,
            "mobile_top10": f.mobile_top10,
            "cwe": f.cwe,
        },
        "tools": sorted({s.tool for s in f.sources}),
        "evidence": [item.value for item in (f.evidence or [])[:50]],
        "notes": [{"text": n.text, "author": n.author, "at": n.created_at}
                  for n in notes],
    })
    if f.location:
        loc = f.location
        data["location"] = {"file": loc.file, "class": loc.clazz,
                            "method": loc.method, "line": loc.line,
                            "component": loc.component}
    if f.remediation:
        data["remediation"] = f.remediation.summary
    return data


def _entity_summary(e) -> dict:
    return {"id": e.id, "type": e.type.value, "key": e.key, "label": e.label}


def _project_summary(p) -> dict:
    return {
        "id": p.id,
        "name": p.name,
        "platform": p.target_platform.value,
        "authorized": p.is_authorized,
        "engagement": p.authorization_ref or "",
        "sha256": p.source_sha256,
        "created": p.created_at,
    }


# --------------------------------------------------------------- read-only tools

def list_projects(home: str | Path | None = None) -> dict:
    """Every project themob has ingested, newest first, with its gate state."""
    with _session(home) as (repos, _audit):
        return {"projects": [_project_summary(p)
                             for p in repos.projects.list(limit=500)]}


def corpus(home: str | Path | None = None, top: int = 50) -> dict:
    """The local corpus across every project: prevalence, verdicts, co-occurrence.

    Names no app. It is the cross-project read the Trends page shows and an agent
    can reason over: which weaknesses recur, how often they are confirmed or
    dismissed, and which travel together. Local only; nothing leaves the machine.
    """
    from ..intel import corpus as corpus_mod

    with _session(home) as (repos, _audit):
        c = corpus_mod.build(repos, top=int(top))
    return {
        "projects": c.projects,
        "findings": c.findings,
        "by_platform": c.by_platform,
        "by_severity": c.by_severity,
        "weaknesses": [
            {"key": w.key, "title": w.title, "severity": w.severity,
             "masvs": w.masvs_category, "mobile_top10": w.mobile_top10,
             "apps": w.apps, "occurrences": w.occurrences,
             "confirmed": w.confirmed, "false_positive": w.false_positive,
             "accepted_risk": w.accepted_risk, "new": w.new}
            for w in c.weaknesses],
        "co_occurrence": [{"a": a, "b": b, "apps": n}
                          for a, b, n in c.co_occurrence],
        "generated_at": c.generated_at,
    }


def overview(home: str | Path | None = None, project: str = "") -> dict:
    """The 30-second read: counts, the app's facts, and the worst findings."""
    with _session(home) as (repos, _audit):
        proj, error = _resolve_project(repos, project)
        if proj is None:
            return {"error": error}
        snapshot = build_snapshot(repos, proj.id)
        findings = repos.findings.list(proj.id)
        counts = {s.value: 0 for s in Severity}
        for f in findings:
            counts[f.severity.value] += 1
        worst = next((s.value for s in Severity if counts[s.value]), None)
        app = snapshot.root
        app_facts: dict[str, Any] = {}
        if app is not None:
            for key in ("package", "version_name", "min_sdk", "target_sdk",
                        "debuggable", "allow_backup", "uses_cleartext_traffic"):
                value = app.attributes.get(key)
                if value not in (None, "", [], {}):
                    app_facts[key] = value
        return {
            "project": _project_summary(proj),
            "entities": len(snapshot),
            "relationships": snapshot.edge_count,
            "findings": len(findings),
            "severity_counts": {k: v for k, v in counts.items() if v},
            "highest_severity": worst,
            "application": app_facts,
            "top_findings": [_finding_summary(f) for f in findings[:15]],
        }


def list_findings(home: str | Path | None = None, project: str = "",
                  severity: str | None = None, status: str | None = None) -> dict:
    """The findings for a project, optionally filtered by severity and status."""
    sev = None
    if severity:
        try:
            sev = Severity(severity)
        except ValueError:
            return {"error": f"unknown severity {severity!r}"}
    st = None
    if status:
        try:
            st = FindingStatus(status)
        except ValueError:
            return {"error": f"unknown status {status!r}"}
    with _session(home) as (repos, _audit):
        proj, error = _resolve_project(repos, project)
        if proj is None:
            return {"error": error}
        findings = repos.findings.list(proj.id, severity=sev, status=st)
        return {"project": proj.id,
                "count": len(findings),
                "findings": [_finding_summary(f) for f in findings]}


def get_finding(home: str | Path | None = None, project: str = "",
                fingerprint: str = "") -> dict:
    """One finding in full: standards, location, evidence, remediation, notes.

    A fingerprint prefix is accepted when it is unambiguous.
    """
    if not fingerprint:
        return {"error": "a fingerprint is required"}
    with _session(home) as (repos, _audit):
        proj, error = _resolve_project(repos, project)
        if proj is None:
            return {"error": error}
        f = repos.findings.get_by_fingerprint(proj.id, fingerprint)
        if f is None:
            match = [x for x in repos.findings.list(proj.id, limit=100000)
                     if x.fingerprint.startswith(fingerprint)]
            f = match[0] if len(match) == 1 else None
        if f is None:
            return {"error": f"no finding {fingerprint!r} in this project"}
        return _finding_full(f, repos.findings.notes(f.id))


def get_section(home: str | Path | None = None, project: str = "",
                section: str = "") -> dict:
    """One tester-facing section (a projection of the graph): its findings and
    entities. Known sections are the keys in :data:`SECTIONS`."""
    known = {s.key for s in SECTIONS}
    if section not in known:
        return {"error": f"unknown section {section!r}. Known: "
                         + ", ".join(sorted(known))}
    with _session(home) as (repos, _audit):
        proj, error = _resolve_project(repos, project)
        if proj is None:
            return {"error": error}
        snapshot = build_snapshot(repos, proj.id)
        findings = repos.findings.list(proj.id)
        view = next((v for v in _project_sections(snapshot, findings)
                     if v.key == section), None)
        if view is None:
            return {"section": section, "findings": [], "entities": []}
        return {
            "section": view.key,
            "title": view.title,
            "description": view.section.description,
            "findings": [_finding_summary(f) for f in view.findings],
            "entities": [_entity_summary(e) for e in view.entities[:500]],
        }


def graph(home: str | Path | None = None, project: str = "",
          type: str | None = None, reachable_from: str | None = None) -> dict:
    """The attack-surface graph: counts by type, one type's entities, or what is
    reachable from a given entity id."""
    with _session(home) as (repos, _audit):
        proj, error = _resolve_project(repos, project)
        if proj is None:
            return {"error": error}
        snapshot = build_snapshot(repos, proj.id)
        base = {"entities": len(snapshot), "relationships": snapshot.edge_count}
        if reachable_from:
            reached = [snapshot.get(i) for i in sorted(
                snapshot.reachable_from(reachable_from)) if i != reachable_from]
            base["reachable_from"] = reachable_from
            base["reached"] = [_entity_summary(e) for e in reached if e is not None]
            return base
        if type:
            try:
                wanted = EntityType(type)
            except ValueError:
                return {"error": f"unknown entity type {type!r}"}
            base["type"] = type
            base["of_type"] = [_entity_summary(e)
                               for e in snapshot.of_type(wanted)[:500]]
            return base
        base["counts_by_type"] = {t.value: n for t, n in
                                  snapshot.counts_by_type().items() if n}
        return base


def get_entity(home: str | Path | None = None, project: str = "",
               entity: str = "") -> dict:
    """One node by id or key: its attributes, connectivity, and path from the app."""
    if not entity:
        return {"error": "an entity id or key is required"}
    with _session(home) as (repos, _audit):
        proj, error = _resolve_project(repos, project)
        if proj is None:
            return {"error": error}
        snapshot = build_snapshot(repos, proj.id)
        node = snapshot.get(entity) or next(
            (e for e in snapshot.entities if e.key == entity), None)
        if node is None:
            return {"error": f"no entity {entity!r} in this project"}
        path = [snapshot.get(n) for n in snapshot.path_from_root(node.id)]
        return {
            **_entity_summary(node),
            "connections": snapshot.degree(node.id),
            "attributes": {k: v for k, v in node.attributes.items()
                           if v not in (None, "", [], {})},
            "path_from_app": [e.label or e.key for e in path if e is not None],
        }


def list_code(home: str | Path | None = None, project: str = "",
              filter: str = "", limit: int = 200) -> dict:
    """The decompiled class list (needs a prior analyze so jadx has run)."""
    from ..adapters.jadx_decompile import read_class_index

    with _session(home) as (repos, _audit):
        proj, error = _resolve_project(repos, project)
        if proj is None:
            return {"error": error}
        snapshot = build_snapshot(repos, proj.id)
        app = snapshot.root
        index_path = app.attributes.get("class_index") if app else None
        if not index_path:
            return {"error": "no decompiled sources yet. Run analyze so jadx runs",
                    "classes": []}
        workspace = Workspace(resolve_home(home), proj.id)
        index = read_class_index(workspace, str(index_path))
        needle = (filter or "").lower()
        classes = [e["fqcn"] for e in index
                   if not needle or needle in e["fqcn"].lower()]
        return {"total": len(index), "matched": len(classes),
                "classes": classes[:max(0, limit)]}


def read_class(home: str | Path | None = None, project: str = "",
               fqcn: str = "") -> dict:
    """The decompiled source of one class. Paths are resolved inside the project
    workspace only, so a tool-produced path cannot escape it."""
    from ..adapters.jadx_decompile import read_class_index

    if not fqcn:
        return {"error": "a fully-qualified class name is required"}
    with _session(home) as (repos, _audit):
        proj, error = _resolve_project(repos, project)
        if proj is None:
            return {"error": error}
        snapshot = build_snapshot(repos, proj.id)
        app = snapshot.root
        index_path = app.attributes.get("class_index") if app else None
        if not index_path:
            return {"error": "no decompiled sources yet. Run analyze so jadx runs"}
        workspace = Workspace(resolve_home(home), proj.id)
        index = read_class_index(workspace, str(index_path))
        entry = next((e for e in index if e["fqcn"] == fqcn), None)
        if entry is None:
            match = [e for e in index if fqcn in e["fqcn"]]
            entry = match[0] if len(match) == 1 else None
        if entry is None:
            return {"error": f"no class matching {fqcn!r}"}
        try:
            path = workspace.resolve(entry["path"])
            source = path.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:                            # noqa: BLE001
            return {"error": f"could not read the class: {exc}"}
        return {"fqcn": entry["fqcn"], "source": source[:400000]}


def list_queries(home: str | Path | None = None) -> dict:
    """The built-in questions, plus any a tester saved."""
    with _session(home) as (repos, _audit):
        saved = repos.queries.list()
        return {
            "builtin": [{"key": q.key, "title": q.title} for q in _queries.BUILTINS],
            "saved": [{"key": q.key, "title": q.title} for q in saved],
        }


def run_query(home: str | Path | None = None, project: str = "",
              key: str = "") -> dict:
    """Run a built-in or saved query over a project and return its matches."""
    if not key:
        return {"error": "a query key is required. list_queries shows them"}
    with _session(home) as (repos, _audit):
        proj, error = _resolve_project(repos, project)
        if proj is None:
            return {"error": error}
        query = _queries.builtin(key) or repos.queries.load(key)
        if query is None:
            return {"error": f"no query {key!r}. list_queries shows them"}
        snapshot = build_snapshot(repos, proj.id)
        findings = repos.findings.list(proj.id)
        result = _queries.run(snapshot, findings, query)
        return {
            "key": key,
            "description": query.description,
            "summary": result.summary,
            "matches": [{
                "entity": _entity_summary(m.entity),
                "worst_severity": m.worst.value if m.worst else None,
                "reasons": list(m.reasons),
            } for m in result.matches[:500]],
        }


def audit(home: str | Path | None = None, project: str = "",
          verify: bool = False, limit: int = 100) -> dict:
    """The hash-chained audit trail, optionally only for one project, and
    optionally with the result of re-walking the chain."""
    with _session(home) as (repos, audit_trail):
        project_id = None
        if project:
            proj, error = _resolve_project(repos, project)
            if proj is None:
                return {"error": error}
            project_id = proj.id
        out: dict[str, Any] = {}
        if verify:
            ok, message = audit_trail.verify_chain()
            out["chain_ok"] = ok
            out["chain_message"] = message
        entries = audit_trail.entries(project_id, limit=max(1, limit))
        out["entries"] = [{
            "time": e.ts, "actor": e.actor, "action": e.action,
            "detail": {k: v for k, v in e.detail.items() if not k.startswith("_")},
        } for e in entries]
        return out


def list_analyzers(home: str | Path | None = None) -> dict:
    """The analyzer roster and whether each can run right now."""
    from ..adapters import build_registry
    from ..sandbox.runner import SandboxRunner

    sandbox = SandboxRunner()
    rows = [{"name": a.name, "stage": a.stage.value.replace("_", " "),
             "availability": a.availability(sandbox)}
            for a in build_registry().all()]
    return {"docker_available": sandbox.is_available(), "analyzers": rows}


def doctor(home: str | Path | None = None) -> dict:
    """A quick environment read: Docker, and what each analyzer needs."""
    return list_analyzers(home)


# --------------------------------------------------------------- gated tools

def _summarise_run(summary) -> dict:
    return {
        "entities": summary.entities,
        "findings": summary.findings,
        "duration_s": round(summary.duration_s, 2),
        "state": summary.state.value if hasattr(summary.state, "value")
        else str(summary.state),
        "failed": [{"analyzer": o.analyzer, "error": o.error}
                   for o in summary.failed],
    }


def authorize_target(home: str | Path | None = None, sample_path: str = "",
                     engagement_ref: str = "", operator: str = "",
                     name: str = "", scope_note: str = "",
                     attested: bool = False) -> dict:
    """Ingest a sample and record the authorization attestation.

    This is the gate. It refuses unless ``attested`` is true and an
    ``engagement_ref`` is given, and it records who attested under which
    engagement in the hash-chained audit trail. Decompiling software you are not
    authorised to assess may breach its licence and, in some places, the law.
    """
    from ..orchestrator import IntakeError
    from ..orchestrator.authorize import GateDecision, authorize_target as _auth

    if not sample_path:
        return {"error": "a sample_path is required"}
    if not attested:
        return {"error": "refused: set attested=true to attest you are "
                         "authorised to assess this sample"}
    if not engagement_ref.strip():
        return {"error": "refused: an engagement_ref is required, so the audit "
                         "trail records what authorised this"}
    who = operator.strip() or current_operator()
    with _session(home) as (repos, audit_trail):
        try:
            result = _auth(GateDecision(
                sample_path=sample_path, project_name=name,
                engagement_ref=engagement_ref, scope_note=scope_note,
                attested=True, operator=who), repos, audit_trail,
                root=resolve_home(home))
        except IntakeError as exc:
            return {"error": f"intake refused the sample: {exc}"}
        except AuthorizationError as exc:
            return {"error": f"authorization failed: {exc}"}
        return {"project": _project_summary(result.project),
                "workspace": str(result.workspace.path),
                "operator": who}


def analyze(home: str | Path | None = None, project: str = "",
            stages: list[str] | None = None, analyzers: list[str] | None = None,
            *, _registry=None, _sandbox=None) -> dict:
    """Run the analysis pipeline over an already-authorized project.

    Refuses a project with no attestation. The analyzers run in network-less
    containers, so this needs a running Docker daemon; if it is not up the tool
    returns a structured message rather than raising. ``_registry`` and
    ``_sandbox`` are injection points for the tests.
    """
    from ..adapters import build_registry
    from ..orchestrator import IntakeError, Pipeline, target_for
    from ..sandbox.runner import SandboxRunner

    stage_objs = None
    if stages:
        try:
            stage_objs = [Stage(s) for s in stages]
        except ValueError as exc:
            return {"error": f"unknown stage: {exc}"}

    with _session(home) as (repos, audit_trail):
        proj, error = _resolve_project(repos, project)
        if proj is None:
            return {"error": error}
        try:
            require_authorization(proj)
        except AuthorizationError as exc:
            return {"error": f"{exc}"}

        workspace = Workspace(resolve_home(home), proj.id)
        try:
            target = target_for(proj, workspace)
        except IntakeError as exc:
            return {"error": f"{exc}"}

        sandbox = _sandbox if _sandbox is not None else SandboxRunner()
        if _registry is None and not sandbox.is_available():
            return {"error": "Docker is not available: the analyzers run in "
                             "containers, so a run needs a daemon. Start Docker "
                             "and retry.", "docker_available": False}

        registry = _registry if _registry is not None else build_registry()
        try:
            summary = Pipeline(registry, repos, sandbox, audit_trail).run(
                proj, target, workspace, stages=stage_objs,
                analyzers=analyzers or None)
        except Exception as exc:                            # noqa: BLE001
            logger.exception("analyze failed")
            return {"error": f"the run failed: {exc}"}
        return {"project": proj.id, **_summarise_run(summary)}


def record_verdict(home: str | Path | None = None, project: str = "",
                   fingerprint: str = "", status: str = "", note: str = "",
                   operator: str = "") -> dict:
    """Record a tester's verdict on a finding (confirmed, false-positive or
    accepted-risk). The two that remove a finding from the report need a note.
    Appends to the audit trail."""
    from ..orchestrator.validation import ValidationError, record

    if status not in _VERDICT_STATUS:
        return {"error": f"unknown verdict {status!r}; choose confirmed, "
                         "false-positive or accepted-risk"}
    who = operator.strip() or current_operator()
    with _session(home) as (repos, audit_trail):
        proj, error = _resolve_project(repos, project)
        if proj is None:
            return {"error": error}
        f = repos.findings.get_by_fingerprint(proj.id, fingerprint)
        if f is None:
            return {"error": f"no finding {fingerprint!r} in this project"}
        try:
            verdict = record(repos, audit_trail, f.id,
                             FindingStatus(_VERDICT_STATUS[status]),
                             operator=who, note=note)
        except ValidationError as exc:
            return {"error": f"the verdict was refused: {exc}"}
        return {"fingerprint": f.fingerprint, "title": verdict.finding.title,
                "status": verdict.status.value, "operator": who}


def scan(home: str | Path | None = None, sample_path: str = "",
         engagement_ref: str = "", operator: str = "", name: str = "",
         scope_note: str = "", out: str = "themob-out", attested: bool = False,
         *, _registry=None, _sandbox=None) -> dict:
    """Authorize, analyze and export a report in one gated step.

    Same gate as :func:`authorize_target`: it refuses without ``attested=true``
    and an engagement. Needs Docker for the pipeline. ``_registry`` / ``_sandbox``
    are injection points for the tests.
    """
    authorized = authorize_target(home, sample_path=sample_path,
                                  engagement_ref=engagement_ref, operator=operator,
                                  name=name, scope_note=scope_note,
                                  attested=attested)
    if "error" in authorized:
        return authorized
    project_id = authorized["project"]["id"]

    run = analyze(home, project=project_id, _registry=_registry, _sandbox=_sandbox)
    if "error" in run:
        return {**run, "project": _project_summary_from(home, project_id)}

    from ..report import export as export_report

    with _session(home) as (repos, audit_trail):
        workspace = Workspace(resolve_home(home), project_id)
        try:
            written = export_report(repos, audit_trail, project_id, out,
                                    operator=operator or current_operator(),
                                    workspace=workspace)
        except Exception as exc:                            # noqa: BLE001
            logger.exception("scan export failed")
            return {**run, "export_error": f"the report could not be written: {exc}"}
        report = written.report
        return {
            "project": project_id,
            "entities": run.get("entities", 0),
            "findings": report.total if report else 0,
            "severity_counts": report.counts if report else {},
            "files": {kind: str(path) for kind, path in written.files.items()},
            "failed": run.get("failed", []),
        }


def _project_summary_from(home, project_id) -> dict:
    with _session(home) as (repos, _audit):
        proj = repos.projects.get(project_id)
        return _project_summary(proj) if proj else {"id": project_id}
