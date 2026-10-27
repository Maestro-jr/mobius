"""Repositories: the only code that talks SQL.

Everything above this layer works with Pydantic models (``Entity``, ``Edge``,
``Finding``) and the :class:`Project` / :class:`Job` records defined here.

Two upserts carry the system's core semantics and are worth reading closely:

* :meth:`EntityRepository.upsert` collides on ``(project_id, type, key)`` so two
  analyzers that discover the same thing converge on **one** graph node, with
  their attributes merged rather than duplicated.
* :meth:`FindingRepository.upsert` collides on ``(project_id, fingerprint)`` so
  two tools reporting the same weakness at the same place merge into **one**
  finding with two rows in ``finding_sources``, the agreement trail that
  cross-tool voting scores later.

``Project`` and ``Job`` live here rather than in ``model/`` because they are
storage records with no analyzer-facing behaviour; the locked Pydantic model
package stays exactly as delivered.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence
from uuid import uuid4

from ..model.entities import Edge, Entity
from ..model.enums import (EdgeType, EntityType, EvidenceKind, FindingStatus,
                           JobStatus, MASVSCategory, Platform, Severity, Stage)
from ..model.findings import (DataFlowStep, Evidence, Finding, FindingSource,
                              Location, Remediation)
from .db import Database

# Higher wins when two reports of the same finding disagree on severity.
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

# A status the tester set by hand is never overwritten by a re-run.
_HUMAN_STATUSES = {
    FindingStatus.CONFIRMED,
    FindingStatus.FALSE_POSITIVE,
    FindingStatus.ACCEPTED_RISK,
}


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), default=str)


def _loads(value: str | None, fallback: Any) -> Any:
    if not value:
        return fallback
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return fallback


class RepositoryError(RuntimeError):
    """A repository was given data the schema cannot accept."""


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------

@dataclass
class Project:
    """One assessment: one uploaded app plus its authorization record."""
    id: str = field(default_factory=lambda: uuid4().hex)
    name: str = ""
    target_platform: Platform = Platform.ANDROID
    source_path: str = ""               # workspace-relative path to the sample
    source_sha256: str = ""
    authorization_ref: str | None = None
    authorized_by: str | None = None
    authorized_at: str | None = None
    created_at: str = field(default_factory=_utcnow_iso)

    @property
    def is_authorized(self) -> bool:
        return bool(self.authorized_at and self.authorized_by)


@dataclass
class Job:
    """One analyzer run within a stage."""
    id: str = field(default_factory=lambda: uuid4().hex)
    project_id: str = ""
    stage: Stage = Stage.INTAKE
    analyzer: str | None = None
    status: JobStatus = JobStatus.PENDING
    started_at: str | None = None
    finished_at: str | None = None
    error: str | None = None
    created_at: str = field(default_factory=_utcnow_iso)


@dataclass
class Note:
    """One thing a tester wrote about a finding."""
    id: str = field(default_factory=lambda: uuid4().hex)
    finding_id: str = ""
    author: str = ""
    text: str = ""
    created_at: str = field(default_factory=_utcnow_iso)


@dataclass
class SavedQuery:
    """One stored question. ``definition`` is a Query serialised as JSON."""
    id: str = field(default_factory=lambda: uuid4().hex)
    key: str = ""
    title: str = ""
    description: str = ""
    definition: str = "{}"
    author: str = ""
    created_at: str = field(default_factory=_utcnow_iso)
    updated_at: str = field(default_factory=_utcnow_iso)


@dataclass
class AuditEntry:
    """One immutable line in the audit trail."""
    id: str = field(default_factory=lambda: uuid4().hex)
    project_id: str | None = None
    ts: str = field(default_factory=_utcnow_iso)
    actor: str = ""
    action: str = ""
    target_sha256: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Projects
# ---------------------------------------------------------------------------

class ProjectRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def create(self, project: Project) -> Project:
        if not project.name.strip():
            raise RepositoryError("project name is required")
        if not project.source_sha256:
            raise RepositoryError("project source_sha256 is required")
        self._db.execute(
            "INSERT INTO projects (id, name, target_platform, source_path, "
            "source_sha256, authorization_ref, authorized_by, authorized_at, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (project.id, project.name.strip(), project.target_platform.value,
             project.source_path, project.source_sha256, project.authorization_ref,
             project.authorized_by, project.authorized_at, project.created_at),
        )
        return project

    def get(self, project_id: str) -> Project | None:
        row = self._db.query_one("SELECT * FROM projects WHERE id = ?", (project_id,))
        return self._row(row) if row else None

    def list(self, limit: int = 100) -> list[Project]:
        rows = self._db.query(
            "SELECT * FROM projects ORDER BY created_at DESC LIMIT ?", (int(limit),))
        return [self._row(r) for r in rows]

    def set_authorization(self, project_id: str, *, ref: str, by: str,
                          at: str | None = None) -> None:
        """Record the attestation that unlocks the pipeline for this project."""
        self._db.execute(
            "UPDATE projects SET authorization_ref = ?, authorized_by = ?, "
            "authorized_at = ? WHERE id = ?",
            (ref, by, at or _utcnow_iso(), project_id),
        )

    def delete(self, project_id: str) -> None:
        """Delete a project; cascades to every row that references it."""
        self._db.execute("DELETE FROM projects WHERE id = ?", (project_id,))

    @staticmethod
    def _row(row) -> Project:
        return Project(
            id=row["id"], name=row["name"],
            target_platform=Platform(row["target_platform"]),
            source_path=row["source_path"], source_sha256=row["source_sha256"],
            authorization_ref=row["authorization_ref"],
            authorized_by=row["authorized_by"], authorized_at=row["authorized_at"],
            created_at=row["created_at"],
        )


# ---------------------------------------------------------------------------
# Entities and edges: the attack-surface graph
# ---------------------------------------------------------------------------

class EntityRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def upsert(self, project_id: str, entity: Entity) -> Entity:
        """Insert *entity*, or merge it into the existing node with the same key.

        Attributes merge shallowly with the incoming value winning, so a later
        analyzer can enrich a node another one created. Returns the stored
        entity: note its ``id`` may differ from the one passed in when the node
        already existed; always use the returned object.

        **A null in an update means "I have nothing to say", not "delete it".**
        ``json_patch`` implements RFC 7396, where a null member removes the key,
        so the merge is fed a copy with nulls stripped. Without that, apktool
        finding no network security config would erase the reference androguard
        recovered from the manifest, and the config auditor would then report
        that an app declaring an NSC has none. Absence of knowledge in one tool
        must never destroy another tool's knowledge.

        The INSERT still carries the nulls, because on a *new* node an explicit
        null is real information: ``exported_declared = None`` means the manifest
        omitted ``android:exported``, which is itself worth auditing.
        """
        if not entity.key:
            raise RepositoryError("entity key is required")
        merged = {k: v for k, v in entity.attributes.items() if v is not None}
        row = self._db.query_one(
            "INSERT INTO entities (id, project_id, type, platform, key, label, attributes) "
            "VALUES (?,?,?,?,?,?,?) "
            "ON CONFLICT (project_id, type, key) DO UPDATE SET "
            "  label = COALESCE(excluded.label, entities.label), "
            "  attributes = json_patch(entities.attributes, ?) "
            "RETURNING *",
            (entity.id, project_id, entity.type.value, entity.platform.value,
             entity.key, entity.label, _json(entity.attributes), _json(merged)),
        )
        return self._row(row)

    def upsert_many(self, project_id: str, entities: Iterable[Entity]) -> list[Entity]:
        return [self.upsert(project_id, e) for e in entities]

    def get(self, entity_id: str) -> Entity | None:
        row = self._db.query_one("SELECT * FROM entities WHERE id = ?", (entity_id,))
        return self._row(row) if row else None

    def get_by_key(self, project_id: str, etype: EntityType, key: str) -> Entity | None:
        row = self._db.query_one(
            "SELECT * FROM entities WHERE project_id = ? AND type = ? AND key = ?",
            (project_id, etype.value, key))
        return self._row(row) if row else None

    def list(self, project_id: str, etype: EntityType | None = None) -> list[Entity]:
        if etype is None:
            rows = self._db.query(
                "SELECT * FROM entities WHERE project_id = ? ORDER BY type, key",
                (project_id,))
        else:
            rows = self._db.query(
                "SELECT * FROM entities WHERE project_id = ? AND type = ? ORDER BY key",
                (project_id, etype.value))
        return [self._row(r) for r in rows]

    def counts_by_type(self, project_id: str) -> dict[EntityType, int]:
        rows = self._db.query(
            "SELECT type, COUNT(*) AS n FROM entities WHERE project_id = ? GROUP BY type",
            (project_id,))
        counts = {t: 0 for t in EntityType}
        for row in rows:
            try:
                counts[EntityType(row["type"])] = int(row["n"])
            except ValueError:            # a type not in the enum: ignore, don't crash
                continue
        return counts

    def count(self, project_id: str) -> int:
        row = self._db.query_one(
            "SELECT COUNT(*) AS n FROM entities WHERE project_id = ?", (project_id,))
        return int(row["n"]) if row else 0

    @staticmethod
    def _row(row) -> Entity:
        return Entity(
            id=row["id"], type=EntityType(row["type"]),
            platform=Platform(row["platform"]), key=row["key"], label=row["label"],
            attributes=_loads(row["attributes"], {}),
            created_at=row["created_at"],
        )


class EdgeRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def upsert(self, project_id: str, edge: Edge) -> Edge:
        """Insert a typed edge; identical (src, dst, type) triples collapse."""
        row = self._db.query_one(
            "INSERT INTO edges (id, project_id, src_id, dst_id, type, attributes) "
            "VALUES (?,?,?,?,?,?) "
            "ON CONFLICT (project_id, src_id, dst_id, type) DO UPDATE SET "
            "  attributes = json_patch(edges.attributes, excluded.attributes) "
            "RETURNING *",
            (edge.id, project_id, edge.src_id, edge.dst_id, edge.type.value,
             _json(edge.attributes)),
        )
        return self._row(row)

    def connect(self, project_id: str, src: Entity, dst: Entity, etype: EdgeType,
                **attributes: Any) -> Edge:
        """Convenience: link two stored entities."""
        return self.upsert(project_id, Edge(src_id=src.id, dst_id=dst.id,
                                            type=etype, attributes=attributes))

    def list(self, project_id: str) -> list[Edge]:
        rows = self._db.query(
            "SELECT * FROM edges WHERE project_id = ?", (project_id,))
        return [self._row(r) for r in rows]

    def neighbors(self, project_id: str, entity_id: str) -> list[Edge]:
        rows = self._db.query(
            "SELECT * FROM edges WHERE project_id = ? AND (src_id = ? OR dst_id = ?)",
            (project_id, entity_id, entity_id))
        return [self._row(r) for r in rows]

    def count(self, project_id: str) -> int:
        row = self._db.query_one(
            "SELECT COUNT(*) AS n FROM edges WHERE project_id = ?", (project_id,))
        return int(row["n"]) if row else 0

    @staticmethod
    def _row(row) -> Edge:
        return Edge(
            id=row["id"], src_id=row["src_id"], dst_id=row["dst_id"],
            type=EdgeType(row["type"]), attributes=_loads(row["attributes"], {}),
            created_at=row["created_at"],
        )


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

class FindingRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def upsert(self, project_id: str, finding: Finding) -> Finding:
        """Insert a finding, or merge it into the one with the same fingerprint.

        Merge policy on collision: keep the **higher** severity and confidence,
        never overwrite a status the tester set by hand, and append the reporting
        tool to ``finding_sources``. Evidence and entity links are additive.
        Confidence *scoring* from agreement is the normalizer's job; this layer
        only guarantees the merge happens and the agreement trail is recorded.
        """
        if not finding.fingerprint:
            raise RepositoryError("finding fingerprint is required")

        existing = self.get_by_fingerprint(project_id, finding.fingerprint)
        if existing is None:
            self._insert(project_id, finding)
            stored_id = finding.id
        else:
            stored_id = existing.id
            self._merge(existing, finding)

        for source in finding.sources:
            # The incoming finding is this reporter's report, so its confidence
            # is this reporter's opinion. Captured before any merge collapses it.
            self.add_source(stored_id, source, finding.confidence)
        for item in finding.evidence:
            self.add_evidence(stored_id, item)
        if finding.entity_ids:
            self.link_entities(stored_id, finding.entity_ids)

        stored = self.get(stored_id)
        if stored is None:                                    # pragma: no cover
            raise RepositoryError("finding vanished during upsert")
        return stored

    def _insert(self, project_id: str, f: Finding) -> None:
        self._db.execute(
            "INSERT INTO findings (id, project_id, fingerprint, weakness_key, title, "
            "description, "
            "severity, base_severity, confidence, status, requires_manual_validation, "
            "masvs_category, "
            "masvs_control, maswe_id, mobile_top10, cwe, risk, score_rationale, "
            "location, data_flow, "
            "remediation, created_at, updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (f.id, project_id, f.fingerprint, f.weakness_key, f.title, f.description,
             # base_severity is the reporter's own rating, kept so the scorer
             # can raise from a fixed starting point on every run.
             f.severity.value, f.severity.value, float(f.confidence), f.status.value,
             1 if f.requires_manual_validation else 0,
             f.masvs_category.value if f.masvs_category else None,
             f.masvs_control, f.maswe_id, f.mobile_top10, f.cwe,
             # Normally the scorer fills these, but a Finding that arrives
             # carrying them must not lose them silently on the way in.
             None if f.risk is None else float(f.risk), f.score_rationale,
             _json(f.location.model_dump(by_alias=True)) if f.location else None,
             _json([s.model_dump() for s in f.data_flow]),
             _json(f.remediation.model_dump()) if f.remediation else None,
             f.created_at.isoformat(timespec="seconds"), _utcnow_iso()),
        )

    def _merge(self, existing: Finding, incoming: Finding) -> None:
        severity = max(existing.severity, incoming.severity,
                       key=lambda s: _SEVERITY_RANK[s])
        confidence = max(existing.confidence, incoming.confidence)
        status = (existing.status if existing.status in _HUMAN_STATUSES
                  else incoming.status)
        # Fill in standards mapping / remediation the first reporter did not have.
        self._db.execute(
            "UPDATE findings SET severity = ?, confidence = ?, status = ?, "
            "  description = CASE WHEN description = '' THEN ? ELSE description END, "
            "  weakness_key   = COALESCE(weakness_key, ?), "
            "  masvs_category = COALESCE(masvs_category, ?), "
            "  masvs_control  = COALESCE(masvs_control, ?), "
            "  maswe_id       = COALESCE(maswe_id, ?), "
            "  mobile_top10   = COALESCE(mobile_top10, ?), "
            "  cwe            = COALESCE(cwe, ?), "
            "  location       = COALESCE(location, ?), "
            "  remediation    = COALESCE(remediation, ?), "
            "  updated_at = ? "
            "WHERE id = ?",
            (severity.value, float(confidence), status.value,
             incoming.description,
             incoming.weakness_key,
             incoming.masvs_category.value if incoming.masvs_category else None,
             incoming.masvs_control, incoming.maswe_id, incoming.mobile_top10,
             incoming.cwe,
             _json(incoming.location.model_dump(by_alias=True)) if incoming.location else None,
             _json(incoming.remediation.model_dump()) if incoming.remediation else None,
             _utcnow_iso(), existing.id),
        )

    # -- attachments ---------------------------------------------------------

    def add_source(self, finding_id: str, source: FindingSource,
                   confidence: float | None = None) -> None:
        """Record that a tool reported this finding (idempotent per tool+rule).

        ``confidence`` is *this reporter's* opinion, not the finding's merged
        value. Cross-tool voting asks how likely it is that every reporter is
        wrong, which cannot be answered once the weaker opinions have been
        collapsed into the strongest one.
        """
        self._db.execute(
            "INSERT OR IGNORE INTO finding_sources "
            "(id, finding_id, tool, rule, raw_ref, confidence) "
            "VALUES (?,?,?,?,?,?)",
            (uuid4().hex, finding_id, source.tool, source.rule, source.raw_ref,
             None if confidence is None else float(confidence)),
        )

    def add_evidence(self, finding_id: str, item: Evidence) -> None:
        self._db.execute(
            "INSERT INTO evidence (id, finding_id, kind, value, artifact_path) "
            "VALUES (?,?,?,?,?)",
            (uuid4().hex, finding_id, item.kind.value, item.value, item.artifact_path),
        )

    def link_entities(self, finding_id: str, entity_ids: Sequence[str]) -> None:
        for entity_id in entity_ids:
            self._db.execute(
                "INSERT OR IGNORE INTO finding_entities (finding_id, entity_id) "
                "VALUES (?,?)", (finding_id, entity_id))

    # -- reads ---------------------------------------------------------------

    def get(self, finding_id: str) -> Finding | None:
        row = self._db.query_one("SELECT * FROM findings WHERE id = ?", (finding_id,))
        return self._hydrate(row) if row else None

    def project_of(self, finding_id: str) -> str | None:
        """Which project a finding belongs to, without hydrating the whole row.

        The audit trail is keyed by project, and a verdict recorded against the
        wrong one is worse than useless.
        """
        row = self._db.query_one(
            "SELECT project_id FROM findings WHERE id = ?", (finding_id,))
        return row["project_id"] if row else None

    def get_by_fingerprint(self, project_id: str, fingerprint: str) -> Finding | None:
        row = self._db.query_one(
            "SELECT * FROM findings WHERE project_id = ? AND fingerprint = ?",
            (project_id, fingerprint))
        return self._hydrate(row) if row else None

    def list(self, project_id: str, *, severity: Severity | None = None,
             status: FindingStatus | None = None,
             masvs_category: MASVSCategory | None = None,
             limit: int = 1000) -> list[Finding]:
        sql = ["SELECT * FROM findings WHERE project_id = ?"]
        params: list[Any] = [project_id]
        if severity is not None:
            sql.append("AND severity = ?")
            params.append(severity.value)
        if status is not None:
            sql.append("AND status = ?")
            params.append(status.value)
        if masvs_category is not None:
            sql.append("AND masvs_category = ?")
            params.append(masvs_category.value)
        # Severity order is textual in SQLite, so rank it explicitly.
        sql.append(
            "ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, confidence DESC LIMIT ?")
        params.append(int(limit))
        rows = self._db.query(" ".join(sql), tuple(params))
        return [self._hydrate(r) for r in rows]

    def counts_by_severity(self, project_id: str) -> dict[Severity, int]:
        rows = self._db.query(
            "SELECT severity, COUNT(*) AS n FROM findings WHERE project_id = ? "
            "GROUP BY severity", (project_id,))
        counts = {s: 0 for s in Severity}
        for row in rows:
            try:
                counts[Severity(row["severity"])] = int(row["n"])
            except ValueError:
                continue
        return counts

    def count(self, project_id: str) -> int:
        row = self._db.query_one(
            "SELECT COUNT(*) AS n FROM findings WHERE project_id = ?", (project_id,))
        return int(row["n"]) if row else 0

    def add_note(self, finding_id: str, text: str, author: str = "") -> "Note":
        """Record what the tester said about this finding.

        A status with no reason is an assertion the next reader has to take on
        trust. Notes accumulate rather than replace, because the sequence of a
        doubt, a reproduction attempt and an answer is often the useful part.
        """
        text = (text or "").strip()
        if not text:
            raise RepositoryError("a note needs text")
        note = Note(finding_id=finding_id, text=text, author=author.strip())
        self._db.execute(
            "INSERT INTO finding_notes (id, finding_id, author, text, created_at) "
            "VALUES (?,?,?,?,?)",
            (note.id, finding_id, note.author, note.text, note.created_at))
        return note

    def notes(self, finding_id: str) -> list["Note"]:
        rows = self._db.query(
            "SELECT * FROM finding_notes WHERE finding_id = ? ORDER BY created_at",
            (finding_id,))
        return [Note(id=r["id"], finding_id=r["finding_id"], author=r["author"],
                     text=r["text"], created_at=r["created_at"]) for r in rows]

    def set_status(self, finding_id: str, status: FindingStatus) -> None:
        """The manual-validation workflow: confirm / false positive / accept risk."""
        self._db.execute(
            "UPDATE findings SET status = ?, updated_at = ? WHERE id = ?",
            (status.value, _utcnow_iso(), finding_id))

    def set_confidence(self, finding_id: str, confidence: float) -> None:
        if not 0.0 <= confidence <= 1.0:
            raise RepositoryError("confidence must be between 0.0 and 1.0")
        self._db.execute(
            "UPDATE findings SET confidence = ?, updated_at = ? WHERE id = ?",
            (float(confidence), _utcnow_iso(), finding_id))

    def set_data_flow(self, finding_id: str,
                      steps: Sequence[DataFlowStep]) -> None:
        """Replace a finding's recorded flow, source first, sinks after.

        Replaced rather than appended: a re-run traces the same value again and
        appending would grow the same path every time the pipeline is run.
        """
        payload = _json([s.model_dump(by_alias=True) for s in steps])
        self._db.execute(
            "UPDATE findings SET data_flow = ?, updated_at = ? WHERE id = ?",
            (payload, _utcnow_iso(), finding_id))

    def source_votes(self, finding_id: str) -> list[tuple[str, float | None]]:
        """``(tool, confidence)`` per reporter, for cross-tool voting.

        Separate from :meth:`sources` because ``FindingSource`` is part of the
        fixed model package and carries provenance, not scoring inputs.
        """
        rows = self._db.query(
            "SELECT tool, confidence FROM finding_sources WHERE finding_id = ? "
            "ORDER BY tool", (finding_id,))
        return [(r["tool"], None if r["confidence"] is None
                 else float(r["confidence"])) for r in rows]

    def set_score(self, finding_id: str, *, severity: Severity,
                  masvs_category: MASVSCategory | None,
                  masvs_control: str | None, maswe_id: str | None,
                  mobile_top10: str | None, cwe: str | None,
                  risk: float, rationale: str) -> None:
        """Write the scorer's verdict and the standards mapping.

        The mapping is overwritten rather than filled in only when missing: it
        comes from the weakness pack, so a correction there has to reach
        findings that were stored before it.

        Status is untouched. A tester's verdict outranks arithmetic, and
        severity and status are separate axes.
        """
        self._db.execute(
            "UPDATE findings SET severity = ?, masvs_category = ?, "
            "  masvs_control = ?, maswe_id = ?, mobile_top10 = ?, cwe = ?, "
            "  risk = ?, score_rationale = ?, updated_at = ? WHERE id = ?",
            (severity.value,
             masvs_category.value if masvs_category else None,
             masvs_control, maswe_id, mobile_top10, cwe,
             float(risk), rationale or None, _utcnow_iso(), finding_id))

    def sources(self, finding_id: str) -> list[FindingSource]:
        rows = self._db.query(
            "SELECT tool, rule, raw_ref FROM finding_sources WHERE finding_id = ? "
            "ORDER BY tool, rule", (finding_id,))
        return [FindingSource(tool=r["tool"], rule=r["rule"], raw_ref=r["raw_ref"])
                for r in rows]

    def evidence(self, finding_id: str) -> list[Evidence]:
        rows = self._db.query(
            "SELECT kind, value, artifact_path FROM evidence WHERE finding_id = ? "
            "ORDER BY created_at", (finding_id,))
        return [Evidence(kind=EvidenceKind(r["kind"]), value=r["value"],
                         artifact_path=r["artifact_path"]) for r in rows]

    def entity_ids(self, finding_id: str) -> list[str]:
        rows = self._db.query(
            "SELECT entity_id FROM finding_entities WHERE finding_id = ?", (finding_id,))
        return [r["entity_id"] for r in rows]

    def _hydrate(self, row) -> Finding:
        location = _loads(row["location"], None)
        remediation = _loads(row["remediation"], None)
        return Finding(
            id=row["id"], fingerprint=row["fingerprint"],
            weakness_key=row["weakness_key"], title=row["title"],
            description=row["description"], severity=Severity(row["severity"]),
            confidence=float(row["confidence"]), status=FindingStatus(row["status"]),
            base_severity=(Severity(row["base_severity"])
                           if row["base_severity"] else None),
            risk=None if row["risk"] is None else float(row["risk"]),
            score_rationale=row["score_rationale"],
            requires_manual_validation=bool(row["requires_manual_validation"]),
            masvs_category=(MASVSCategory(row["masvs_category"])
                            if row["masvs_category"] else None),
            masvs_control=row["masvs_control"], maswe_id=row["maswe_id"],
            mobile_top10=row["mobile_top10"], cwe=row["cwe"],
            location=Location(**location) if location else None,
            data_flow=[DataFlowStep(**s) for s in _loads(row["data_flow"], [])],
            remediation=Remediation(**remediation) if remediation else None,
            evidence=self.evidence(row["id"]),
            sources=self.sources(row["id"]),
            entity_ids=self.entity_ids(row["id"]),
            created_at=row["created_at"], updated_at=row["updated_at"],
        )


# ---------------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------------

class JobRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def create(self, project_id: str, stage: Stage, analyzer: str | None = None) -> Job:
        job = Job(project_id=project_id, stage=stage, analyzer=analyzer)
        self._db.execute(
            "INSERT INTO jobs (id, project_id, stage, analyzer, status, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (job.id, project_id, stage.value, analyzer, job.status.value, job.created_at))
        return job

    def start(self, job_id: str) -> None:
        self._db.execute(
            "UPDATE jobs SET status = ?, started_at = ? WHERE id = ?",
            (JobStatus.RUNNING.value, _utcnow_iso(), job_id))

    def finish(self, job_id: str, status: JobStatus, error: str | None = None) -> None:
        if status in (JobStatus.PENDING, JobStatus.RUNNING):
            raise RepositoryError(f"{status.value} is not a terminal job status")
        self._db.execute(
            "UPDATE jobs SET status = ?, finished_at = ?, error = ? WHERE id = ?",
            (status.value, _utcnow_iso(), error, job_id))

    def get(self, job_id: str) -> Job | None:
        row = self._db.query_one("SELECT * FROM jobs WHERE id = ?", (job_id,))
        return self._row(row) if row else None

    def list(self, project_id: str) -> list[Job]:
        rows = self._db.query(
            "SELECT * FROM jobs WHERE project_id = ? ORDER BY created_at", (project_id,))
        return [self._row(r) for r in rows]

    @staticmethod
    def _row(row) -> Job:
        return Job(
            id=row["id"], project_id=row["project_id"], stage=Stage(row["stage"]),
            analyzer=row["analyzer"], status=JobStatus(row["status"]),
            started_at=row["started_at"], finished_at=row["finished_at"],
            error=row["error"], created_at=row["created_at"],
        )


# ---------------------------------------------------------------------------
# Audit: append-only (UPDATE/DELETE are blocked by triggers in the schema)
# ---------------------------------------------------------------------------

class AuditRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def append(self, entry: AuditEntry) -> AuditEntry:
        if not entry.actor or not entry.action:
            raise RepositoryError("audit entries require an actor and an action")
        self._db.execute(
            "INSERT INTO audit_log (id, project_id, ts, actor, action, target_sha256, detail) "
            "VALUES (?,?,?,?,?,?,?)",
            (entry.id, entry.project_id, entry.ts, entry.actor, entry.action,
             entry.target_sha256, _json(entry.detail)),
        )
        return entry

    def list(self, project_id: str | None = None, limit: int = 500) -> list[AuditEntry]:
        if project_id is None:
            rows = self._db.query(
                "SELECT * FROM audit_log ORDER BY ts DESC, rowid DESC LIMIT ?",
                (int(limit),))
        else:
            rows = self._db.query(
                "SELECT * FROM audit_log WHERE project_id = ? "
                "ORDER BY ts DESC, rowid DESC LIMIT ?", (project_id, int(limit)))
        return [self._row(r) for r in rows]

    def list_ascending(self, project_id: str | None = None) -> list[AuditEntry]:
        """Entries in insertion order: what hash-chain verification walks.

        ``ts`` has one-second resolution and ties are common during a fast run,
        so order by ``rowid``, which is the true insertion order.
        """
        if project_id is None:
            rows = self._db.query("SELECT * FROM audit_log ORDER BY rowid")
        else:
            rows = self._db.query(
                "SELECT * FROM audit_log WHERE project_id = ? ORDER BY rowid",
                (project_id,))
        return [self._row(r) for r in rows]

    def last(self, project_id: str | None = None) -> AuditEntry | None:
        if project_id is None:
            row = self._db.query_one("SELECT * FROM audit_log ORDER BY rowid DESC LIMIT 1")
        else:
            row = self._db.query_one(
                "SELECT * FROM audit_log WHERE project_id = ? ORDER BY rowid DESC LIMIT 1",
                (project_id,))
        return self._row(row) if row else None

    @staticmethod
    def _row(r) -> AuditEntry:
        return AuditEntry(
            id=r["id"], project_id=r["project_id"], ts=r["ts"], actor=r["actor"],
            action=r["action"], target_sha256=r["target_sha256"],
            detail=_loads(r["detail"], {}))


# ---------------------------------------------------------------------------
# Saved queries
# ---------------------------------------------------------------------------

class SavedQueryRepository:
    """The questions a tester wants back next week.

    Not scoped to a project on purpose: a saved query is a way of working, not a
    fact about one APK. See migration 0007.

    The definition round-trips through JSON, and it is validated on the way out
    rather than trusted. A row can be older than the code reading it, or
    hand-edited, and a query that half-loads would silently answer a different
    question from the one that was saved.
    """

    def __init__(self, db: Database) -> None:
        self._db = db

    def save(self, query, *, author: str = "") -> "SavedQuery":
        """Insert or update by key. Refuses to shadow a builtin."""
        from ..correlate.queries import builtin, to_json

        key = (query.key or "").strip()
        if not key:
            raise RepositoryError("a saved query needs a key")
        if builtin(key) is not None:
            raise RepositoryError(
                f"{key!r} is a built-in query; saving over it would silently "
                "change what the builtin does. Choose another key.")

        now = _utcnow_iso()
        existing = self.get(key)
        record = SavedQuery(
            id=existing.id if existing else uuid4().hex,
            key=key, title=query.title or key,
            description=query.description, definition=to_json(query),
            author=author or (existing.author if existing else ""),
            created_at=existing.created_at if existing else now,
            updated_at=now)

        self._db.execute(
            "INSERT INTO saved_queries (id, key, title, description, "
            "definition, author, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET title = excluded.title, "
            "description = excluded.description, definition = excluded.definition, "
            "author = excluded.author, updated_at = excluded.updated_at",
            (record.id, record.key, record.title, record.description,
             record.definition, record.author, record.created_at,
             record.updated_at),
        )
        return record

    def get(self, key: str) -> "SavedQuery | None":
        row = self._db.query_one("SELECT * FROM saved_queries WHERE key = ?",
                                 (key,))
        return self._row(row) if row else None

    def list(self, limit: int = 200) -> list["SavedQuery"]:
        rows = self._db.query(
            "SELECT * FROM saved_queries ORDER BY title LIMIT ?", (int(limit),))
        return [self._row(r) for r in rows]

    def delete(self, key: str) -> None:
        self._db.execute("DELETE FROM saved_queries WHERE key = ?", (key,))

    def load(self, key: str):
        """The stored row as a runnable Query, or None.

        Raises :class:`RepositoryError` when the row exists but does not parse,
        because "your saved query is corrupt" is an answer and silently
        returning nothing is not.
        """
        from ..correlate.queries import QueryError, from_json

        record = self.get(key)
        if record is None:
            return None
        try:
            return from_json(record.definition)
        except (QueryError, ValueError) as exc:
            raise RepositoryError(
                f"saved query {key!r} could not be read: {exc}") from None

    @staticmethod
    def _row(row) -> "SavedQuery":
        return SavedQuery(
            id=row["id"], key=row["key"], title=row["title"],
            description=row["description"], definition=row["definition"],
            author=row["author"], created_at=row["created_at"],
            updated_at=row["updated_at"])


# ---------------------------------------------------------------------------
# Facade
# ---------------------------------------------------------------------------

class Repositories:
    """Every repository over one database, so callers pass a single object."""

    def __init__(self, db: Database) -> None:
        self.db = db
        self.projects = ProjectRepository(db)
        self.entities = EntityRepository(db)
        self.edges = EdgeRepository(db)
        self.findings = FindingRepository(db)
        self.jobs = JobRepository(db)
        self.audit = AuditRepository(db)
        self.queries = SavedQueryRepository(db)
