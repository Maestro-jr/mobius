"""Authorization attestation and the tamper-evident audit trail.

themob decompiles software the operator does not own, so the authorization gate
is not ceremony: it is the legal record. Nothing in the pipeline runs until a
project carries an attestation, and every run appends to an audit trail that
cannot be edited after the fact.

Immutability has two layers:

1. ``audit_log`` has ``BEFORE UPDATE`` / ``BEFORE DELETE`` triggers that abort,
   no code path in this application can rewrite history.
2. Each entry carries ``_prev``/``_hash``: the SHA-256 of the previous entry's
   hash plus this entry's canonical payload. Editing the file out of band (with
   the sqlite CLI, say) breaks the chain, and :func:`verify_chain` finds where.

Mirrors TOPRECON's ``audit/attestation.py``, moved from JSONL onto the database
so attestations, runs and findings share one transactional store.
"""
from __future__ import annotations

import getpass
import hashlib
import json
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..storage.repositories import (AuditEntry, AuditRepository, Project,
                                    ProjectRepository)


class Action:
    """The audit vocabulary. Add here, never inline a bare string."""
    PROJECT_CREATED = "project.created"
    PROJECT_AUTHORIZED = "project.authorized"
    PROJECT_DELETED = "project.deleted"
    PIPELINE_STARTED = "pipeline.started"
    PIPELINE_FINISHED = "pipeline.finished"
    STAGE_STARTED = "stage.started"
    STAGE_FINISHED = "stage.finished"
    ANALYZER_STARTED = "analyzer.started"
    ANALYZER_FINISHED = "analyzer.finished"
    ANALYZER_FAILED = "analyzer.failed"
    FINDING_STATUS_CHANGED = "finding.status_changed"
    SECRET_REVEALED = "secret.revealed"
    REPORT_EXPORTED = "report.exported"
    # Phase 3. Separate from PROJECT_AUTHORIZED because assessing a binary and
    # executing it are different acts: see themob/dynamic/gate.py.
    EXECUTION_AUTHORIZED = "execution.authorized"
    # Testing whether a found credential is live touches the owning provider's
    # systems, so it is its own authorization: see themob/validate/gate.py.
    VALIDATION_AUTHORIZED = "validation.authorized"
    # The arms-length REA handoff (themob/rea.py): preparing a bundle for an
    # external reverse-engineering agent, and importing its result as a note on
    # a finding, are both on the trail, so what was sent out and what came back
    # are recorded like every other step.
    REA_PREPARED = "rea.prepared"
    REA_IMPORTED = "rea.imported"


# Reserved keys the chain owns inside ``detail``.
_PREV_KEY = "_prev"
_HASH_KEY = "_hash"
_GENESIS = "0" * 64


class AuthorizationError(PermissionError):
    """Raised when work is attempted on a project with no valid attestation.

    The pipeline fails closed on this: no attestation, no analysis.
    """


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _safe(fn) -> str:
    try:
        return str(fn())
    except Exception:                    # noqa: BLE001, identity is best-effort
        return "unknown"


def current_operator() -> str:
    """Who is running this. Recorded on every audit entry."""
    return f"{_safe(getpass.getuser)}@{_safe(socket.gethostname)}"


@dataclass(frozen=True)
class Attestation:
    """The operator's statement that they are authorized to assess this target."""
    target_name: str
    target_sha256: str
    operator: str
    engagement_ref: str = ""             # ticket / SOW / engagement identifier
    scope_note: str = ""
    attested: bool = False
    ts: str = field(default_factory=_utcnow_iso)

    def validate(self) -> None:
        if not self.attested:
            raise AuthorizationError(
                "authorization was not attested: the operator must confirm they "
                "own the target or hold written authorization to assess it")
        if not self.target_sha256 or len(self.target_sha256) != 64:
            raise AuthorizationError("attestation requires the target SHA-256")
        if not self.operator.strip():
            raise AuthorizationError("attestation requires an operator identity")

    @property
    def reference(self) -> str:
        """Stored on the project as ``authorization_ref``."""
        return self.engagement_ref.strip() or f"attested:{self.ts}"

    def to_detail(self) -> dict[str, Any]:
        return {
            "target_name": self.target_name,
            "engagement_ref": self.engagement_ref,
            "scope_note": self.scope_note,
            "attested": self.attested,
            "attested_at": self.ts,
        }


def _canonical(entry: AuditEntry, detail: dict[str, Any]) -> bytes:
    """Stable byte encoding of an entry, excluding the chain fields themselves."""
    payload = {
        "id": entry.id,
        "project_id": entry.project_id,
        "ts": entry.ts,
        "actor": entry.actor,
        "action": entry.action,
        "target_sha256": entry.target_sha256,
        "detail": {k: v for k, v in sorted(detail.items())
                   if k not in (_PREV_KEY, _HASH_KEY)},
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      default=str).encode("utf-8")


def _chain_hash(prev: str, entry: AuditEntry, detail: dict[str, Any]) -> str:
    return hashlib.sha256(prev.encode("ascii") + _canonical(entry, detail)).hexdigest()


class AuditTrail:
    """Append-only, hash-chained audit log for one database."""

    def __init__(self, audit_repo: AuditRepository) -> None:
        self._repo = audit_repo

    # -------------------------------------------------------------- appending

    def record(self, action: str, *, project_id: str | None = None,
               target_sha256: str | None = None, actor: str | None = None,
               **detail: Any) -> AuditEntry:
        """Append one entry, linked to the previous entry by hash."""
        if not action:
            raise ValueError("audit action is required")
        entry = AuditEntry(
            project_id=project_id,
            actor=actor or current_operator(),
            action=action,
            target_sha256=target_sha256,
            detail=dict(detail),
        )
        previous = self._repo.last()
        prev_hash = (previous.detail.get(_HASH_KEY) if previous else None) or _GENESIS
        entry.detail[_PREV_KEY] = prev_hash
        entry.detail[_HASH_KEY] = _chain_hash(prev_hash, entry, entry.detail)
        return self._repo.append(entry)

    def record_attestation(self, project: Project, attestation: Attestation,
                           projects: ProjectRepository) -> AuditEntry:
        """Validate an attestation, stamp it on the project, and audit it.

        Raises :class:`AuthorizationError` before anything is written if the
        attestation is incomplete: the gate fails closed.
        """
        attestation.validate()
        if attestation.target_sha256 != project.source_sha256:
            raise AuthorizationError(
                "attestation hash does not match the project's sample, refusing "
                "to authorize a different binary than the one that was attested")

        projects.set_authorization(project.id, ref=attestation.reference,
                                   by=attestation.operator, at=attestation.ts)
        return self.record(Action.PROJECT_AUTHORIZED, project_id=project.id,
                           target_sha256=project.source_sha256,
                           actor=attestation.operator, **attestation.to_detail())

    # --------------------------------------------------------------- querying

    def entries(self, project_id: str | None = None, limit: int = 500) -> list[AuditEntry]:
        return self._repo.list(project_id, limit=limit)

    def head(self) -> str:
        """The hash at the tip of the chain, spanning the whole log.

        A tamper-evident deliverable records this: it ties the exported report
        to the immutable trail without shipping the trail. GENESIS when the log
        is empty.
        """
        latest = self._repo.list(None, limit=1)
        if not latest:
            return _GENESIS
        return latest[0].detail.get(_HASH_KEY) or _GENESIS

    def verify_chain(self, project_id: str | None = None) -> tuple[bool, str]:
        """Re-walk the chain. Returns ``(ok, message)``.

        A project filter only makes sense for display; the chain spans the whole
        log, so verification always walks every entry.
        """
        prev = _GENESIS
        for entry in self._repo.list_ascending():
            recorded_prev = entry.detail.get(_PREV_KEY)
            recorded_hash = entry.detail.get(_HASH_KEY)
            if recorded_prev is None or recorded_hash is None:
                return False, f"entry {entry.id} ({entry.action}) is not chained"
            if recorded_prev != prev:
                return False, f"chain break before entry {entry.id} ({entry.action})"
            expected = _chain_hash(prev, entry, entry.detail)
            if expected != recorded_hash:
                return False, f"entry {entry.id} ({entry.action}) was modified"
            prev = recorded_hash
        return True, "audit chain intact"


def require_authorization(project: Project | None) -> Project:
    """Gate every pipeline entry point. Fails closed on anything unexpected."""
    if project is None:
        raise AuthorizationError("no project. Nothing is authorized")
    if not project.is_authorized:
        raise AuthorizationError(
            f"project {project.name!r} has no authorization attestation; "
            "analysis is refused until the authorization gate is completed")
    return project
