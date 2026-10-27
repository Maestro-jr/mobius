"""Authorize a target: intake plus attestation, as one Qt-free step.

The authorization gate is the one control the whole tool rests on, and until now
the code that binds it to intake lived in ``app/auth_gate.py``, behind a PyQt6
import. The window needs it and so does the headless CLI, and the CLI must not
drag in a UI toolkit to ingest a file. So the logic lives here, importing nothing
from ``app/``: the dialog collects the operator's statement and hands it over, and
the CLI does the same from its arguments.

The contract is the gate's contract, unchanged: intake first, then the
attestation, and if the attestation is refused the project and its workspace are
removed so an unauthorized sample never lingers on disk. The rollback is itself
recorded before it happens, because the audit trail outlives the project it
describes (migration 0002): "ingested, then refused" stays on record.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from ..audit.attestation import (Action, Attestation, AuditTrail,
                                 AuthorizationError, current_operator)
from .intake import IntakeResult, intake

logger = logging.getLogger(__name__)


@dataclass
class GateDecision:
    """What an operator attested to, however they were asked.

    The Qt dialog fills this from its fields; the CLI fills it from its
    arguments and an interactive confirmation. ``operator`` is explicit so the
    CLI can record who ran a headless scan, rather than always the OS user; left
    blank it falls back to :func:`current_operator`.
    """

    sample_path: str | Path
    project_name: str = ""
    engagement_ref: str = ""
    scope_note: str = ""
    attested: bool = False
    operator: str = ""


def authorize_target(decision: GateDecision, repos, audit: AuditTrail, *,
                     root: Path | None = None) -> IntakeResult:
    """Ingest the sample and record the attestation, atomically.

    Raises :class:`~themob.orchestrator.intake.IntakeError` if the file is not a
    package, or :class:`AuthorizationError` if the attestation is incomplete; on
    the latter the half-made project is rolled back. The caller shows the
    message.
    """
    result = intake(decision.sample_path, repos, audit,
                    name=decision.project_name, root=root)
    operator = decision.operator.strip() or current_operator()
    try:
        audit.record_attestation(
            result.project,
            Attestation(
                target_name=result.target.name or result.project.name,
                target_sha256=result.project.source_sha256,
                operator=operator,
                engagement_ref=decision.engagement_ref,
                scope_note=decision.scope_note,
                attested=decision.attested,
            ),
            repos.projects,
        )
    except AuthorizationError:
        logger.warning("attestation rejected, rolling back project %s",
                       result.project.id)
        # Recorded before the delete: the trail outlives the project it names.
        audit.record(Action.PROJECT_DELETED, project_id=result.project.id,
                     target_sha256=result.project.source_sha256,
                     reason="attestation rejected at the authorization gate")
        repos.projects.delete(result.project.id)
        result.workspace.delete()
        raise

    authorized = repos.projects.get(result.project.id)
    if authorized is not None:
        result.project = authorized
    return result
