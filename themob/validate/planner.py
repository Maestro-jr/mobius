"""Turn secret findings into runnable probes, and results into verdicts.

The planner reads the secret findings a scan already produced, works out which
provider each belongs to, and prepares the read-only probe an operator runs. It
records nothing when it plans: preparing a command is safe, and the gate has
already authorised running one. What it records is the *result* the operator
brings back, which lands as an ordinary verdict in the manual-validation
workflow, so "the provider says this key is live" is captured the same way any
other human conclusion about a finding is, beside the evidence and never over
it.

A live result does not silently rewrite the severity. That is deliberate and
consistent with the rest of themob: a verdict is a human conclusion recorded in
the audit trail, and the scorer, not a verdict, owns severity. What a confirmed
live credential gets is a CONFIRMED verdict and a note saying the provider
agreed; a revoked one gets ACCEPTED_RISK with the reason, which is what removes
a dead key from the body of the report without pretending it was never there.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..model.enums import EntityType, FindingStatus
from ..model.findings import Finding
from ..orchestrator.validation import record as record_verdict
from . import providers
from .gate import require_validation


@dataclass
class ValidationTask:
    """One finding, the provider it belongs to, and how to check it."""

    finding_id: str
    fingerprint: str
    title: str
    provider: str | None
    probe: providers.Probe | None
    note: str = ""

    @property
    def runnable(self) -> bool:
        return self.probe is not None

    def to_detail(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "provider": self.provider,
            "runnable": self.runnable,
            "command": self.probe.command if self.probe else "",
        }


def plan(repos, project_id: str) -> list[ValidationTask]:
    """Prepare a probe for every secret finding the gate authorises checking.

    The gate is required here: planning is safe, but there is no reason to
    prepare a probe for a project nobody attested they may validate, and asking
    for the gate up front is what keeps the whole surface behind one decision.
    """
    require_validation(repos, project_id)

    secrets = {e.id: e for e in repos.entities.list(project_id, EntityType.SECRET)}
    tasks: list[ValidationTask] = []
    for finding in repos.findings.list(project_id, limit=10_000):
        if not (finding.weakness_key or "").startswith("android.secrets."):
            continue
        entity = _secret_entity(finding, secrets)
        provider = _provider_of(finding, entity)
        probe = providers.probe_for(provider)
        note = ""
        if provider and probe is None:
            listed = providers.PROBES.get(provider)
            note = listed.note if listed else "no automated probe for this provider"
        elif provider is None:
            note = "no recognisable provider; verify this one by hand"
        tasks.append(ValidationTask(
            finding_id=finding.id, fingerprint=finding.fingerprint,
            title=finding.title, provider=provider, probe=probe, note=note))
    return tasks


def _secret_entity(finding: Finding, secrets: dict):
    for entity_id in finding.entity_ids:
        if entity_id in secrets:
            return secrets[entity_id]
    return None


def _provider_of(finding: Finding, entity) -> str | None:
    attributes = entity.attributes if entity is not None else {}
    return providers.classify(
        rule=str(attributes.get("rule") or ""),
        tags=attributes.get("tags") or [],
        weakness_key=finding.weakness_key or "",
        preview=str(attributes.get("preview") or ""))


# ------------------------------------------------------------------ the result

def record_result(repos, audit, finding_id: str, *, live: bool | None,
                  operator: str, note: str = "") -> None:
    """Record what the operator's probe found, as a verdict.

    ``live=True`` confirms the finding; ``live=False`` marks it accepted risk
    with the reason that the credential is revoked; ``live=None`` records only a
    note, for a probe that was inconclusive. The verdict path audits it and
    enforces that a suppressing verdict carries a reason.
    """
    require_validation(repos, _project_of(repos, finding_id))

    if live is True:
        reason = note or "the provider confirms this credential is live"
        record_verdict(repos, audit, finding_id, FindingStatus.CONFIRMED,
                       operator=operator, note=f"validation: {reason}")
    elif live is False:
        reason = note or "the provider reports this credential is revoked"
        record_verdict(repos, audit, finding_id, FindingStatus.ACCEPTED_RISK,
                       operator=operator, note=f"validation: {reason}")
    else:
        # Inconclusive: not a verdict, just a note on the trail so the attempt
        # is on the record.
        from ..audit.attestation import Action
        audit.record(Action.VALIDATION_AUTHORIZED, project_id=None,
                     actor=operator, finding_id=finding_id,
                     result="inconclusive", note=note)


def _project_of(repos, finding_id: str) -> str:
    project_id = repos.findings.project_of(finding_id)
    if not project_id:
        from .gate import ValidationNotAuthorized
        raise ValidationNotAuthorized(f"no finding {finding_id!r}")
    return project_id
