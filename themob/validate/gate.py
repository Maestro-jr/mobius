"""The validation gate: testing a live credential is its own authorization.

Finding a hardcoded AWS key is reading a file. Checking whether that key still
works is reaching out to Amazon with it, which touches a third party's systems,
may appear in their logs, and can trip an alert on the very account being
assessed. Those are different acts with different blast radii, so validation
gets its own attestation, exactly as executing an app did in Phase 3.

There is a second, sharper reason it is gated and never automatic: themob does
not hold the secret. The workers redact before anything leaves the container, so
the engine has a digest and a masked preview, never the value. It therefore
*cannot* validate a credential itself, and would not if it could. What it does
is prepare the read-only probe an operator runs with the value they read from
the cited file. The gate records that the operator was authorised to run it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..audit.attestation import (Action, AuditTrail, AuthorizationError,
                                 _utcnow_iso)


class ValidationNotAuthorized(AuthorizationError):
    """Credential validation was attempted without its attestation."""


@dataclass
class ValidationAttestation:
    """The operator's statement that probing these credentials is authorised."""

    operator: str = ""
    engagement_ref: str = ""
    # The explicit acknowledgement. Validating a credential contacts its
    # provider, so this is not a default-on convenience.
    acknowledged: bool = False
    scope_note: str = ""
    ts: str = field(default_factory=_utcnow_iso)

    def validate(self) -> None:
        if not self.operator.strip():
            raise ValidationNotAuthorized(
                "validation requires an operator identity: an unattributed "
                "probe of someone's live credentials is not a record anyone "
                "can stand behind")
        if not self.acknowledged:
            raise ValidationNotAuthorized(
                "validating a credential contacts the provider that owns it and "
                "can trip an alert on the account under assessment. Acknowledge "
                "that the engagement authorises this before running a probe")

    def to_detail(self) -> dict[str, Any]:
        return {
            "operator": self.operator,
            "engagement_ref": self.engagement_ref,
            "acknowledged": self.acknowledged,
            "scope_note": self.scope_note,
            "attested_at": self.ts,
        }


def authorize(attestation: ValidationAttestation, project_id: str,
              audit: AuditTrail) -> ValidationAttestation:
    """Validate the attestation and record it. Raises rather than returning False."""
    attestation.validate()
    audit.record(Action.VALIDATION_AUTHORIZED, project_id=project_id,
                 actor=attestation.operator, **attestation.to_detail())
    return attestation


def require_validation(repos, project_id: str) -> dict[str, Any]:
    """The gate the planner calls before it will prepare a probe. Fails closed."""
    for entry in repos.audit.list(project_id, limit=10_000):
        if entry.action != Action.VALIDATION_AUTHORIZED:
            continue
        detail = entry.detail or {}
        if detail.get("acknowledged") and str(detail.get("operator") or "").strip():
            return detail
    raise ValidationNotAuthorized(
        "this project has no validation attestation. Testing whether a found "
        "credential is live is a separate, opt-in act from finding it")
