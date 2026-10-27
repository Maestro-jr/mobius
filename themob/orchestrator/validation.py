"""The manual-validation workflow: a tester's verdict on a finding.

The build plan calls this loop the thing that makes themob a console rather than
a report generator. A scanner produces candidates; an assessment is what a person
concluded about them, and that conclusion has to be recorded as carefully as the
scan was.

So a status change is not a database update, it is an auditable event:

* it goes in the **hash-chained audit trail**, next to the authorization
  attestation and every analyzer run. "Who decided this was a false positive,
  and when" is exactly the question a disputed report turns on, and an answer
  that lives only in a mutable column is not an answer.
* it carries a **note**, because "false positive" with no reason is an assertion
  the next reader has to take on trust. Marking something a false positive
  without saying why is refused outright: it is the one verdict that removes a
  finding from the report, and an unexplained removal is indistinguishable from
  an oversight.
* it never touches severity, confidence or the standards mapping. Those are the
  scanner's account of the finding, and a human verdict is a separate fact
  recorded alongside, not an edit to the evidence.

Re-running the pipeline does not undo any of this: the storage merge preserves a
status a tester set by hand, and the scorer leaves status alone.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..audit.attestation import Action, AuditTrail
from ..model.enums import FindingStatus
from ..model.findings import Finding
from ..storage.repositories import Note, Repositories

# Verdicts a person can record. NEW is the scanner's starting state, not a
# conclusion, so it is not something a tester sets.
VERDICTS: tuple[FindingStatus, ...] = (
    FindingStatus.CONFIRMED,
    FindingStatus.FALSE_POSITIVE,
    FindingStatus.ACCEPTED_RISK,
)

# Verdicts that take a finding out of the report. These need a reason.
_NEEDS_REASON = (FindingStatus.FALSE_POSITIVE, FindingStatus.ACCEPTED_RISK)

VERDICT_LABELS: dict[FindingStatus, str] = {
    FindingStatus.NEW: "Unreviewed",
    FindingStatus.CONFIRMED: "Confirmed",
    FindingStatus.FALSE_POSITIVE: "False positive",
    FindingStatus.ACCEPTED_RISK: "Accepted risk",
}


class ValidationError(ValueError):
    """The verdict was refused, and the finding is unchanged."""


@dataclass
class Verdict:
    """What was recorded, so a caller can show it without re-reading."""

    finding: Finding
    status: FindingStatus
    note: Note | None = None


def record(repos: Repositories, audit: AuditTrail, finding_id: str,
           status: FindingStatus, *, operator: str, note: str = "") -> Verdict:
    """Record a tester's verdict on one finding.

    Raises :class:`ValidationError` and changes nothing when the verdict is not
    one a person can set, when the operator is unnamed, or when a verdict that
    suppresses a finding arrives without a reason.
    """
    if status not in VERDICTS:
        raise ValidationError(
            f"{status.value!r} is not a verdict a tester sets; "
            f"choose one of {', '.join(s.value for s in VERDICTS)}")

    operator = (operator or "").strip()
    if not operator:
        raise ValidationError(
            "a verdict needs an operator: an unattributed decision is not an "
            "audit record")

    text = (note or "").strip()
    if status in _NEEDS_REASON and not text:
        raise ValidationError(
            f"{VERDICT_LABELS[status].lower()} needs a reason: this verdict "
            "removes the finding from the report, and an unexplained removal "
            "cannot be told apart from an oversight")

    finding = repos.findings.get(finding_id)
    if finding is None:
        raise ValidationError(f"no finding {finding_id!r}")

    previous = finding.status
    stored_note = repos.findings.add_note(finding_id, text, operator) if text else None
    repos.findings.set_status(finding_id, status)

    audit.record(
        Action.FINDING_STATUS_CHANGED,
        project_id=repos.findings.project_of(finding_id),
        actor=operator,
        finding=finding_id,
        fingerprint=finding.fingerprint,
        weakness=finding.weakness_key,
        was=previous.value,
        now=status.value,
        # The note text is in the trail as well as the notes table: the table is
        # working notes a tester may edit, the trail is what the decision was
        # justified by at the time.
        reason=text or None,
    )

    updated = repos.findings.get(finding_id)
    return Verdict(finding=updated or finding, status=status, note=stored_note)
