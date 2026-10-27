"""The Finding: the normalized unit every analyzer produces.

This is the load-bearing type of the whole system: every tool's raw output is
mapped into this shape, findings are de-duplicated by ``fingerprint`` so that
multiple tools reporting the same issue merge into one record (and raise its
confidence), and the UI renders it directly.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator

from .enums import EvidenceKind, FindingStatus, MASVSCategory, Severity


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Evidence(BaseModel):
    kind: EvidenceKind
    value: str                              # snippet text, HTTP transcript, or a short note
    artifact_path: str | None = None        # path within the project workspace, if the evidence is a file
    redacted: bool = False                  # the value was already masked at the source (a sandbox-redacted secret preview); the UI shows it as-is and never offers to reveal a fuller value that does not exist


class Location(BaseModel):
    file: str | None = None
    clazz: str | None = Field(default=None, alias="class")   # 'class' is a Python keyword
    method: str | None = None
    line: int | None = None
    component: str | None = None

    model_config = {"populate_by_name": True}


class RemediationStep(BaseModel):
    text: str


class Remediation(BaseModel):
    summary: str
    steps: list[RemediationStep] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)


class DataFlowStep(BaseModel):
    kind: str                               # 'source' | 'propagation' | 'sink'
    location: Location
    note: str | None = None


class FindingSource(BaseModel):
    """Which tool reported this finding. Multiple sources on one finding == agreement."""
    tool: str                               # e.g. 'semgrep', 'mobsf', 'gitleaks'
    rule: str | None = None                 # the tool's own rule/check id
    raw_ref: str | None = None              # pointer back into that tool's raw output


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))

    # Dedup/voting key. IMPORTANT: build it from the *normalized* weakness identity
    # (canonical weakness key + location), NOT the tool-specific rule name, so that
    # semgrep and mobsf reporting the same issue at the same place collide and merge.
    fingerprint: str

    # The canonical weakness this finding is an instance of, from
    # knowledge/*-weaknesses.json. The fingerprint is built from it but is a
    # hash, so it cannot be read back; without this column nothing downstream
    # can ask what class of issue a stored finding is. The normalizer groups on
    # it, the scorer maps it to MASVS, and the report names it.
    #
    # Optional only so a finding can be constructed before its key is known.
    # Every adapter themob ships sets it, and a test asserts that.
    weakness_key: str | None = None

    title: str
    description: str = ""
    severity: Severity
    confidence: float = 0.5                 # 0..1; raised when independent tools agree
    status: FindingStatus = FindingStatus.NEW
    requires_manual_validation: bool = True

    # Standards mapping (the advisory layer).
    masvs_category: MASVSCategory | None = None
    masvs_control: str | None = None        # e.g. 'MASVS-STORAGE-1'
    maswe_id: str | None = None             # e.g. 'MASWE-0001'
    mobile_top10: str | None = None         # e.g. 'M1'
    cwe: str | None = None                  # e.g. 'CWE-798'

    # The scorer's output. risk is an ordering from 0 to 100, not a
    # measurement; score_rationale is the one sentence that explains the
    # severity, because a rating a report cannot justify is one nobody trusts.
    # What the reporting adapter rated it, before any context was applied.
    # The scorer raises from this rather than from the stored severity, so
    # running twice cannot compound.
    base_severity: Severity | None = None
    risk: float | None = None
    score_rationale: str | None = None

    location: Location | None = None
    evidence: list[Evidence] = Field(default_factory=list)
    entity_ids: list[str] = Field(default_factory=list)     # links into the attack-surface graph
    data_flow: list[DataFlowStep] = Field(default_factory=list)
    sources: list[FindingSource] = Field(default_factory=list)
    remediation: Remediation | None = None

    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)

    @field_validator("confidence")
    @classmethod
    def _validate_confidence(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")
        return v

    @staticmethod
    def compute_fingerprint(
        weakness_key: str,
        location: "Location | None" = None,
        evidence: str = "",
    ) -> str:
        """Deterministic dedup key.

        ``weakness_key`` must be the CANONICAL weakness identity (e.g. a MASWE id or
        an internal canonical rule id from the normalize mapping). Never a raw
        tool rule name, or findings from different tools for the same issue won't
        merge. ``location`` and ``evidence`` disambiguate distinct instances.
        """
        loc = ""
        if location is not None:
            loc = "|".join(
                "" if x is None else str(x)
                for x in (location.file, location.clazz, location.method, location.component)
            )
        basis = f"{weakness_key}::{loc}::{evidence}".encode()
        return hashlib.sha256(basis).hexdigest()
