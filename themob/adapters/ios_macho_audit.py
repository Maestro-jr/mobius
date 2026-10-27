"""iOS Mach-O hardening: findings from the build-time protections lief read.

The ios-unpack worker already reads each Mach-O's exploit mitigations (PIE,
stack canary, ARC, NX, code signature, FairPlay encryption), and the ios-unpack
adapter stores them as the ``hardening`` dict on the NATIVE_LIB node. This
adapter is the judgement half, the iOS counterpart of nativelib-scan: it reads
that dict off the graph and turns an absent mitigation into a finding on the
Mach-O it belongs to.

**It runs no container.** Like the config auditor, it judges the graph the
unpack stage built rather than re-opening the sample, so it carries no image and
sets ``wants_graph``. The judgement lives here, not in the worker: the worker
reports that a binary is not PIE, and this decides that a non-PIE binary is a
weakness.

Severities stay conservative, matching the native (.so) pack: a missing
mitigation is not a vulnerability by itself, it is a weakened defence that makes
an unrelated memory bug easier to exploit, so these confirm and rank rather than
accuse. A flag the worker could not determine (``None``) yields no finding:
themob never claims a weakness it did not measure.

The worker's JSON was already validated into the graph by ios-unpack, so the
attributes read here are trusted; the persisted payload this adapter writes is
re-read defensively in :meth:`normalize` all the same.
"""
from __future__ import annotations

import json
from typing import Any, Iterator

from ..knowledge import get as weakness
from ..model.entities import Entity
from ..model.enums import EntityType, EvidenceKind, Platform, Stage
from ..model.findings import (Evidence, Finding, FindingSource, Location,
                              Remediation, RemediationStep)
from ..sandbox.runner import SandboxRunner
from ..storage.workspace import Workspace
from .base import (AnalysisContext, Analyzer, AnalyzerResult, RawResult, Target)

_MAX_TEXT = 2048
_MAX_MACHOS = 64
_MAX_CHECKS = 512

# One rule per hardening flag: the flag the worker reports, the weakness its
# absence means, and the evidence line. A mitigation is "absent" only when the
# flag is exactly False; a flag that is None (the parser could not tell) is left
# alone, so an undetermined protection is never reported as a missing one.
_RULES: tuple[tuple[str, str, str], ...] = (
    ("pie", "ios.macho.no-pie", "the MH_PIE flag is not set (no ASLR)"),
    ("nx", "ios.macho.no-nx", "executable data pages are allowed (no W^X)"),
    ("arc", "ios.macho.no-arc", "no ARC runtime calls are bound"),
    ("stack_canary", "ios.macho.no-stack-canary",
     "no stack-protector symbols are bound"),
    ("signed", "ios.macho.no-code-signature",
     "no LC_CODE_SIGNATURE load command"),
    ("encrypted", "ios.macho.not-encrypted",
     "the LC_ENCRYPTION_INFO cryptid is 0 (no FairPlay)"),
)


def _clip(value: Any, limit: int = _MAX_TEXT) -> str:
    if value is None:
        return ""
    return str(value).strip()[:limit]


class IosMachoAuditAnalyzer(Analyzer):
    """Turn the Mach-O hardening flags on the NATIVE_LIB node into findings."""

    name = "ios-macho-audit"
    display = "iOS · Mach-O hardening"
    stage = Stage.REVERSE_ENGINEERING
    platforms = (Platform.IOS,)
    image = ""                      # reads the graph, not the sample
    tool = "ios-macho-audit"
    wants_graph = True
    license_note = ("themob's own auditor. It reads the hardening flags the iOS "
                    "unpack stage put on the graph; no third-party tool and no "
                    "container.")

    # -- run ------------------------------------------------------------------

    def run(self, target: Target, workspace: Workspace,
            sandbox: SandboxRunner | None = None,
            context: AnalysisContext | None = None) -> RawResult:
        base = RawResult(analyzer=self.name)

        if context is None or context.is_empty:
            base.error = ("nothing to audit: run the iOS unpack stage first so "
                          "the Mach-O is in the graph")
            return base

        machos = context.of_type(EntityType.NATIVE_LIB)
        checks = list(self._audit(machos))[:_MAX_CHECKS]
        payload: dict[str, Any] = {
            "ok": True,
            "tool": self.tool,
            "checks": checks,
            "counts": {"machos": len(machos), "findings": len(checks)},
        }

        # Persisted like any tool's output, so a finding can cite it.
        try:
            path = workspace.raw_dir(self.name) / "ios-macho-audit.json"
            path.write_text(json.dumps(payload, indent=2, sort_keys=True),
                            encoding="utf-8")
            base.raw_path = workspace.relative(path)
        except OSError:
            base.raw_path = None

        base.payload = payload
        base.ok = True
        return base

    def _audit(self, machos: list[Entity]) -> Iterator[dict[str, Any]]:
        for macho in machos[:_MAX_MACHOS]:
            hardening = macho.attributes.get("hardening")
            if not isinstance(hardening, dict):
                continue
            for flag, key, evidence in _RULES:
                if hardening.get(flag) is False:
                    yield self._check(key, macho, evidence=evidence)

    @staticmethod
    def _check(weakness_key: str, entity: Entity, *, evidence: str) -> dict[str, Any]:
        """One judgement, in the shape ``normalize`` reads back.

        ``get`` raises on an unknown key, which is deliberate: a typo in a rule
        would otherwise reach a report as an unmapped finding with no severity.
        """
        weakness(weakness_key)              # fail fast on an unknown key
        return {
            "weakness": weakness_key,
            "entity_key": entity.key,
            "entity_id": entity.id,
            "entity_type": entity.type.value,
            "file": entity.key,
            "evidence": _clip(evidence),
        }

    # -- normalize ------------------------------------------------------------

    def normalize(self, raw: RawResult, target: Target) -> AnalyzerResult:
        result = AnalyzerResult()
        if not raw.ok or not raw.payload:
            return result
        if raw.raw_path:
            result.artifacts.append(raw.raw_path)

        checks = raw.payload.get("checks")
        if not isinstance(checks, list):
            return result

        for check in checks[:_MAX_CHECKS]:
            if not isinstance(check, dict):
                continue
            finding = self._finding(check, raw)
            if finding is not None:
                result.findings.append(finding)
        return result

    def _finding(self, check: dict[str, Any], raw: RawResult) -> Finding | None:
        key = check.get("weakness")
        if not isinstance(key, str):
            return None
        try:
            spec = weakness(key)
        except KeyError:
            # Unreachable in practice: _check validates on the way in. A
            # malformed persisted document must not take the run down.
            return None

        location = Location(file=_clip(check.get("file"), 512) or None)
        evidence_text = _clip(check.get("evidence"))

        # The fingerprint is the canonical weakness plus where (the Mach-O path),
        # so re-running converges and each binary's finding is its own row.
        fingerprint = Finding.compute_fingerprint(key, location)

        description = spec.description
        if evidence_text:
            description = f"{description}\n\nObserved: {evidence_text}."

        entity_id = check.get("entity_id")
        return Finding(
            fingerprint=fingerprint,
            weakness_key=key,
            title=spec.title,
            description=description,
            severity=spec.severity,
            # A build-flag fact read straight from the Mach-O headers: not a
            # guess, so confident, but a weakened defence rather than a proven
            # exploit, which the severity already reflects.
            confidence=0.9,
            masvs_category=spec.masvs_category,
            masvs_control=spec.masvs_control,
            maswe_id=spec.maswe_id,
            mobile_top10=spec.mobile_top10,
            cwe=spec.cwe,
            location=location,
            evidence=[Evidence(kind=EvidenceKind.SNIPPET, value=evidence_text,
                               artifact_path=raw.raw_path)] if evidence_text else [],
            entity_ids=[entity_id] if isinstance(entity_id, str) and entity_id else [],
            sources=[FindingSource(tool=self.tool, rule=key,
                                   raw_ref=raw.raw_path)],
            remediation=Remediation(
                summary=spec.remediation,
                steps=[RemediationStep(text=spec.remediation)],
                references=list(spec.references)),
        )
