"""Turning what we watched into findings on the same graph as everything else.

A dynamic observation is not a special kind of result. The whole design of
themob is that a finding is a finding: keyed by a canonical weakness, attached
to a graph entity, carrying a source that says who reported it. A runtime
finding built any other way would sit outside the correlator, the scorer and the
report, which is exactly where it must not sit.

So this builds ordinary :class:`Finding` objects from two runtime sources,
Frida's observations and mitmproxy's flows, with one thing that makes them worth
the risk of Phase 3:

**The source method is ``runtime``, and it shares a blind spot with nobody.**
Every static reporter reads the code or the manifest. This one watched the app
run. When a runtime finding lands on the same fingerprint as a static one, the
voting layer sees two genuinely independent methods agreeing, which is the
strongest corroboration themob can express: "semgrep saw the call site and we
watched it fire" is a harder claim than either half.

**A runtime finding confirms; it rarely accuses alone.** Watching an app use
AES-CBC is a fact about behaviour, not automatically a vulnerability, so these
carry the observation and let it either corroborate a static finding through the
fingerprint or stand as an INFO-level record of what the app did. The judgement
stays with the tester, which is the manual-validation workflow doing its job.

Nothing here executes anything. It reads the evidence a run already produced,
the same way the static adapters read a container's output, so it is testable in
full without a device.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Sequence

from ..knowledge import get as weakness
from ..model.enums import EvidenceKind
from ..model.findings import (Evidence, Finding, FindingSource,
                              Remediation, RemediationStep)
from .capture import CaptureResult, Flow

logger = logging.getLogger(__name__)

# Weak primitives worth flagging when the app is watched using them. Keyed to
# the canonical weaknesses that already exist, so a runtime observation of weak
# crypto merges with semgrep's static one rather than starting a parallel finding.
_WEAK_CIPHERS = {
    "des": "android.crypto.weak-cipher-mode",
    "desede": "android.crypto.weak-cipher-mode",
    "rc4": "android.crypto.weak-cipher-mode",
    "arc4": "android.crypto.weak-cipher-mode",
    "blowfish": "android.crypto.weak-cipher-mode",
    # ECB leaks structure regardless of the cipher.
    "aes/ecb": "android.crypto.weak-cipher-mode",
    "des/ecb": "android.crypto.weak-cipher-mode",
}
_WEAK_DIGESTS = {
    "md5": "android.crypto.weak-hash",
    "sha-1": "android.crypto.weak-hash",
    "sha1": "android.crypto.weak-hash",
}

_FRIDA = "frida"
_MITMPROXY = "mitmproxy"


@dataclass
class Observation:
    """One thing Frida watched, before it is judged a finding or not."""

    kind: str                             # cipher / digest / secret-key / pin-check
    detail: dict[str, Any]


def from_frida(observations: Sequence[Observation], *,
               app_entity_id: str = "",
               raw_ref: str = "") -> list[Finding]:
    """Findings from what an agent watched. Weak primitives corroborate; the
    rest is recorded as behaviour for the tester to weigh.
    """
    findings: list[Finding] = []
    seen: set[str] = set()

    for obs in observations:
        key, title_extra, evidence = _classify(obs)
        if key is None:
            continue
        # One finding per weakness-and-value: an app that encrypts a hundred
        # times with DES has one weak-cipher finding, not a hundred.
        dedup = f"{key}:{evidence}"
        if dedup in seen:
            continue
        seen.add(dedup)
        findings.append(_finding(
            key, evidence, tool=_FRIDA, rule=obs.kind, raw_ref=raw_ref,
            entity_id=app_entity_id, title_extra=title_extra))
    return findings


def from_capture(result: CaptureResult, *,
                 endpoint_ids: dict[str, str] | None = None,
                 raw_ref: str = "") -> list[Finding]:
    """Findings from intercepted traffic.

    The one themob can make with confidence is cleartext: a plain-HTTP request
    is not a suspicion, it was observed on the wire. It merges with the static
    endpoint extractor's cleartext finding through the shared weakness key.
    """
    endpoint_ids = endpoint_ids or {}
    findings: list[Finding] = []
    seen: set[str] = set()

    for flow in result.flows:
        if (flow.scheme or "").lower() != "http":
            continue
        host = flow.host
        if host in seen:
            continue
        seen.add(host)
        key = "android.network.cleartext-endpoint"
        entity_id = endpoint_ids.get(host, "")
        findings.append(_finding(
            key, f"http://{host}{flow.path}", tool=_MITMPROXY,
            rule="cleartext-observed", raw_ref=raw_ref, entity_id=entity_id,
            title_extra="observed in traffic",
            evidence_kind=EvidenceKind.HTTP))
    return findings


def _classify(obs: Observation):
    """Map a Frida observation to a canonical weakness, or None to ignore it."""
    detail = obs.detail or {}
    if obs.kind == "cipher":
        transformation = str(detail.get("transformation") or "").lower()
        head = transformation.split("/")[0]
        mode2 = "/".join(transformation.split("/")[:2])
        key = _WEAK_CIPHERS.get(mode2) or _WEAK_CIPHERS.get(head)
        if key:
            return key, "observed in use", transformation
        return None, "", ""
    if obs.kind == "digest":
        algo = str(detail.get("algorithm") or "").lower()
        key = _WEAK_DIGESTS.get(algo)
        if key:
            return key, "observed in use", algo
        return None, "", ""
    # secret-key, pin-check and the rest are behaviour worth a tester's eye but
    # not a weakness on their own; they travel as evidence on other findings or
    # in the activity log, not as accusations here.
    return None, "", ""


def _finding(key: str, evidence: str, *, tool: str, rule: str, raw_ref: str,
             entity_id: str, title_extra: str,
             evidence_kind: EvidenceKind = EvidenceKind.SNIPPET) -> Finding:
    """One runtime finding, indistinguishable from a static one but for its source.

    The fingerprint is the canonical weakness plus the observed value, the same
    construction the static adapters use, so a runtime finding and the static
    finding for the same weakness at the same place collide and merge.
    """
    spec = weakness(key)
    fingerprint = Finding.compute_fingerprint(key, None, evidence)
    return Finding(
        fingerprint=fingerprint,
        weakness_key=key,
        title=f"{spec.title} ({title_extra})",
        description=spec.description
        + "\n\nObserved at runtime rather than inferred from the code.",
        # The reporting severity is the weakness default. The scorer decides the
        # rest, and the runtime source is what lets voting raise confidence when
        # a static tool agrees.
        severity=spec.severity,
        confidence=0.9,
        masvs_category=spec.masvs_category,
        masvs_control=spec.masvs_control,
        maswe_id=spec.maswe_id,
        mobile_top10=spec.mobile_top10,
        cwe=spec.cwe,
        evidence=[Evidence(kind=evidence_kind, value=evidence[:1000],
                           artifact_path=raw_ref or None)],
        entity_ids=[entity_id] if entity_id else [],
        sources=[FindingSource(tool=tool, rule=rule, raw_ref=raw_ref or None)],
        remediation=Remediation(
            summary=spec.remediation,
            steps=[RemediationStep(text=spec.remediation)],
            references=list(spec.references)),
    )


def parse_frida_events(lines: Sequence[str]) -> list[Observation]:
    """Read the ``themob-observe`` lines an agent emitted.

    The agent prints one tagged JSON object per event. Everything else on the
    stream is Frida's own chatter and is skipped, and a malformed line is
    skipped rather than trusted: it came off a hostile app's process.
    """
    import json

    out: list[Observation] = []
    for raw in lines:
        raw = raw.strip()
        marker = "themob-observe "
        idx = raw.find(marker)
        if idx < 0:
            continue
        try:
            payload = json.loads(raw[idx + len(marker):])
        except ValueError:
            continue
        if not isinstance(payload, dict):
            continue
        kind = payload.pop("kind", "")
        if kind in ("ready", "error", ""):
            continue
        out.append(Observation(kind=str(kind), detail=payload))
    return out
