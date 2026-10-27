"""gitleaks: secret-shaped strings in what the earlier stages produced.

Stage 3. It scans the *artifacts* directory, apktool's decoded resources and
assets plus jadx's decompiled Java, not the APK. The package itself is never
mounted here: by this point the interesting text has already been extracted by
tools built for it, and handing a scanner the original archive as well would
widen its reach for nothing.

Unlike the config auditor, this adapter emits both entities and findings. A
secret is a node in the attack-surface graph because later stages pivot on it:
the endpoint extractor wants to know which host a leaked key belongs to, and
the correlator wants "this exported Provider reaches this secret".

**The secret value never enters themob.** The worker returns a redacted match
and a SHA-256, and this adapter stores exactly that. A console that copies live
credentials into its own database and then into its report has created a second
place to leak them from. The tester reads the real value from the cited file.

Mapping gitleaks' rule ids onto canonical weakness keys happens here for now.
When the normalizer lands (1.8) this table moves there, because semgrep's secret
rules and MobSF's will need the same treatment and the mapping has to be one
shared thing rather than one per adapter.
"""
from __future__ import annotations

import json
import re
from typing import Any

from ..knowledge import Weakness, get as weakness
from ..model.enums import (EdgeType, EntityType, EvidenceKind, Platform,
                           Stage)
from ..model.findings import (Evidence, Finding, FindingSource, Location,
                              Remediation, RemediationStep)
from ..sandbox.runner import SandboxRunner, SandboxResult, with_limits
from ..storage.workspace import Workspace
from .base import (ENV_CAPTURE_SECRETS, AnalysisContext, Analyzer,
                   AnalyzerResult, EdgeSpec, EntityRef, RawResult, Target,
                   capture_secret_values)

_MAX_TEXT = 2048
_MAX_FINDINGS = 2000
# Occurrences listed on one finding. Past this the list stops informing.
_MAX_EVIDENCE = 50

# gitleaks rule id -> canonical weakness key. Matched as substrings because the
# rule set names providers in many shapes ("aws-access-token",
# "aws-secret-key"), and a provider is what decides the severity.
# Deliberately narrow. A Google Maps or Firebase key is routinely shipped in an
# app on purpose and is usually origin-restricted, so calling it critical trains
# the reader to ignore the row. Those fall through to the service tier, whose
# wording says each one needs checking rather than assuming.
_CLOUD = ("aws", "gcp", "azure", "alibaba", "digitalocean", "heroku")
_PRIVATE_KEY = ("private-key", "privatekey", "rsa-key", "ssh-key", "pgp",
                "-----begin")
_GENERIC = ("generic-api-key", "generic", "high-entropy", "entropy")

_KEY_PRIVATE = "android.secrets.private-key"
_KEY_CLOUD = "android.secrets.cloud-credential"
_KEY_SERVICE = "android.secrets.service-api-key"
_KEY_GENERIC = "android.secrets.high-entropy-string"

# A workspace-relative path from the worker. It reports paths relative to its
# /scan mount, which is this project's artifacts/ directory.
_ARTIFACTS = "artifacts"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _text(value: Any, limit: int = _MAX_TEXT) -> str | None:
    if value is None or isinstance(value, (dict, list)):
        return None
    text = (value if isinstance(value, str) else str(value)).strip()
    return text[:limit] or None


def _number(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def classify(rule: str, tags: list[str] | None = None) -> str:
    """Which canonical weakness a gitleaks rule id represents.

    Order matters. A private key is checked first because "gcp-private-key"
    contains a provider name too, and the key material is the worse half of
    that finding.
    """
    haystack = " ".join([rule or "", " ".join(tags or [])]).lower()
    if any(token in haystack for token in _PRIVATE_KEY):
        return _KEY_PRIVATE
    if any(token in haystack for token in _CLOUD):
        return _KEY_CLOUD
    # Generic before service: "generic-api-key" contains "api-key", and a
    # generic pattern hit is a weaker claim than a named provider's.
    if any(token in haystack for token in _GENERIC):
        return _KEY_GENERIC
    return _KEY_SERVICE


class GitleaksScanAnalyzer(Analyzer):
    """Scan the decoded tree for secrets that shipped inside the package."""

    name = "gitleaks-scan"
    display = "gitleaks · secret scan"
    stage = Stage.SECRETS
    platforms = (Platform.ANDROID, Platform.IOS)
    image = "themob/gitleaks:1"
    tool = "gitleaks"
    timeout = 900.0
    license_note = ("gitleaks is MIT; invoked as a subprocess in a container so "
                    "the decoded tree never reaches the engine process.")

    # -- run ------------------------------------------------------------------

    def run(self, target: Target, workspace: Workspace,
            sandbox: SandboxRunner,
            context: AnalysisContext | None = None) -> RawResult:
        base = RawResult(analyzer=self.name)

        scan_dir = workspace.artifacts_root
        if not scan_dir.is_dir() or not any(scan_dir.iterdir()):
            base.error = ("nothing to scan: run the unpack and reverse "
                          "engineering stages first")
            return base

        # Forwarded into the container, where the redaction decision is made;
        # off by default, so only a redacted match leaves the sandbox.
        env = {ENV_CAPTURE_SECRETS: "1"} if capture_secret_values() else None
        result = sandbox.run(
            self.image, [],
            scan_dir=scan_dir,
            limits=with_limits(sandbox, timeout_s=self.timeout,
                               memory=self.memory),
            env=env,
        )
        return self._to_raw_result(result, workspace)

    def _to_raw_result(self, result: SandboxResult,
                       workspace: Workspace) -> RawResult:
        raw_path: str | None = None
        if result.stdout:
            target_file = workspace.raw_dir(self.name) / "gitleaks.json"
            try:
                target_file.write_bytes(result.stdout)
                raw_path = workspace.relative(target_file)
            except OSError:
                raw_path = None

        base = RawResult(
            analyzer=self.name,
            raw_path=raw_path,
            stderr=result.stderr[:_MAX_TEXT],
            exit_code=result.exit_code,
            duration_s=result.duration_s,
        )

        if not result.stdout:
            base.error = result.error or "the worker produced no output"
            return base
        try:
            payload = json.loads(result.stdout.decode("utf-8", "replace"))
        except (ValueError, UnicodeDecodeError) as exc:
            base.error = f"worker output was not valid JSON: {exc}"
            return base
        if not isinstance(payload, dict):
            base.error = "worker output was not a JSON object"
            return base

        base.payload = payload
        # A sandbox-level failure is the only thing that outranks the worker's
        # own diagnosis, same precedence the other adapters use.
        if result.timed_out or result.truncated:
            base.error = result.error
        elif not payload.get("ok"):
            base.error = _text(payload.get("error")) or "gitleaks reported a failure"
        elif result.error and not result.ok:
            base.error = result.error
        else:
            base.ok = True
        return base

    # -- normalize ------------------------------------------------------------

    def normalize(self, raw: RawResult, target: Target) -> AnalyzerResult:
        result = AnalyzerResult()
        if not raw.ok or not raw.payload:
            return result
        if raw.raw_path:
            result.artifacts.append(raw.raw_path)

        entries = raw.payload.get("findings")
        if not isinstance(entries, list):
            return result

        app_ref = EntityRef(EntityType.APP, target.fallback_app_key)

        # What was looked at, and whether the list was cut. "2000 secrets" and
        # "at least 2000, and the worker stopped counting" are materially
        # different statements to put in front of a tester, and the second one
        # means the next run needs a wider cap rather than a tick.
        scanned = raw.payload.get("scanned")
        scanned = scanned if isinstance(scanned, dict) else {}
        result.entities.append(self.entity(
            EntityType.APP, target.fallback_app_key, target,
            secret_scan={
                "tool": self.tool,
                "tool_version": _text(raw.payload.get("tool_version"), 64),
                "files": _number(scanned.get("files")),
                "bytes": _number(scanned.get("bytes")),
                "hits": len(entries),
                "truncated": bool(raw.payload.get("truncated")),
            }))

        # Group by the secret's digest before emitting anything. One leaked
        # credential is one finding with several occurrences, not several
        # findings: what a tester does about it is rotate the key once, and a
        # report that lists it eight times is a worse report. It is also what
        # lets apkleaks reporting the same digest merge with this rather than
        # double-report, because the fingerprint no longer includes the file.
        grouped: dict[str, list[dict[str, Any]]] = {}
        order: list[str] = []
        for entry in entries[:_MAX_FINDINGS]:
            if not isinstance(entry, dict):
                continue
            digest = _text(entry.get("secret_sha256"), 64)
            if not digest or not _SHA256.match(digest):
                # Without the digest there is no stable identity for this
                # secret, and a finding that cannot dedupe is worse than none.
                continue
            if digest not in grouped:
                grouped[digest] = []
                order.append(digest)
            grouped[digest].append(entry)

        for digest in order:
            hits = grouped[digest]
            first = hits[0]
            rule = _text(first.get("rule"), 128) or "unknown"
            tags = [t for t in (first.get("tags") or []) if isinstance(t, str)]
            weakness_key = classify(rule, tags)
            path = _text(first.get("file"), 1024) or ""
            line = _number(first.get("line"))

            entity = self.entity(
                EntityType.SECRET, f"sha256:{digest}", target,
                label=f"{rule}:{digest[:8]}",
                kind=weakness_key.rsplit(".", 1)[-1],
                rule=rule,
                detector=self.tool,
                # The redacted match, never the value.
                preview=_text(first.get("match"), 200),
                entropy=first.get("entropy")
                if isinstance(first.get("entropy"), (int, float)) else None,
                first_seen_in=f"{_ARTIFACTS}/{path}" if path else None,
                line=line,
                occurrences=len(hits),
                tags=tags[:16],
            )
            result.entities.append(entity)
            result.edges.append(EdgeSpec(app_ref, EntityRef.of(entity),
                                         EdgeType.USES))
            result.findings.append(
                self._finding(weakness_key, hits, rule, digest, raw))
        return result

    def _finding(self, weakness_key: str, hits: list[dict[str, Any]], rule: str,
                 digest: str, raw: RawResult) -> Finding:
        spec: Weakness = weakness(weakness_key)
        first = hits[0]
        path = _text(first.get("file"), 1024) or ""
        location = Location(file=f"{_ARTIFACTS}/{path}" if path else None,
                            line=_number(first.get("line")))

        # Keyed on the canonical weakness plus the secret's digest, and
        # deliberately NOT on the file. The same key pasted into three files is
        # one leaked credential: rotating it fixes all three. Leaving the file
        # out is also what lets a second tool reporting the same digest merge
        # into this finding and raise its confidence instead of repeating it.
        fingerprint = Finding.compute_fingerprint(weakness_key, None, digest)

        evidence = []
        for hit in hits[:_MAX_EVIDENCE]:
            where = _text(hit.get("file"), 1024) or ""
            line = _number(hit.get("line"))
            # The full match only when the operator opted in; otherwise None and
            # the redacted match is all that left the sandbox. Record which, so
            # the UI gates a real value but never fakes a reveal of a redacted one.
            full = _text(hit.get("value"), 400)
            preview = _text(hit.get("match"), 200) or ""
            shown, redacted = (full, False) if full else (preview, True)
            label = f"{_ARTIFACTS}/{where}" if where else "(unknown file)"
            if line:
                label = f"{label}:{line}"
            evidence.append(Evidence(
                kind=EvidenceKind.SNIPPET,
                value=f"{label}  {rule}: {shown}".strip(),
                redacted=redacted,
                artifact_path=raw.raw_path))

        detail = _text(first.get("description"), 512) or ""
        description = spec.description
        if detail:
            description = f"{description}\n\nDetector: {detail}"
        if len(hits) > 1:
            description = (f"{description}\n\nFound in {len(hits)} places; "
                           "rotating the credential fixes all of them.")

        return Finding(
            fingerprint=fingerprint,
            weakness_key=weakness_key,
            title=spec.title,
            description=description,
            severity=spec.severity,
            # A pattern match is evidence, not proof. A generic hit is weaker
            # still, which is why it is a different weakness with its own
            # default severity rather than the same one at lower confidence.
            confidence=0.6 if weakness_key == _KEY_GENERIC else 0.8,
            masvs_category=spec.masvs_category,
            masvs_control=spec.masvs_control,
            maswe_id=spec.maswe_id,
            mobile_top10=spec.mobile_top10,
            cwe=spec.cwe,
            location=location,
            # The pipeline resolves a "type:key" placeholder to the real row id
            # once the entity has been upserted, which is the only way an
            # adapter can link to a node it is creating in the same batch.
            entity_ids=[f"{EntityType.SECRET.value}:sha256:{digest}"],
            evidence=evidence,
            sources=[FindingSource(tool=self.tool, rule=rule,
                                   raw_ref=raw.raw_path)],
            remediation=Remediation(
                summary=spec.remediation,
                steps=[RemediationStep(text=spec.remediation)],
                references=list(spec.references)),
        )
