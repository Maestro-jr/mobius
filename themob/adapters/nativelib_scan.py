"""Native library hardening: findings from the ELF facts the worker read.

androguard already lists the ``.so`` files as NativeLib nodes, but a name and a
size say nothing about how the code was built. This adapter runs the nativelib
worker, which reads each library's ELF headers in the sandbox, and turns the
absence of an exploit mitigation into a finding on the library it belongs to.

The findings attach to the NativeLib node androguard created, keyed by the same
in-APK path, so the graph gains "this exported component loads this library, and
that library has an executable stack" rather than a parallel list nobody
correlates. The judgement lives here, not in the worker: the worker reports that
a stack is executable, and this decides that an executable stack is a weakness.

Severities stay conservative on purpose. A missing mitigation is not a
vulnerability by itself; it is a weakened defence that makes some other memory
bug easier to exploit. So these confirm and rank rather than accuse, which is
why the stack-canary case is INFO.
"""
from __future__ import annotations

import json
from typing import Any

from ..knowledge import Weakness, get as weakness
from ..model.enums import (EdgeType, EntityType, EvidenceKind, Platform, Stage)
from ..model.findings import (Evidence, Finding, Location, Remediation,
                              RemediationStep)
from ..sandbox.runner import SandboxRunner, SandboxResult, with_limits
from ..storage.workspace import Workspace
from .base import (AnalysisContext, Analyzer, AnalyzerResult, EdgeSpec,
                   EntityRef, RawResult, Target)

_MAX_TEXT = 2048
_MAX_LIBS = 256
_ARTIFACTS = "artifacts"

# One rule per hardening fact. Each maps a boolean the worker reported to the
# canonical weakness it means, with the finding severity coming from the pack.
_EXECUTABLE_STACK = "android.native.executable-stack"
_NO_RELRO = "android.native.no-relro"
_NO_CANARY = "android.native.no-stack-canary"


def _text(value: Any, limit: int = _MAX_TEXT) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text[:limit] or None


def _canonical_path(worker_path: str) -> str:
    """The in-APK path (``lib/<abi>/<name>``), so the key matches androguard's.

    The worker reports a path relative to the decoded tree, which is prefixed by
    whatever directory apktool wrote into. androguard keys the NativeLib node by
    the zip entry, which starts at ``lib/``. Aligning them is what lets a finding
    land on the existing node instead of forking a second one.
    """
    marker = worker_path.replace("\\", "/")
    index = marker.find("lib/")
    return marker[index:] if index >= 0 else marker


class NativeLibScanAnalyzer(Analyzer):
    """Report the exploit mitigations each native library was, or was not, built with."""

    name = "nativelib-scan"
    display = "nativelib · binary hardening"
    stage = Stage.REVERSE_ENGINEERING
    platforms = (Platform.ANDROID,)
    image = "themob/nativelib:1"
    tool = "nativelib"
    timeout = 300.0

    # -- run ------------------------------------------------------------------

    def run(self, target: Target, workspace: Workspace,
            sandbox: SandboxRunner,
            context: AnalysisContext | None = None) -> RawResult:
        scan_dir = workspace.artifacts_root
        if not scan_dir.is_dir() or not any(scan_dir.iterdir()):
            base = RawResult(analyzer=self.name)
            base.error = "nothing to scan: run the unpack stage first"
            return base

        result = sandbox.run(
            self.image, [],
            scan_dir=scan_dir,
            limits=with_limits(sandbox, timeout_s=self.timeout,
                               memory=self.memory),
        )
        return self._to_raw_result(result, workspace)

    def _to_raw_result(self, result: SandboxResult,
                       workspace: Workspace) -> RawResult:
        raw_path: str | None = None
        if result.stdout:
            target_file = workspace.raw_dir(self.name) / "nativelib.json"
            try:
                target_file.write_bytes(result.stdout)
                raw_path = workspace.relative(target_file)
            except OSError:
                raw_path = None

        base = RawResult(analyzer=self.name, raw_path=raw_path,
                         stderr=result.stderr[:_MAX_TEXT],
                         exit_code=result.exit_code,
                         duration_s=result.duration_s)

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
        if result.timed_out or result.truncated:
            base.error = result.error
        elif not payload.get("ok"):
            base.error = _text(payload.get("error")) or "nativelib reported a failure"
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

        libraries = raw.payload.get("libraries")
        if not isinstance(libraries, list):
            return result

        app_ref = EntityRef(EntityType.APP, target.fallback_app_key)

        for entry in libraries[:_MAX_LIBS]:
            if not isinstance(entry, dict):
                continue
            worker_path = _text(entry.get("path"), 1024)
            hardening = entry.get("hardening")
            if not worker_path or not isinstance(hardening, dict):
                continue
            path = _canonical_path(worker_path)

            # Re-assert the NativeLib node so a finding always has one to attach
            # to, even if this stage runs before or without androguard's list.
            entity = self.entity(
                EntityType.NATIVE_LIB, path, target,
                label=path.rsplit("/", 1)[-1],
                arch=_text(entry.get("arch"), 32),
                bits=entry.get("bits"),
                hardening={
                    "nx": bool(hardening.get("nx")),
                    "relro": _text(hardening.get("relro"), 16),
                    "stack_canary": bool(hardening.get("stack_canary")),
                    "fortify": bool(hardening.get("fortify")),
                    "executable_stack": bool(hardening.get("executable_stack")),
                })
            result.entities.append(entity)
            result.edges.append(EdgeSpec(app_ref, EntityRef.of(entity),
                                         EdgeType.EMBEDS))

            for finding in self._findings_for(path, hardening, raw):
                result.findings.append(finding)
        return result

    def _findings_for(self, path: str, hardening: dict[str, Any],
                      raw: RawResult) -> list[Finding]:
        findings: list[Finding] = []
        if hardening.get("executable_stack"):
            findings.append(self._finding(_EXECUTABLE_STACK, path, raw,
                                          "the stack is executable"))
        if hardening.get("relro") == "none":
            findings.append(self._finding(_NO_RELRO, path, raw,
                                          "no RELRO segment"))
        if not hardening.get("stack_canary"):
            findings.append(self._finding(_NO_CANARY, path, raw,
                                          "no __stack_chk_fail symbol found"))
        return findings

    def _finding(self, weakness_key: str, path: str, raw: RawResult,
                 observed: str) -> Finding:
        spec: Weakness = weakness(weakness_key)
        location = Location(file=f"{_ARTIFACTS}/{path}")
        # Keyed on the weakness and the library path, so re-running converges and
        # each library's finding is its own row.
        fingerprint = Finding.compute_fingerprint(weakness_key, location)
        return Finding(
            fingerprint=fingerprint,
            weakness_key=weakness_key,
            title=spec.title,
            description=f"{spec.description}\n\nObserved in {path}: {observed}.",
            severity=spec.severity,
            # A build-flag fact read straight from the ELF header: not a guess,
            # so confident, but still a weakened defence rather than a proven
            # exploit, which the severity already reflects.
            confidence=0.9,
            masvs_category=spec.masvs_category,
            masvs_control=spec.masvs_control,
            maswe_id=spec.maswe_id,
            mobile_top10=spec.mobile_top10,
            cwe=spec.cwe,
            location=location,
            evidence=[Evidence(kind=EvidenceKind.SNIPPET,
                               value=f"{path}: {observed}",
                               artifact_path=raw.raw_path)],
            entity_ids=[f"{EntityType.NATIVE_LIB.value}:{path}"],
            remediation=Remediation(
                summary=spec.remediation,
                steps=[RemediationStep(text=spec.remediation)],
                references=list(spec.references)),
        )
