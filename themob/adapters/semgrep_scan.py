"""semgrep: insecure patterns in the decompiled code.

Stage 4. It scans the *artifacts* directory, jadx's decompiled Java and
apktool's decoded resources, not the package. By this point the tools built for
the format have already extracted everything worth reading.

**The rule carries the weakness key, not this file.** Every rule in
``knowledge/semgrep/`` declares ``metadata.themob-weakness``, and the worker
passes it through. That keeps themob's finding identity out of the rule's name:
a rule can be renamed, replaced or split without changing what the finding
merges with. It is the same reason gitleaks' rule ids are mapped rather than
used directly, except here the mapping lives with the rule instead of in a
table that has to be kept in step with someone else's rule set.

An unknown key is refused rather than passed through. A finding with no
weakness behind it reaches a report with no severity and no standards
reference, and nobody notices until it is in front of a client.

Crypto findings also become **CryptoUsage** nodes. The build plan puts those in
the graph, and a node is what lets a later stage ask which component reaches a
weak cipher rather than just listing the file it appeared in.
"""
from __future__ import annotations

import json
from typing import Any

from ..knowledge import get as weakness, keys as weakness_keys
from ..model.enums import (EdgeType, EntityType, EvidenceKind, Platform,
                           Severity, Stage)
from ..model.findings import (Evidence, Finding, FindingSource, Location,
                              Remediation, RemediationStep)
from ..sandbox.runner import SandboxRunner, SandboxResult, with_limits
from ..storage.workspace import Workspace
from .base import (AnalysisContext, Analyzer, AnalyzerResult, EdgeSpec,
                   EntityRef, RawResult, Target)

_MAX_TEXT = 2048
_MAX_FINDINGS = 2000
# Occurrences listed on one finding. Past this the list stops informing.
_MAX_OCCURRENCES = 50

# Which weaknesses are worth a CryptoUsage node. Not every semgrep finding is:
# a node earns its place when a later stage wants to pivot through it.
_CRYPTO = ("android.crypto.",)

# semgrep's severity vocabulary. Only used when the weakness catalogue has no
# opinion, which it always does today; kept so a rule can still say something.
_SEVERITY = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


def _text(value: Any, limit: int = _MAX_TEXT) -> str | None:
    if value is None or isinstance(value, (dict, list)):
        return None
    text = (value if isinstance(value, str) else str(value)).strip()
    return text[:limit] or None


class SemgrepScanAnalyzer(Analyzer):
    """Match the decompiled code against themob's own rule pack."""

    name = "semgrep-scan"
    display = "semgrep · insecure patterns"
    stage = Stage.SAST
    platforms = (Platform.ANDROID, Platform.IOS)
    image = "themob/semgrep:1"
    tool = "semgrep"
    timeout = 1800.0
    memory = "4g"
    license_note = ("semgrep is LGPL-2.1; invoked as a subprocess in a "
                    "container, with themob's own rules baked into the image "
                    "because the container has no network to fetch any from.")

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
            target_file = workspace.raw_dir(self.name) / "semgrep.json"
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
        if result.timed_out or result.truncated:
            base.error = result.error
        elif not payload.get("ok"):
            base.error = _text(payload.get("error")) or "semgrep reported a failure"
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

        hits = raw.payload.get("findings")
        if not isinstance(hits, list):
            return result

        known = weakness_keys()
        app_ref = EntityRef(EntityType.APP, target.fallback_app_key)

        # One finding per (weakness, file). semgrep reports every line it
        # matched, and eight rows for the same weak cipher in one class is a
        # worse report than one row that says where all eight are.
        grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for hit in hits[:_MAX_FINDINGS]:
            if not isinstance(hit, dict):
                continue
            key = _text(hit.get("weakness"), 128)
            if not key or key not in known:
                # Refused, not passed through: see the module docstring.
                continue
            path = _text(hit.get("file"), 512) or ""
            grouped.setdefault((key, path), []).append(hit)

        for (key, path), occurrences in sorted(grouped.items()):
            result.findings.append(
                self._finding(key, path, occurrences, raw))
            if key.startswith(_CRYPTO):
                node = self._crypto_node(key, path, occurrences, target)
                result.entities.append(node)
                result.edges.append(
                    EdgeSpec(app_ref, EntityRef.of(node), EdgeType.USES))
        return result

    def _finding(self, key: str, path: str, occurrences: list[dict[str, Any]],
                 raw: RawResult) -> Finding:
        spec = weakness(key)
        first = occurrences[0]
        lines = sorted({o.get("line") for o in occurrences
                        if isinstance(o.get("line"), int)})

        location = Location(file=path or None,
                            line=lines[0] if lines else None)
        # The file is the identity, not the line: a line number moves whenever
        # anything above it changes, and a re-run would then duplicate the
        # finding rather than converge on it.
        fingerprint = Finding.compute_fingerprint(key, Location(file=path or None))

        description = spec.description
        message = _text(first.get("message"), 1200)
        if message:
            description = f"{description}\n\n{message}"
        if len(occurrences) > 1:
            shown = ", ".join(str(n) for n in lines[:_MAX_OCCURRENCES])
            description += f"\n\n{len(occurrences)} occurrences, at lines {shown}."

        return Finding(
            fingerprint=fingerprint,
            weakness_key=key,
            title=spec.title,
            description=description,
            severity=spec.severity,
            # A pattern match on decompiled code. The call really is there, but
            # whether it is on a path that matters is the tester's call, and
            # jadx output can differ from the original source.
            confidence=0.8,
            masvs_category=spec.masvs_category,
            masvs_control=spec.masvs_control,
            maswe_id=spec.maswe_id,
            mobile_top10=spec.mobile_top10,
            cwe=spec.cwe,
            location=location,
            evidence=[Evidence(kind=EvidenceKind.SNIPPET,
                               value=_text(o.get("snippet"), 400) or "",
                               artifact_path=raw.raw_path)
                      for o in occurrences[:_MAX_OCCURRENCES]
                      if _text(o.get("snippet"), 400)],
            entity_ids=([f"{EntityType.CRYPTO_USAGE.value}:{path}#{key}"]
                        if key.startswith(_CRYPTO) else []),
            sources=[FindingSource(tool=self.tool,
                                   rule=_text(first.get("rule"), 128),
                                   raw_ref=raw.raw_path)],
            remediation=Remediation(
                summary=spec.remediation,
                steps=[RemediationStep(text=spec.remediation)],
                references=list(spec.references)),
        )

    def _crypto_node(self, key: str, path: str,
                     occurrences: list[dict[str, Any]], target: Target):
        """A CryptoUsage node, so the graph can be asked what reaches it."""
        return self.entity(
            EntityType.CRYPTO_USAGE, f"{path}#{key}", target,
            label=f"{weakness(key).title} in {path.rsplit('/', 1)[-1]}"
                  if path else weakness(key).title,
            weakness=key,
            file=path or None,
            occurrences=len(occurrences),
            lines=sorted({o.get("line") for o in occurrences
                          if isinstance(o.get("line"), int)})[:_MAX_OCCURRENCES],
            rule=_text(occurrences[0].get("rule"), 128),
        )
