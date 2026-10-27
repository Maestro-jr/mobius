"""apkleaks: the Android-specific half of the secrets stage.

Stage 3, alongside gitleaks, and deliberately not a duplicate of it. gitleaks
matches provider credential formats well but will not match a secret sitting
between XML tags, and ``res/values/strings.xml`` is exactly where an Android app
keeps an API key. apkleaks greps the decoded resources too, so the pair covers
what neither covers alone.

This adapter hands the worker the APK, unlike gitleaks which is given only the
decoded tree. apkleaks takes an APK and nothing else, and it runs its own jadx
pass inside the container. That is a second decompile, and it is the honest
price of invoking the tool rather than forking its rule set.

**Convergence with gitleaks is the point.** Secret nodes are keyed on
``sha256:<digest>`` and findings are fingerprinted on the canonical weakness
plus that digest, exactly as the gitleaks adapter does. When both tools see the
same credential the node is one node and the finding is one finding carrying
both tools in ``sources``, which is the agreement signal the scorer reads.

Non-credential matches, apkleaks' LinkFinder URLs and bucket names, are left
alone here. They are the endpoint stage's material (1.7), and it reads them from
the raw output this adapter persists rather than making the tool run twice.
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
from .gitleaks_scan import classify

_MAX_TEXT = 2048
_MAX_RULES = 200
_MAX_PER_RULE = 500
_MAX_EVIDENCE = 50

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _text(value: Any, limit: int = _MAX_TEXT) -> str | None:
    if value is None or isinstance(value, (dict, list)):
        return None
    text = (value if isinstance(value, str) else str(value)).strip()
    return text[:limit] or None


def canonical_rule(rule: str) -> str:
    """apkleaks names rules with underscores; the shared mapping uses hyphens.

    Normalising here rather than adding a second table is the whole point: one
    mapping means gitleaks' ``aws-access-token`` and apkleaks'
    ``Amazon_AWS_Access_Key_ID`` land on the same canonical weakness, and the
    two findings merge instead of stacking.
    """
    return (rule or "").replace("_", "-").lower()


class ApkleaksScanAnalyzer(Analyzer):
    """Scan the package with apkleaks' Android-specific pattern set."""

    name = "apkleaks-scan"
    display = "apkleaks · android secret scan"
    stage = Stage.SECRETS
    platforms = (Platform.ANDROID,)
    suffixes = (".apk", ".xapk", ".apkm")
    image = "themob/apkleaks:1"
    tool = "apkleaks"
    # It runs a full jadx decompile of its own before it greps anything.
    timeout = 1500.0
    memory = "4g"
    license_note = ("apkleaks is MIT; invoked as a subprocess in a container, "
                    "never imported, so a hostile package never reaches the "
                    "engine process.")

    # -- run ------------------------------------------------------------------

    def run(self, target: Target, workspace: Workspace,
            sandbox: SandboxRunner,
            context: AnalysisContext | None = None) -> RawResult:
        # The capture opt-in is forwarded into the container, where the
        # redaction decision is made; off by default, the worker redacts.
        env = {ENV_CAPTURE_SECRETS: "1"} if capture_secret_values() else None
        result = sandbox.run(
            self.image, [],
            sample=target.sample_path,
            limits=with_limits(sandbox, timeout_s=self.timeout,
                               memory=self.memory),
            env=env,
        )
        return self._to_raw_result(result, workspace)

    def _to_raw_result(self, result: SandboxResult,
                       workspace: Workspace) -> RawResult:
        raw_path: str | None = None
        if result.stdout:
            target_file = workspace.raw_dir(self.name) / "apkleaks.json"
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
        # Same precedence the other adapters use: only a sandbox-level failure
        # outranks the worker's own diagnosis.
        if result.timed_out or result.truncated:
            base.error = result.error
        elif not payload.get("ok"):
            base.error = _text(payload.get("error")) or "apkleaks reported a failure"
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

        rules = raw.payload.get("results")
        if not isinstance(rules, list):
            return result

        app_ref = EntityRef(EntityType.APP, target.fallback_app_key)

        # Group by digest across every rule. Two apkleaks rules routinely match
        # the same string (Amazon_AWS_Access_Key_ID and AWS_API_Key both fire on
        # one key), and that is one credential, not two.
        grouped: dict[str, list[tuple[str, dict[str, Any]]]] = {}
        order: list[str] = []
        links = 0

        for entry in rules[:_MAX_RULES]:
            if not isinstance(entry, dict):
                continue
            rule = _text(entry.get("rule"), 128) or "unknown"
            matches = entry.get("matches")
            if not isinstance(matches, list):
                continue
            if not entry.get("credential"):
                # URLs and bucket names. Stage 7 reads these from raw_path.
                links += len(matches)
                continue

            for match in matches[:_MAX_PER_RULE]:
                if not isinstance(match, dict):
                    continue
                digest = _text(match.get("sha256"), 64)
                if not digest or not _SHA256.match(digest):
                    continue
                if digest not in grouped:
                    grouped[digest] = []
                    order.append(digest)
                grouped[digest].append((rule, match))

        result.entities.append(self.entity(
            EntityType.APP, target.fallback_app_key, target,
            apkleaks_scan={
                "tool": self.tool,
                "tool_version": _text(raw.payload.get("tool_version"), 64),
                "secrets": len(order),
                "links": links,
                "truncated": bool(raw.payload.get("truncated")),
            }))

        for digest in order:
            hits = grouped[digest]
            rule, first = hits[0]
            weakness_key = classify(canonical_rule(rule))
            rule_names = sorted({name for name, _ in hits})

            entity = self.entity(
                EntityType.SECRET, f"sha256:{digest}", target,
                label=f"{rule}:{digest[:8]}",
                kind=weakness_key.rsplit(".", 1)[-1],
                rule=rule,
                detector=self.tool,
                # Redacted by the worker. The value never travels.
                preview=_text(first.get("preview"), 200),
                matched_rules=rule_names[:16],
            )
            result.entities.append(entity)
            result.edges.append(EdgeSpec(app_ref, EntityRef.of(entity),
                                         EdgeType.USES))
            result.findings.append(
                self._finding(weakness_key, hits, rule_names, digest, raw))
        return result

    def _finding(self, weakness_key: str, hits: list[tuple[str, dict[str, Any]]],
                 rule_names: list[str], digest: str, raw: RawResult) -> Finding:
        spec: Weakness = weakness(weakness_key)

        # Identical construction to the gitleaks adapter, and that is the
        # requirement rather than a coincidence: same weakness plus same digest
        # has to produce the same fingerprint, or the two tools never merge and
        # the agreement never turns into confidence.
        fingerprint = Finding.compute_fingerprint(weakness_key, None, digest)

        evidence = []
        for rule, match in hits[:_MAX_EVIDENCE]:
            # The worker sends the full value only when the operator opted in;
            # otherwise it is None and the redacted preview is all there is. Show
            # whichever we have, and record which, so the UI masks a real value
            # behind the password gate but never pretends a redacted preview
            # hides a fuller one.
            full = _text(match.get("value"), 400)
            preview = _text(match.get("preview"), 200) or ""
            shown, redacted = (full, False) if full else (preview, True)
            evidence.append(Evidence(
                kind=EvidenceKind.SNIPPET,
                value=f"{rule}: {shown}".strip(),
                redacted=redacted,
                artifact_path=raw.raw_path))

        description = spec.description
        if len(rule_names) > 1:
            description = (f"{description}\n\nMatched by "
                           f"{len(rule_names)} apkleaks rules: "
                           f"{', '.join(rule_names)}.")

        return Finding(
            fingerprint=fingerprint,
            weakness_key=weakness_key,
            title=spec.title,
            description=description,
            severity=spec.severity,
            # apkleaks has no line numbers and a looser pattern set than
            # gitleaks, so a hit on its own is a weaker claim. When gitleaks
            # agrees, the merge is what raises this.
            confidence=0.7,
            masvs_category=spec.masvs_category,
            masvs_control=spec.masvs_control,
            maswe_id=spec.maswe_id,
            mobile_top10=spec.mobile_top10,
            cwe=spec.cwe,
            # No file or line: apkleaks reports the matched string and not where
            # it came from. Leaving location empty is honest, and it is also
            # what keeps the fingerprint equal to gitleaks'.
            location=Location(),
            entity_ids=[f"{EntityType.SECRET.value}:sha256:{digest}"],
            evidence=evidence,
            sources=[FindingSource(tool=self.tool, rule=rule_names[0],
                                   raw_ref=raw.raw_path)],
            remediation=Remediation(
                summary=spec.remediation,
                steps=[RemediationStep(text=spec.remediation)],
                references=list(spec.references)),
        )
