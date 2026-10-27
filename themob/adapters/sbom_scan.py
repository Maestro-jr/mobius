"""syft and grype: what the app bundles, and which of it has a published advisory.

Stage 5. It scans the *artifacts* directory rather than the APK, for the same
reason the secret scanners do: by this point apktool has laid the package out
and there is nothing left in the archive that the tools built for it have not
already extracted.

**The build plan names syft, and syft alone cannot do this.** Pointed at an
Android package it reports zero artifacts, and pointed at a directory holding
``META-INF/androidx.core_core.version`` or a shaded
``META-INF/maven/<group>/<artifact>/pom.properties`` it still reports zero: its
Java support reads inside JAR archives, and an APK has none, because Gradle
merged every dependency into ``classes.dex`` long before shipping. So the worker
catalogs the Android evidence itself, hands grype a CycloneDX SBOM built from
it, and still runs syft over the tree for the cases it does cover.

A Library is an entity, not just a finding. The graph needs the node so a later
stage can say "this exported component reaches this vulnerable library", and so
that a clean dependency is still recorded: knowing what shipped is worth
something even when nothing is wrong with it.

Severity comes from the advisory, not from the weakness catalogue. The
catalogue's default is the starting point for a weakness in general; a specific
CVE already carries a considered rating, and overriding it with a house default
would be throwing away the better number.
"""
from __future__ import annotations

import json
from typing import Any

from ..knowledge import get as weakness
from ..model.enums import (EdgeType, EntityType, EvidenceKind, Platform,
                           Severity, Stage)
from ..model.findings import (Evidence, Finding, FindingSource, Location,
                              Remediation, RemediationStep)
from ..sandbox.runner import SandboxRunner, SandboxResult, with_limits
from ..storage.workspace import Workspace
from .base import (AnalysisContext, Analyzer, AnalyzerResult, EdgeSpec,
                   EntityRef, RawResult, Target)

_MAX_TEXT = 2048
_MAX_LIBRARIES = 2000
_MAX_FINDINGS = 5000

_WEAKNESS = "android.supply-chain.vulnerable-dependency"

# grype's severity vocabulary onto themob's. "Negligible" and "Unknown" both
# land on INFO: the finding is still recorded, it just carries no urgency.
_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "negligible": Severity.INFO,
    "unknown": Severity.INFO,
}


def _text(value: Any, limit: int = _MAX_TEXT) -> str | None:
    if value is None or isinstance(value, (dict, list)):
        return None
    text = (value if isinstance(value, str) else str(value)).strip()
    return text[:limit] or None


def _number(value: Any) -> float | None:
    return float(value) if isinstance(value, (int, float)) and not isinstance(
        value, bool) else None


class SbomScanAnalyzer(Analyzer):
    """Catalog the bundled libraries and match them against known advisories."""

    name = "sbom-scan"
    display = "syft + grype · dependencies"
    stage = Stage.DEPENDENCIES
    platforms = (Platform.ANDROID, Platform.IOS)
    image = "themob/sbom:1"
    tool = "grype"
    timeout = 1200.0
    memory = "3g"
    license_note = ("syft and grype are Apache-2.0; both are invoked as "
                    "subprocesses inside a container, and the vulnerability "
                    "database is baked into the image because the container "
                    "has no network to update it from.")

    # -- run ------------------------------------------------------------------

    def run(self, target: Target, workspace: Workspace,
            sandbox: SandboxRunner,
            context: AnalysisContext | None = None) -> RawResult:
        base = RawResult(analyzer=self.name)

        scan_dir = workspace.artifacts_root
        if not scan_dir.is_dir() or not any(scan_dir.iterdir()):
            base.error = ("nothing to scan: run the unpack stage first so the "
                          "package is laid out")
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
            target_file = workspace.raw_dir(self.name) / "sbom.json"
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
        # A sandbox-level failure outranks the worker's own diagnosis; anything
        # else, the worker knows better than the exit code does.
        if result.timed_out or result.truncated:
            base.error = result.error
        elif not payload.get("ok"):
            base.error = _text(payload.get("error")) or "the scan reported a failure"
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

        app_ref = EntityRef(EntityType.APP, target.fallback_app_key)
        libraries = raw.payload.get("libraries")
        if not isinstance(libraries, list):
            return result

        known: dict[str, str] = {}          # purl -> entity key
        for entry in libraries[:_MAX_LIBRARIES]:
            if not isinstance(entry, dict):
                continue
            purl = _text(entry.get("purl"), 512)
            name = _text(entry.get("name"), 128)
            if not purl or not name:
                continue
            # The placeholder the pipeline swaps for a real row id once the
            # entity is upserted. The Library node does not have one yet.
            known[purl] = f"{EntityType.LIBRARY.value}:{purl}"

            library = self.entity(
                EntityType.LIBRARY, purl, target,
                label=f"{name} {_text(entry.get('version'), 64) or ''}".strip(),
                group=_text(entry.get("group"), 128),
                package_name=name,
                version=_text(entry.get("version"), 64),
                purl=purl,
                evidence_path=_text(entry.get("evidence"), 512),
                cataloger=_text(entry.get("cataloger"), 128),
            )
            result.entities.append(library)
            # The app embeds the library. Same edge type the native libraries
            # use, because it is the same relationship.
            result.edges.append(EdgeSpec(app_ref, EntityRef.of(library),
                                         EdgeType.EMBEDS))

        result.findings.extend(
            self._findings(raw, target, known))
        self._record_scan(raw, target, result, app_ref)
        return result

    def _findings(self, raw: RawResult, target: Target,
                  known: dict[str, str]) -> list[Finding]:
        spec = weakness(_WEAKNESS)
        vulnerabilities = raw.payload.get("vulnerabilities")
        if not isinstance(vulnerabilities, list):
            return []

        findings: list[Finding] = []
        for entry in vulnerabilities[:_MAX_FINDINGS]:
            if not isinstance(entry, dict):
                continue
            advisory = _text(entry.get("id"), 64)
            purl = _text(entry.get("purl"), 512)
            if not advisory or not purl:
                continue

            package = _text(entry.get("package"), 128) or ""
            version = _text(entry.get("version"), 64) or ""
            fixed_in = _text(entry.get("fixed_in"), 64)
            severity = _SEVERITY.get(
                (_text(entry.get("severity"), 32) or "").lower(), spec.severity)

            # The advisory id is part of the identity: two different CVEs
            # against the same library are two findings, not one seen twice.
            location = Location(file=purl)
            fingerprint = Finding.compute_fingerprint(_WEAKNESS, location,
                                                      advisory)

            description = spec.description
            detail = _text(entry.get("description"), 1200)
            if detail:
                description = f"{description}\n\n{detail}"

            remediation = spec.remediation
            if fixed_in:
                remediation = (f"Upgrade {package} to {fixed_in} or later. "
                               f"{spec.remediation}")

            findings.append(Finding(
                fingerprint=fingerprint,
                weakness_key=_WEAKNESS,
                title=f"{advisory} in {package} {version}".strip(),
                description=description,
                severity=severity,
                # grype matched a version string against an advisory range. That
                # is a precise operation, but "bundled" is not "reachable", and
                # deciding that is the tester's job.
                confidence=0.9,
                masvs_category=spec.masvs_category,
                masvs_control=spec.masvs_control,
                maswe_id=spec.maswe_id,
                mobile_top10=spec.mobile_top10,
                cwe=spec.cwe,
                location=location,
                evidence=[Evidence(
                    kind=EvidenceKind.SNIPPET,
                    value=(f"{purl} matches {advisory}"
                           + (f", fixed in {fixed_in}" if fixed_in else "")),
                    artifact_path=raw.raw_path)],
                # Wire the finding to the Library node it is about, so the graph
                # can answer "what reaches this vulnerable dependency". The
                # pipeline resolves the placeholder after the entity is upserted.
                entity_ids=[known[purl]] if purl in known else [],
                sources=[FindingSource(tool=self.tool, rule=advisory,
                                       raw_ref=raw.raw_path)],
                remediation=Remediation(
                    summary=remediation,
                    steps=[RemediationStep(text=remediation)],
                    references=[u for u in (entry.get("urls") or [])
                                if isinstance(u, str)][:8]),
            ))
        return findings

    def _record_scan(self, raw: RawResult, target: Target,
                     result: AnalyzerResult, app_ref: EntityRef) -> None:
        """Put the scan's own numbers on the App node.

        A run that found nothing and a run that never happened look identical
        otherwise, and the difference matters when someone reads the report and
        wants to know whether dependencies were examined at all.
        """
        scanned = raw.payload.get("scanned")
        scanned = scanned if isinstance(scanned, dict) else {}
        result.entities.append(self.entity(
            EntityType.APP, target.fallback_app_key, target,
            label=target.name or target.fallback_app_key,
            dependency_scan={
                "files": scanned.get("files"),
                "libraries": scanned.get("libraries"),
                "vulnerabilities": len(result.findings),
                "truncated": bool(raw.payload.get("truncated")),
                "tool_version": raw.payload.get("tool_version"),
                # When grype's vulnerability database was built. Carried so the
                # report can say whether a clean result was matched against
                # current data or stale data.
                "vuln_db": raw.payload.get("vuln_db"),
            },
        ))
