"""Config & platform audit: stage 6 of the plan's pipeline.

This is the first analyzer that emits *judgements*. The unpackers deliberately
do not: androguard records that ``android:debuggable`` is true and apktool
records what the network security config declares, because "is that a problem?"
depends on the whole picture, and a tool that answers it while holding only one
piece answers it badly.

Two things make this adapter unlike the others.

**It runs no container.** It reads the graph earlier stages built, App,
Component and Permission nodes: not the sample. That is not a shortcut around
the sandbox rule, it is the rule holding: the hostile bytes were parsed in a
container already, and re-opening the manifest here to double-check would put
attacker-controlled XML in front of an in-process parser for no gain.

**Its raw output is its own verdict document.** ``run`` writes the checks it
made to ``raw/config-audit/config-audit.json`` and ``normalize`` turns them into
findings, exactly as if a third-party tool had produced them. That keeps the
provenance story uniform: every finding in themob can point at the tool output
it came from, including the findings themob produced itself.

Every finding is keyed by a canonical weakness id from
:mod:`themob.knowledge.weaknesses`, never by a check name local to this file, so
that when MobSF (phase 2) reports the same weakness the two merge and vote
instead of double-reporting.
"""
from __future__ import annotations

import json
from typing import Any, Iterator

from ..knowledge import Weakness, get as weakness
from ..model.entities import Entity
from ..model.enums import (ComponentKind, EntityType, EvidenceKind, Platform,
                           Stage)
from ..model.findings import (Evidence, Finding, FindingSource, Location,
                              Remediation, RemediationStep)
from ..storage.workspace import Workspace
from .base import (AnalysisContext, Analyzer, AnalyzerResult, RawResult,
                   Target)

_MANIFEST = "AndroidManifest.xml"

# Below this, the platform no longer receives security patches and the app
# silently opts out of the hardening newer releases added. A policy constant,
# not a fact: it ages, and it belongs in the knowledge pack with the rest of
# the tunable thresholds whenever the pack grows a section for them.
_MIN_SUPPORTED_SDK = 26

# Cleartext is permitted by the platform default below this target SDK.
_CLEARTEXT_DEFAULT_SDK = 28

_LAUNCHER_ACTION = "android.intent.action.MAIN"
_LAUNCHER_CATEGORY = "android.intent.category.LAUNCHER"

# Bounds. Everything here came from a hostile package via a tool; a manifest can
# declare thousands of anything.
_MAX_CHECKS = 5000
_MAX_DOMAINS_LISTED = 12
_MAX_TEXT = 2000


def _clip(text: Any, limit: int = _MAX_TEXT) -> str:
    return ("" if text is None else str(text))[:limit]


def _is_launcher(component: Entity) -> bool:
    """Whether this component is the app's entry point in the launcher.

    An exported launcher activity is not a finding. It is how the user opens
    the app, and every app on the device has one. Reporting it buries the
    exported components that *are* worth looking at.
    """
    for filt in component.attributes.get("intent_filters") or []:
        if not isinstance(filt, dict):
            continue
        actions = filt.get("actions") or []
        categories = filt.get("categories") or []
        if _LAUNCHER_ACTION in actions and _LAUNCHER_CATEGORY in categories:
            return True
    return False


def _guarded(component: Entity) -> bool:
    """Whether reaching this component requires holding some permission."""
    attributes = component.attributes
    if component.attributes.get("kind") == ComponentKind.PROVIDER.value:
        # A provider can be guarded separately for reads and writes; either one
        # alone still leaves the other side open, so both must be present.
        return bool(attributes.get("read_permission")
                    and attributes.get("write_permission")) or bool(
                        attributes.get("permission"))
    return bool(attributes.get("permission"))


class ConfigAuditAnalyzer(Analyzer):
    """Judge the manifest and platform configuration the unpackers recovered."""

    name = "config-audit"
    display = "config · manifest & platform audit"
    stage = Stage.CONFIG_AUDIT
    platforms = (Platform.ANDROID,)
    image = ""                      # reads the graph, not the sample
    wants_graph = True
    tool = "config-audit"
    license_note = ("themob's own auditor. No third-party tool, and no container, "
                    "because it reads the graph earlier stages built rather than "
                    "the package.")

    # -- run ------------------------------------------------------------------

    def run(self, target: Target, workspace: Workspace,
            sandbox: Any = None,
            context: AnalysisContext | None = None) -> RawResult:
        base = RawResult(analyzer=self.name)

        if context is None or context.is_empty:
            base.error = ("nothing to audit: run the unpack stage first so the "
                          "manifest is in the graph")
            return base

        app = context.app
        if app is None or app.type is not EntityType.APP:
            base.error = "no App node in the graph; the unpack stage did not identify one"
            return base

        components = context.of_type(EntityType.COMPONENT)
        permissions = context.of_type(EntityType.PERMISSION)

        checks = list(self._audit(app, components, permissions))[:_MAX_CHECKS]
        payload: dict[str, Any] = {
            "ok": True,
            "tool": self.tool,
            "app_key": app.key,
            "checks": checks,
            "counts": {"components": len(components),
                       "permissions": len(permissions),
                       "findings": len(checks)},
        }

        # Persisted like any tool's output, so a finding can cite it.
        try:
            path = workspace.raw_dir(self.name) / "config-audit.json"
            path.write_text(json.dumps(payload, indent=2, sort_keys=True),
                            encoding="utf-8")
            base.raw_path = workspace.relative(path)
        except OSError:
            base.raw_path = None

        base.payload = payload
        base.ok = True
        return base

    # -- the checks -----------------------------------------------------------

    def _audit(self, app: Entity, components: list[Entity],
               permissions: list[Entity]) -> Iterator[dict[str, Any]]:
        yield from self._audit_app(app)
        yield from self._audit_network(app)
        yield from self._audit_components(components)
        yield from self._audit_permissions(permissions)

    def _audit_app(self, app: Entity) -> Iterator[dict[str, Any]]:
        attributes = app.attributes

        if attributes.get("debuggable") is True:
            yield self._check("android.config.debuggable", app,
                              evidence="android:debuggable=\"true\"")

        # allowBackup defaults to true, so "not declared" is still "allowed".
        # Saying which of the two it was matters to whoever fixes it.
        backup = attributes.get("allow_backup")
        if backup is not False:
            yield self._check(
                "android.config.backup-allowed", app,
                evidence=("android:allowBackup=\"true\"" if backup is True else
                          "android:allowBackup is not declared"),
                detail=("" if backup is True else
                        "The platform default is true, so backups are permitted."))

        min_sdk = attributes.get("min_sdk")
        if isinstance(min_sdk, int) and 0 < min_sdk < _MIN_SUPPORTED_SDK:
            yield self._check(
                "android.platform.min-sdk-unsupported", app,
                evidence=f"minSdkVersion={min_sdk}",
                detail=f"themob treats API {_MIN_SUPPORTED_SDK} as the current floor.")

        signing = attributes.get("signing")
        if isinstance(signing, dict) and signing.get("v1") is True:
            if not (signing.get("v2") or signing.get("v3")):
                yield self._check(
                    "android.integrity.v1-signature-only", app,
                    evidence="signed with v1 only (no v2 or v3 block)")

    def _audit_network(self, app: Entity) -> Iterator[dict[str, Any]]:
        attributes = app.attributes

        if attributes.get("uses_cleartext_traffic") is True:
            yield self._check("android.network.cleartext-permitted", app,
                              evidence="android:usesCleartextTraffic=\"true\"")

        config = attributes.get("network_security_config")
        target_sdk = attributes.get("target_sdk")

        if not config:
            # No config at all. Below API 28 the platform permits cleartext, so
            # the app is free to speak HTTP whether or not it does today.
            if isinstance(target_sdk, int) and 0 < target_sdk < _CLEARTEXT_DEFAULT_SDK:
                yield self._check(
                    "android.network.no-network-security-config", app,
                    evidence=f"no network security config, targetSdkVersion={target_sdk}")
            return

        if not isinstance(config, dict):
            # androguard recovered the reference but apktool never resolved the
            # file: the declaration exists, its contents are unknown. Not a
            # finding: reporting one either way would be a guess.
            return

        for entry in config.get("configs") or []:
            if not isinstance(entry, dict):
                continue
            yield from self._audit_nsc_entry(app, entry, config)

    def _audit_nsc_entry(self, app: Entity, entry: dict[str, Any],
                         config: dict[str, Any]) -> Iterator[dict[str, Any]]:
        scope = _clip(entry.get("scope"), 32) or "base"
        domains = [d for d in (entry.get("domains") or []) if isinstance(d, str)]
        where = f"{scope}-config"
        if domains:
            listed = ", ".join(domains[:_MAX_DOMAINS_LISTED])
            if len(domains) > _MAX_DOMAINS_LISTED:
                listed += f" (+{len(domains) - _MAX_DOMAINS_LISTED} more)"
            where = f"{where} for {listed}"

        if entry.get("cleartext_permitted") is True:
            # A base-config opt-in is app-wide; a domain-config one is scoped to
            # the hosts it names, which is a materially smaller exposure.
            key = ("android.network.cleartext-permitted-for-domain" if domains
                   else "android.network.cleartext-permitted")
            yield self._check(
                key, app,
                evidence=f"cleartextTrafficPermitted=\"true\" in the {where}",
                file=_clip(config.get("path"), 512) or None,
                # Distinct instances must not collapse into one finding.
                discriminator=where)

        anchors = [a for a in (entry.get("trust_anchors") or []) if isinstance(a, str)]
        if any(a.strip().lower() == "user" for a in anchors):
            yield self._check(
                "android.network.user-ca-trusted", app,
                evidence=f"trust-anchors include the user store in the {where}",
                file=_clip(config.get("path"), 512) or None,
                discriminator=where)

    def _audit_components(self, components: list[Entity]) -> Iterator[dict[str, Any]]:
        for component in components:
            if component.attributes.get("exported") is not True:
                continue
            if _guarded(component):
                continue
            if _is_launcher(component):
                continue

            kind = _clip(component.attributes.get("kind"), 32)
            is_provider = kind == ComponentKind.PROVIDER.value
            key = ("android.ipc.provider-exported-unprotected" if is_provider
                   else "android.ipc.component-exported-unprotected")

            evidence = f"{kind or 'component'} exported with no permission"
            if is_provider and component.attributes.get("authorities"):
                evidence += (f"; authorities="
                             f"{_clip(component.attributes['authorities'], 255)}")
            # An absent android:exported is a different story from an explicit
            # one: it means the manifest relied on a default.
            if component.attributes.get("exported_declared") is None:
                evidence += "; android:exported is not declared"

            yield self._check(key, component, evidence=evidence,
                              component=component.key)

    def _audit_permissions(self, permissions: list[Entity]) -> Iterator[dict[str, Any]]:
        for permission in permissions:
            attributes = permission.attributes
            if not attributes.get("declared_by_app"):
                continue
            declared = _clip(attributes.get("protection_level"), 64)
            # "signatureOrSystem" and "signature|privileged" both count; matching
            # on the substring covers the compound forms. An undeclared level
            # defaults to "normal", which is the weak case.
            if "signature" in declared.lower():
                continue
            yield self._check(
                "android.ipc.custom-permission-weak-protection", permission,
                # Quote what the manifest said, not a normalised copy of it,
                # a reader checking the report against the app has to find it.
                evidence=(f"android:protectionLevel=\"{declared}\"" if declared else
                          "android:protectionLevel is not declared (defaults to normal)"),
                component=permission.key)

    # -- check construction ---------------------------------------------------

    @staticmethod
    def _check(weakness_key: str, entity: Entity, *, evidence: str,
               detail: str = "", component: str | None = None,
               file: str | None = None,
               discriminator: str = "") -> dict[str, Any]:
        """One judgement, in the shape ``normalize`` reads back.

        ``get`` raises on an unknown key, which is deliberate: a typo here would
        otherwise reach a report as an unmapped finding with no severity.
        """
        weakness(weakness_key)              # fail fast on an unknown key
        return {
            "weakness": weakness_key,
            "entity_key": entity.key,
            "entity_id": entity.id,
            "entity_type": entity.type.value,
            "component": component,
            "file": file or _MANIFEST,
            "evidence": _clip(evidence),
            "detail": _clip(detail),
            "discriminator": _clip(discriminator, 255),
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
            spec: Weakness = weakness(key)
        except KeyError:
            # Should be unreachable: _check validates on the way in, but a
            # malformed persisted document must not take the run down.
            return None

        location = Location(
            file=_clip(check.get("file"), 512) or None,
            component=_clip(check.get("component"), 512) or None,
        )
        evidence_text = _clip(check.get("evidence"))
        detail = _clip(check.get("detail"))

        # The fingerprint is the canonical weakness plus *where*, so re-running
        # converges and a second tool reporting the same thing merges. The
        # discriminator separates genuinely distinct instances at one location,
        # two network-security-config entries on the same App node.
        fingerprint = Finding.compute_fingerprint(
            key, location, _clip(check.get("discriminator"), 255))

        description = spec.description
        if detail:
            description = f"{description}\n\n{detail}"

        entity_id = check.get("entity_id")
        return Finding(
            fingerprint=fingerprint,
            weakness_key=key,
            title=spec.title,
            description=description,
            severity=spec.severity,
            # An explicit manifest declaration is a fact, not an inference: the
            # auditor read it out of the graph, so it is not guessing. What it
            # cannot know is whether the exposure matters, which is what the
            # manual-validation workflow (1.12) is for.
            confidence=0.95,
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
