"""Endpoint and cloud-asset recon: stage 7 of the plan's pipeline.

The plan calls this themob's differentiator: pull the backend attack surface out
of the package and hand it to TOPRECON's web-recon engine. That only works if
what comes out is a defensible list, so this stage is mostly *judgement*, not
extraction.

The extraction already happened. apkleaks runs LinkFinder over the decompiled
code and resources during stage 3, and its worker deliberately passes URL-shaped
hits through unredacted for exactly this reason. Re-scanning the tree with a
second extractor would duplicate a tool themob already runs at arms length.

What LinkFinder hands over is raw, and raw is not the same as useful. On the
project's own fixture it returns seven hits, and three are not endpoints:

* ``http://schemas.android.com/apk/res/android``, an XML namespace. Every
  Android manifest contains it, and no app has ever talked to it.
* ``/order``, a bare path with no host.
* ``AES/ECB/PKCS5Padding``, a cipher transformation that happens to contain
  slashes.

Shipping those to a recon engine would have it scanning w3.org on behalf of
every app themob ever looks at. So this adapter filters, classifies and
normalises, and each rejection is a rule with a reason rather than a
hand-maintained blocklist.

It runs no container. Its input is the JSON another worker already produced in
one, which is structured and bounded, so there is nothing hostile left to parse
in the way that opening the package again would be.
"""
from __future__ import annotations

import ipaddress
import json
from typing import Any, Iterable
from urllib.parse import urlsplit, urlunsplit

from ..knowledge import get as weakness
from ..model.enums import EdgeType, EntityType, EvidenceKind, Platform, Stage
from ..model.findings import (Evidence, Finding, FindingSource, Location,
                              Remediation, RemediationStep)
from ..storage.workspace import Workspace
from .base import (AnalysisContext, Analyzer, AnalyzerResult, EdgeSpec,
                   EntityRef, RawResult, Target)

# The upstream whose output this reads, per platform: (analyzer, file, key).
# Android reads apkleaks' LinkFinder hits; iOS reads the URL list the ios-unpack
# worker scanned out of the bundle. Either way this stage only classifies.
_SOURCES: dict[Platform, tuple[str, str, str]] = {
    Platform.ANDROID: ("apkleaks-scan", "apkleaks.json", "results"),
    Platform.IOS: ("ios-unpack", "ios-unpack.json", "endpoints"),
}

# The cleartext-endpoint weakness, by platform: same meaning, platform-honest key.
_CLEARTEXT_KEY: dict[Platform, str] = {
    Platform.ANDROID: "android.network.cleartext-endpoint",
    Platform.IOS: "ios.network.cleartext-endpoint",
}

_MAX_ENDPOINTS = 2000
_MAX_TEXT = 2000

# Schemes worth reporting. A recon engine speaks HTTP; everything else is a
# different kind of finding and not this stage's business.
_WEB_SCHEMES = ("http", "https")

# Hosts that appear in every Android package and belong to nobody's backend.
# These are namespace and specification URLs: they are declarations, not
# destinations, and an app never sends a request to one.
_NON_ENDPOINT_HOSTS = frozenset({
    "schemas.android.com",
    "www.w3.org", "w3.org",
    "java.sun.com", "xml.org", "xmlpull.org",
    "www.apache.org", "apache.org",
    "goo.gl", "developer.android.com", "android.googlesource.com",
    "www.gnu.org", "gnu.org", "opensource.org", "creativecommons.org",
    "json-schema.org", "www.json.org",
})

# Cloud storage and backend hosts, by the suffix that identifies the provider.
# The bucket is the interesting part: it is a named store that may be readable
# by anyone, which is a different question from "the app talks to this API".
_CLOUD_SUFFIXES: tuple[tuple[str, str], ...] = (
    (".s3.amazonaws.com", "aws-s3"),
    (".s3-website.amazonaws.com", "aws-s3"),
    (".storage.googleapis.com", "gcp-gcs"),
    (".firebaseio.com", "firebase-rtdb"),
    (".firebasestorage.app", "firebase-storage"),
    (".appspot.com", "gcp-appengine"),
    (".blob.core.windows.net", "azure-blob"),
    (".table.core.windows.net", "azure-table"),
    (".queue.core.windows.net", "azure-queue"),
    (".digitaloceanspaces.com", "do-spaces"),
    (".r2.cloudflarestorage.com", "cloudflare-r2"),
)

# Bare provider hosts, where the bucket sits in the path rather than the host.
_CLOUD_PATH_HOSTS: tuple[tuple[str, str], ...] = (
    ("s3.amazonaws.com", "aws-s3"),
    ("storage.googleapis.com", "gcp-gcs"),
)


def _clip(value: Any, limit: int = _MAX_TEXT) -> str:
    return ("" if value is None else str(value))[:limit]


def _is_private(host: str) -> bool:
    """Whether the host is an address nobody outside the network can reach."""
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return host in ("localhost", "localhost.localdomain")


def classify_cloud(host: str, path: str) -> tuple[str, str] | None:
    """``(provider, bucket)`` when the host names a cloud store, else None."""
    lowered = host.lower()
    for suffix, provider in _CLOUD_SUFFIXES:
        if lowered.endswith(suffix) and len(lowered) > len(suffix):
            return provider, lowered[:-len(suffix)]
    for bare, provider in _CLOUD_PATH_HOSTS:
        if lowered == bare:
            bucket = path.strip("/").split("/", 1)[0]
            if bucket:
                return provider, bucket
    return None


def normalise_url(value: str) -> tuple[str, str, str, str] | None:
    """``(url, scheme, host, path)`` for a usable web URL, else None.

    Rejects, in order: anything that is not an absolute http(s) URL, anything
    with no host, and hosts that are namespace declarations rather than
    destinations. The query and fragment are dropped because they vary per
    request; what a tester probes is the path.
    """
    text = (value or "").strip().strip('"').strip("'")
    if not text or "://" not in text:
        return None                     # a bare path is not an endpoint
    try:
        parts = urlsplit(text)
    except ValueError:
        return None

    scheme = (parts.scheme or "").lower()
    if scheme not in _WEB_SCHEMES:
        return None
    host = (parts.hostname or "").lower()
    if not host or host in _NON_ENDPOINT_HOSTS:
        return None
    # A host with no dot and no port is not a routable name; "localhost" is the
    # exception worth keeping, because a dev endpoint left in a release build
    # is a real finding.
    if "." not in host and not _is_private(host):
        return None

    path = parts.path or "/"
    netloc = host if parts.port is None else f"{host}:{parts.port}"
    return urlunsplit((scheme, netloc, path, "", "")), scheme, host, path


class EndpointExtractAnalyzer(Analyzer):
    """Turn extracted links into Endpoint and CloudAsset nodes."""

    name = "endpoint-extract"
    display = "endpoints · backend attack surface"
    stage = Stage.API_RECON
    platforms = (Platform.ANDROID, Platform.IOS)
    image = ""                      # reads another stage's output, not the app
    wants_graph = True
    tool = "endpoint-extract"
    license_note = ("themob's own extractor. It reads the URL list an earlier "
                    "worker already produced inside a container (apkleaks on "
                    "Android, ios-unpack on iOS), so no third-party tool and no "
                    "second pass over the package.")

    # -- run ------------------------------------------------------------------

    def run(self, target: Target, workspace: Workspace,
            sandbox: Any = None,
            context: AnalysisContext | None = None) -> RawResult:
        base = RawResult(analyzer=self.name)

        spec = _SOURCES.get(target.platform)
        if spec is None:
            base.error = f"no endpoint source is defined for {target.platform.value}"
            return base
        analyzer_name, filename, required_key = spec

        source = workspace.raw_dir(analyzer_name) / filename
        if not source.is_file():
            stage_word = "secrets" if target.platform is Platform.ANDROID else "iOS unpack"
            base.error = (f"nothing to read: run the {stage_word} stage first, "
                          f"{analyzer_name} has produced no output")
            return base
        try:
            document = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            base.error = f"{filename} could not be read: {exc}"
            return base
        if not isinstance(document, dict) or required_key not in document:
            base.error = f"{filename} is not in the shape this stage expects"
            return base

        endpoints, assets, rejected = self._classify(
            self._candidates_for(target.platform, document))
        payload: dict[str, Any] = {
            "ok": True,
            "tool": self.tool,
            "source": workspace.relative(source),
            "endpoints": endpoints[:_MAX_ENDPOINTS],
            "cloud_assets": assets[:_MAX_ENDPOINTS],
            # Kept deliberately. When a tester asks why a URL they can see in
            # the package is not in the report, this is the answer, and it is
            # the difference between a filter and a black box.
            "rejected": rejected[:_MAX_ENDPOINTS],
            "counts": {"endpoints": len(endpoints), "cloud_assets": len(assets),
                       "rejected": len(rejected)},
        }

        try:
            path = workspace.raw_dir(self.name) / "endpoints.json"
            path.write_text(json.dumps(payload, indent=2, sort_keys=True),
                            encoding="utf-8")
            base.raw_path = workspace.relative(path)
        except OSError:
            base.raw_path = None

        base.payload = payload
        base.ok = True
        return base

    # -- classification -------------------------------------------------------

    def _candidates_for(self, platform: Platform,
                        document: dict[str, Any]) -> Iterable[tuple[str, str]]:
        """The (value, rule) pairs to classify, whichever upstream produced them."""
        if platform is Platform.IOS:
            return self._ios_candidates(document)
        return self._candidates(document.get("results"))

    @staticmethod
    def _ios_candidates(document: dict[str, Any]) -> Iterable[tuple[str, str]]:
        """The ios-unpack worker's flat URL list, each tagged with one rule."""
        for value in document.get("endpoints") or []:
            if isinstance(value, str) and value.strip():
                yield value, "ios-unpack"

    def _classify(self, candidates: Iterable[tuple[str, str]]) -> tuple[list, list, list]:
        endpoints: dict[str, dict[str, Any]] = {}
        assets: dict[str, dict[str, Any]] = {}
        rejected: list[dict[str, str]] = []

        for value, rule in candidates:
            parsed = normalise_url(value)
            if parsed is None:
                # A bare host is still worth keeping when a rule says it is a
                # bucket: apkleaks reports S3 buckets without a scheme.
                cloud = self._bare_cloud_host(value, rule)
                if cloud is not None:
                    assets.setdefault(cloud["key"], cloud)
                    continue
                rejected.append({"value": _clip(value, 255), "rule": _clip(rule, 128),
                                 "reason": self._why(value)})
                continue

            url, scheme, host, path = parsed
            cloud = classify_cloud(host, path)
            if cloud is not None:
                provider, bucket = cloud
                key = f"{provider}:{bucket}"
                assets.setdefault(key, {
                    "key": key, "provider": provider, "bucket": bucket,
                    "host": host, "url": url, "rule": _clip(rule, 128),
                })
                continue

            entry = endpoints.setdefault(url, {
                "url": url, "scheme": scheme, "host": host, "path": path,
                "cleartext": scheme == "http",
                "private": _is_private(host),
                "rules": [],
            })
            if rule and rule not in entry["rules"]:
                entry["rules"].append(_clip(rule, 128))

        return list(endpoints.values()), list(assets.values()), rejected

    @staticmethod
    def _candidates(results: Any) -> Iterable[tuple[str, str]]:
        """Every non-credential value apkleaks reported, with its rule.

        Credential matches never carry a value out of the worker, so there is
        nothing to read there even if this wanted it.
        """
        if not isinstance(results, list):
            return
        for entry in results:
            if not isinstance(entry, dict) or entry.get("credential"):
                continue
            rule = _clip(entry.get("rule"), 128)
            for match in entry.get("matches") or []:
                if not isinstance(match, dict):
                    continue
                value = match.get("value")
                if isinstance(value, str) and value.strip():
                    yield value, rule

    @staticmethod
    def _bare_cloud_host(value: str, rule: str) -> dict[str, Any] | None:
        """apkleaks reports a bucket as a hostname with no scheme."""
        host = (value or "").strip().strip("/").lower()
        if "://" in host or "/" in host or " " in host:
            return None
        cloud = classify_cloud(host, "")
        if cloud is None:
            return None
        provider, bucket = cloud
        return {"key": f"{provider}:{bucket}", "provider": provider,
                "bucket": bucket, "host": host,
                "url": f"https://{host}", "rule": _clip(rule, 128)}

    @staticmethod
    def _why(value: str) -> str:
        """Why a candidate was not treated as an endpoint."""
        text = (value or "").strip()
        if "://" not in text:
            return "not an absolute URL"
        try:
            parts = urlsplit(text)
        except ValueError:
            return "unparseable"
        if (parts.scheme or "").lower() not in _WEB_SCHEMES:
            return f"scheme {parts.scheme!r} is not http or https"
        host = (parts.hostname or "").lower()
        if not host:
            return "no host"
        if host in _NON_ENDPOINT_HOSTS:
            return "namespace or specification host, not a destination"
        return "host is not a routable name"

    # -- normalize ------------------------------------------------------------

    def normalize(self, raw: RawResult, target: Target) -> AnalyzerResult:
        result = AnalyzerResult()
        if not raw.ok or not raw.payload:
            return result
        if raw.raw_path:
            result.artifacts.append(raw.raw_path)

        payload = raw.payload
        app_ref = EntityRef(EntityType.APP, target.fallback_app_key)

        for entry in payload.get("endpoints") or []:
            if not isinstance(entry, dict) or not entry.get("url"):
                continue
            url = _clip(entry["url"], 1024)
            entity = self.entity(
                EntityType.ENDPOINT, url, target,
                label=_clip(entry.get("host"), 255) or url,
                host=_clip(entry.get("host"), 255),
                scheme=_clip(entry.get("scheme"), 16),
                path=_clip(entry.get("path"), 512),
                cleartext=bool(entry.get("cleartext")),
                private=bool(entry.get("private")),
                reported_by=[_clip(r, 128) for r in (entry.get("rules") or [])][:8],
            )
            result.entities.append(entity)
            result.edges.append(EdgeSpec(app_ref, EntityRef.of(entity),
                                         EdgeType.TALKS_TO))
            if entry.get("cleartext"):
                result.findings.append(
                    self._cleartext_finding(entry, raw, target))

        for entry in payload.get("cloud_assets") or []:
            if not isinstance(entry, dict) or not entry.get("key"):
                continue
            entity = self.entity(
                EntityType.CLOUD_ASSET, _clip(entry["key"], 512), target,
                label=_clip(entry.get("bucket"), 255) or _clip(entry["key"], 255),
                provider=_clip(entry.get("provider"), 64),
                bucket=_clip(entry.get("bucket"), 255),
                host=_clip(entry.get("host"), 255),
                url=_clip(entry.get("url"), 1024),
            )
            result.entities.append(entity)
            result.edges.append(EdgeSpec(app_ref, EntityRef.of(entity),
                                         EdgeType.USES))

        counts = payload.get("counts") or {}
        result.entities.append(self.entity(
            EntityType.APP, target.fallback_app_key, target,
            endpoint_scan={
                "endpoints": counts.get("endpoints"),
                "cloud_assets": counts.get("cloud_assets"),
                "rejected": counts.get("rejected"),
                "source": _clip(payload.get("source"), 512),
            }))
        return result

    def _cleartext_finding(self, entry: dict[str, Any], raw: RawResult,
                           target: Target) -> Finding:
        spec = weakness(_CLEARTEXT_KEY.get(target.platform,
                                           "android.network.cleartext-endpoint"))
        url = _clip(entry["url"], 1024)
        location = Location(file=url)
        return Finding(
            fingerprint=Finding.compute_fingerprint(spec.key, location, url),
            weakness_key=spec.key,
            title=f"{spec.title}: {_clip(entry.get('host'), 255)}",
            description=spec.description,
            severity=spec.severity,
            # The URL is in the package. Whether that endpoint is still live,
            # and whether it carries anything sensitive, is the tester's call.
            confidence=0.9,
            masvs_category=spec.masvs_category,
            masvs_control=spec.masvs_control,
            maswe_id=spec.maswe_id,
            mobile_top10=spec.mobile_top10,
            cwe=spec.cwe,
            location=location,
            evidence=[Evidence(kind=EvidenceKind.SNIPPET, value=url,
                               artifact_path=raw.raw_path)],
            entity_ids=[f"{EntityType.ENDPOINT.value}:{url}"],
            sources=[FindingSource(tool=self.tool, rule=spec.key,
                                   raw_ref=raw.raw_path)],
            remediation=Remediation(
                summary=spec.remediation,
                steps=[RemediationStep(text=spec.remediation)],
                references=list(spec.references)),
        )
