"""The TOPRECON handoff: the backend attack surface, as a document.

The build plan calls this the differentiator: "export the endpoint/cloud subgraph
into your web engine; round-trip the results back as enriched entities". This is
the export half. The round trip is phase 2, and the format is chosen so that
adding it later does not need a new one.

Three decisions worth stating, because each rules out something a naive export
would do.

**Hosts, not URLs, are the unit.** A web recon engine resolves names, enumerates
subdomains and scans ports; it does that per host, and handing it forty URLs on
one host would have it do the same work forty times. The URLs travel too, as
paths under their host, because they are what a tester probes once recon says
the host is live.

**Private and loopback addresses are marked, not dropped.** Scanning
``192.168.1.10`` from somewhere else reaches a different machine, or nothing, so
the recon engine must not treat it as a public target. It is still exported,
because a release build addressing a developer's machine is a real finding, and
dropping it here would hide it.

**Nothing is included that the app did not name.** No enrichment, no guessing at
sibling hosts. The value of this handoff is that every entry traces back to a
string in the package, and an inferred host would break that.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Sequence

from ..model.entities import Entity
from ..model.enums import EntityType
from ..model.findings import Finding
from .graph import GraphSnapshot
from .pivots import exposure as compute_exposure, entry_points

# The document's own version, so a consumer can tell what it is reading. Bump it
# when the shape changes, never when the contents do.
FORMAT = "themob.handoff/1"


@dataclass
class Host:
    """One host the app addresses, and everything known about it."""

    name: str
    schemes: set[str] = field(default_factory=set)
    paths: set[str] = field(default_factory=set)
    cleartext: bool = False
    private: bool = False
    cloud_provider: str | None = None
    buckets: set[str] = field(default_factory=set)
    externally_reachable: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "host": self.name,
            "schemes": sorted(self.schemes),
            "paths": sorted(self.paths),
            "cleartext": self.cleartext,
            "private": self.private,
            "cloud_provider": self.cloud_provider,
            "buckets": sorted(self.buckets),
            "externally_reachable": self.externally_reachable,
        }


def build(snapshot: GraphSnapshot,
          findings: Sequence[Finding] = ()) -> dict[str, Any]:
    """The endpoint and cloud subgraph, grouped by host.

    ``findings`` is optional and only used to attach what themob already knows
    about a host, so the recon engine can skip confirming what is settled.
    """
    endpoints = snapshot.of_type(EntityType.ENDPOINT)
    assets = snapshot.of_type(EntityType.CLOUD_ASSET)

    hosts: dict[str, Host] = {}
    entries = entry_points(snapshot)

    for entity in endpoints:
        name = str(entity.attributes.get("host") or "").strip().lower()
        if not name:
            continue
        host = hosts.setdefault(name, Host(name=name))
        scheme = str(entity.attributes.get("scheme") or "").lower()
        if scheme:
            host.schemes.add(scheme)
        path = str(entity.attributes.get("path") or "").strip()
        if path and path != "/":
            host.paths.add(path)
        host.cleartext = host.cleartext or bool(entity.attributes.get("cleartext"))
        host.private = host.private or bool(entity.attributes.get("private"))
        if entries and not host.externally_reachable:
            host.externally_reachable = compute_exposure(
                snapshot, entity.id, entries).reachable

    for entity in assets:
        name = str(entity.attributes.get("host") or "").strip().lower()
        if not name:
            continue
        host = hosts.setdefault(name, Host(name=name))
        host.cloud_provider = (str(entity.attributes.get("provider") or "")
                               or host.cloud_provider)
        bucket = str(entity.attributes.get("bucket") or "").strip()
        if bucket:
            host.buckets.add(bucket)

    known = _known_issues(snapshot, findings, endpoints + assets)
    return {
        "format": FORMAT,
        "project_id": snapshot.project_id,
        "app": _app_identity(snapshot),
        # Sorted so two exports of the same project are byte-identical, which
        # is what lets a consumer diff one run against the next.
        "hosts": [hosts[name].as_dict() for name in sorted(hosts)],
        "known_issues": known,
        "counts": {"hosts": len(hosts), "endpoints": len(endpoints),
                   "cloud_assets": len(assets)},
    }


def _app_identity(snapshot: GraphSnapshot) -> dict[str, Any]:
    """Which app this surface came from, so results can be attributed."""
    app = snapshot.root
    if app is None or app.type is not EntityType.APP:
        return {}
    return {
        "package": app.attributes.get("package") or app.key,
        "version_name": app.attributes.get("version_name"),
        "version_code": app.attributes.get("version_code"),
    }


def _known_issues(snapshot: GraphSnapshot, findings: Sequence[Finding],
                  entities: Sequence[Entity]) -> list[dict[str, Any]]:
    """What themob already established about these hosts.

    Sent so the recon engine does not spend a scan re-confirming that an
    endpoint is plaintext when the package said so outright.
    """
    host_by_entity = {
        e.id: str(e.attributes.get("host") or "").strip().lower()
        for e in entities
    }
    grouped: dict[str, set[str]] = defaultdict(set)
    for finding in findings:
        if not finding.weakness_key:
            continue
        for entity_id in finding.entity_ids:
            host = host_by_entity.get(entity_id)
            if host:
                grouped[host].add(finding.weakness_key)
    return [{"host": host, "weaknesses": sorted(keys)}
            for host, keys in sorted(grouped.items())]
