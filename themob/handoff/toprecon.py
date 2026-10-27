"""The TOPRECON handoff: what the app talks to, and who is allowed to look.

themob reads a package and learns every host it contacts. TOPRECON takes a host
and maps the infrastructure behind it, actively if told to. Joining them is the
obvious move and it is the one place in either tool where a mistake stops being
a wrong finding and becomes scanning somebody's servers without permission.

**themob knows what the app talks to. It does not know who owns any of it.** A
shopping app contacts its own backend, Google, Facebook, a payments provider and
three ad networks, and nothing in the package says which of those the client
owns. So this module refuses to decide. Every host it exports is out of scope
until a human puts it in scope, the exported document says so in a field a
reader cannot miss, and the "first-party candidate" flag is exactly that: a
candidate, derived from the package name, and never an authorization.

TOPRECON's engine takes ``scope_domains`` for an app seed and pivots into only
those apexes. This document is written to fill that argument, and it defaults it
to empty. A handoff that guessed would be a handoff that widens an engagement
quietly.

**Coming back**, TOPRECON's findings about a host enrich the endpoint themob
already has, as attributes on the existing node. The locked model has no entity
type for an IP or a certificate and gaining one is not worth the churn: what an
assessment of *the app* needs is "this endpoint resolves to these addresses and
runs these services", which is a property of the endpoint.

Re-importing converges rather than duplicating, because the entity upsert
collides on ``(project_id, type, key)`` and the keys here are the ones themob
already assigned.
"""
from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..correlate.graph import GraphSnapshot
from ..model.entities import Entity
from ..model.enums import EntityType
from ..storage.repositories import Project, Repositories

logger = logging.getLogger(__name__)

FORMAT = "themob.handoff.toprecon/1"

# TOPRECON's own entity type strings (core/entities.py). Written here rather
# than imported: the two tools are separate programs and importing across them
# would make one a library of the other, which neither wants.
TR_MOBILE_APP = "mobile_app"
TR_DOMAIN = "domain"
TR_URL = "url"
TR_CLOUD_BUCKET = "cloud_bucket"

# Hosts that belong to somebody else no matter whose app this is. Not a
# blocklist for correctness, a shortcut for the operator: these are never a
# first-party candidate, so the review list stays short enough to actually read.
_NEVER_FIRST_PARTY = (
    "googleapis.com", "google.com", "gstatic.com", "googletagmanager.com",
    "google-analytics.com", "doubleclick.net", "crashlytics.com",
    "firebaseio.com", "facebook.com", "fbcdn.net", "graph.facebook.com",
    "amazonaws.com", "cloudfront.net", "akamai.net", "akamaized.net",
    "sentry.io", "bugsnag.com", "appsflyer.com", "adjust.com", "branch.io",
    "onesignal.com", "mixpanel.com", "segment.io", "cloudflare.com",
    "microsoft.com", "windows.net", "apple.com", "github.com", "jsdelivr.net",
)


@dataclass
class Seed:
    """One thing TOPRECON could be pointed at, and what themob knows about it."""

    type: str                       # a TOPRECON entity type string
    value: str
    source: str = ""                # the themob entity this came from
    note: str = ""
    # A candidate only. Derived from the package name, which is a reverse
    # domain by convention and a lie whenever the developer felt like it.
    first_party_candidate: bool = False
    cleartext: bool = False


@dataclass
class Handoff:
    """The document themob hands over, and the scope it refuses to assume."""

    package: str = ""
    project_name: str = ""
    sha256: str = ""
    authorization_ref: str | None = None
    authorized_by: str | None = None
    generated_at: str = ""
    seeds: list[Seed] = field(default_factory=list)
    # Empty on purpose, and the one field a reader has to fill in. TOPRECON
    # takes this as scope_domains and pivots into nothing else.
    scope_domains: list[str] = field(default_factory=list)
    notice: str = ""

    @property
    def candidates(self) -> list[Seed]:
        return [s for s in self.seeds if s.first_party_candidate]


NOTICE = (
    "Every host below was extracted from the package. themob does not know "
    "who owns any of it, and a mobile app routinely contacts analytics, ad "
    "and payment providers the client has no authority over. scope_domains is "
    "empty deliberately: fill it with the apexes this engagement authorises, "
    "and TOPRECON will pivot into those and nothing else. first_party_candidate "
    "is derived from the package name and is a hint for review, never an "
    "authorization."
)


def apex(host: str) -> str:
    """The registrable-looking apex of a host, near enough for a review list.

    Deliberately not a public-suffix implementation. A wrong apex here shortens
    or lengthens a list a human then reads; it never authorises anything, since
    scope is entered by hand.
    """
    host = (host or "").strip().lower().rstrip(".")
    if not host or host.replace(".", "").isdigit():
        return host
    parts = [p for p in host.split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def package_apex(package: str) -> str:
    """The domain an Android package name implies, by the reverse-DNS custom.

    ``com.example.shop`` implies ``example.com``. It is a convention, not a
    fact: plenty of packages are named after something else entirely, which is
    why what comes out of this is called a candidate.
    """
    parts = [p for p in (package or "").split(".") if p]
    if len(parts) < 2:
        return ""
    return f"{parts[1]}.{parts[0]}".lower()


def _third_party(host: str) -> bool:
    host = (host or "").lower()
    return any(host == known or host.endswith("." + known)
               for known in _NEVER_FIRST_PARTY)


def build(snapshot: GraphSnapshot, project: Project) -> Handoff:
    """The endpoint and cloud subgraph, as something TOPRECON can be seeded with."""
    app = next(iter(snapshot.of_type(EntityType.APP)), None)
    package = str((app.attributes.get("package") if app else "") or "")
    own = package_apex(package)

    handoff = Handoff(
        package=package,
        project_name=project.name,
        sha256=project.source_sha256,
        authorization_ref=project.authorization_ref,
        authorized_by=project.authorized_by,
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        notice=NOTICE,
    )

    if package:
        handoff.seeds.append(Seed(
            type=TR_MOBILE_APP, value=package, source="app",
            note="the package this assessment covers"))

    seen: set[tuple[str, str]] = set()

    for entity in snapshot.of_type(EntityType.ENDPOINT):
        host = str(entity.attributes.get("host") or "").strip().lower()
        if not host or entity.attributes.get("private"):
            # A private address is somebody's LAN, not an internet asset, and
            # handing one to a recon engine points it at a network it cannot
            # reach and should not try to.
            continue
        host_apex = apex(host)
        candidate = bool(own) and host_apex == own and not _third_party(host)

        if ("domain", host_apex) not in seen:
            seen.add(("domain", host_apex))
            handoff.seeds.append(Seed(
                type=TR_DOMAIN, value=host_apex, source=entity.key,
                note="apex of a host the app contacts",
                first_party_candidate=candidate))
        if ("url", entity.key) not in seen:
            seen.add(("url", entity.key))
            handoff.seeds.append(Seed(
                type=TR_URL, value=entity.key, source=entity.key,
                note="an endpoint the app calls",
                first_party_candidate=candidate,
                cleartext=bool(entity.attributes.get("cleartext"))))

    for entity in snapshot.of_type(EntityType.CLOUD_ASSET):
        bucket = str(entity.attributes.get("bucket") or entity.key)
        if ("bucket", bucket) not in seen:
            seen.add(("bucket", bucket))
            handoff.seeds.append(Seed(
                type=TR_CLOUD_BUCKET, value=bucket, source=entity.key,
                note=str(entity.attributes.get("provider") or "cloud storage")))

    return handoff


def to_dict(handoff: Handoff) -> dict[str, Any]:
    return {
        "format": FORMAT,
        "notice": handoff.notice,
        "package": handoff.package,
        "project": handoff.project_name,
        "sha256": handoff.sha256,
        "authorization": {"ref": handoff.authorization_ref,
                          "by": handoff.authorized_by},
        "generated_at": handoff.generated_at,
        # First, because it is the field that decides what gets touched.
        "scope_domains": list(handoff.scope_domains),
        "seeds": [asdict(s) for s in sorted(
            handoff.seeds, key=lambda s: (s.type, s.value))],
    }


def write(handoff: Handoff, path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(to_dict(handoff), indent=2, sort_keys=False) + "\n",
        encoding="utf-8")
    return target


# --------------------------------------------------------------- coming back

@dataclass
class HostFacts:
    """What TOPRECON established about one host."""

    host: str
    addresses: list[str] = field(default_factory=list)
    ports: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    risk: str | None = None
    risk_reason: str = ""

    def as_attributes(self) -> dict[str, Any]:
        return {"recon": {
            "addresses": self.addresses[:20],
            "ports": self.ports[:40],
            "services": self.services[:40],
            "technologies": self.technologies[:40],
            "risk": self.risk,
            "risk_reason": self.risk_reason[:500],
        }}


@dataclass
class ImportReport:
    """What came back, and what could not be matched to anything themob has."""

    hosts_read: int = 0
    enriched: int = 0
    unmatched: list[str] = field(default_factory=list)
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error

    @property
    def summary(self) -> str:
        if self.error:
            return f"the recon results could not be read: {self.error}"
        return (f"{self.hosts_read} host(s) read, {self.enriched} endpoint(s) "
                f"enriched, {len(self.unmatched)} unmatched")


def _host_of(node: dict) -> str:
    """The host a TOPRECON node is about, whatever type it is."""
    value = str(node.get("value") or "").strip().lower()
    if not value:
        return ""
    if "://" in value:
        return (urlsplit(value).hostname or "").lower()
    return value.split("/")[0].split(":")[0]


def read_results(path: str | Path) -> tuple[dict[str, HostFacts], str]:
    """Parse a TOPRECON export. Everything in it is treated as untrusted.

    It is a file from another program that talked to the internet, so every
    field is checked rather than assumed, and a malformed document returns an
    error instead of a half-applied import.
    """
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {}, f"{type(exc).__name__}: {exc}"
    if not isinstance(document, dict):
        return {}, "the export is not a JSON object"

    graph = document.get("graph")
    nodes = graph.get("nodes") if isinstance(graph, dict) else None
    if not isinstance(nodes, list):
        return {}, "the export carries no graph nodes"

    facts: dict[str, HostFacts] = {}
    for node in nodes[:20_000]:
        if not isinstance(node, dict):
            continue
        host = _host_of(node)
        if not host:
            continue
        entry = facts.setdefault(host, HostFacts(host=host))
        etype = str(node.get("type") or "")
        data = node.get("data") if isinstance(node.get("data"), dict) else {}

        if etype == "ip":
            _add(entry.addresses, str(node.get("value") or ""))
        elif etype == "port":
            _add(entry.ports, str(node.get("value") or ""))
        elif etype == "service":
            _add(entry.services, str(node.get("value") or ""))
        elif etype == "web_tech":
            _add(entry.technologies, str(node.get("value") or ""))

        for key in ("ip", "address", "resolved"):
            value = data.get(key)
            if isinstance(value, str):
                _add(entry.addresses, value)
            elif isinstance(value, list):
                for item in value[:20]:
                    _add(entry.addresses, str(item))

        risk = node.get("risk")
        if isinstance(risk, str) and risk and entry.risk is None:
            entry.risk = risk
            entry.risk_reason = str(node.get("risk_reason") or "")
    return facts, ""


def _add(target: list[str], value: str) -> None:
    value = value.strip()[:200]
    if value and value not in target and len(target) < 100:
        target.append(value)


def apply(repos: Repositories, project_id: str, snapshot: GraphSnapshot,
          path: str | Path) -> ImportReport:
    """Fold TOPRECON's results onto the endpoints themob already has.

    Enriching what exists rather than adding nodes: the locked model has no
    entity type for an address or a certificate, and "this endpoint resolves
    here and runs these services" is a property of the endpoint anyway.
    """
    facts, error = read_results(path)
    report = ImportReport(hosts_read=len(facts), error=error)
    if error:
        return report

    matched: set[str] = set()
    for entity in snapshot.of_type(EntityType.ENDPOINT):
        host = str(entity.attributes.get("host") or "").strip().lower()
        known = facts.get(host)
        if known is None:
            continue
        matched.add(host)
        repos.entities.upsert(project_id, Entity(
            type=EntityType.ENDPOINT, platform=entity.platform,
            key=entity.key, label=entity.label,
            attributes=known.as_attributes()))
        report.enriched += 1

    report.unmatched = sorted(set(facts) - matched)[:200]
    logger.info("toprecon handoff: %s", report.summary)
    return report
