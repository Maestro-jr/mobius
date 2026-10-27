"""Sections, pivots and the TOPRECON handoff.

The pivot tests are the ones that matter. An app's attack surface is not its
findings, it is the findings something else on the device can reach, and nothing
before this module could tell a hardcoded key used by an internal class from the
same key reachable through an exported Activity. Both are HIGH in a severity
table; only one of them gets exploited.
"""
from __future__ import annotations

import pytest

from themob.correlate import (SECTIONS, GraphSnapshot, attack_paths,
                              build_handoff, entry_points, exposed_findings,
                              exposure, project, section_for_entity)
from themob.model.entities import Edge, Entity
from themob.model.enums import EdgeType, EntityType, Platform, Severity
from themob.model.findings import Finding, FindingSource

PKG = "com.example.shop"


def _entity(etype: EntityType, key: str, **attrs) -> Entity:
    return Entity(type=etype, platform=Platform.ANDROID, key=key,
                  label=key.rsplit(".", 1)[-1], attributes=attrs)


def _finding(weakness: str, severity: Severity, *entity_ids: str) -> Finding:
    return Finding(
        fingerprint=weakness + ":" + ":".join(entity_ids),
        weakness_key=weakness, title=weakness, severity=severity,
        entity_ids=list(entity_ids),
        sources=[FindingSource(tool="test", rule=weakness)])


@pytest.fixture()
def app_graph():
    """An app with one open door, one closed one, and a secret behind each."""
    app = _entity(EntityType.APP, PKG, package=PKG)
    exported = _entity(EntityType.COMPONENT, f"{PKG}.PublicActivity",
                       kind="activity", exported=True)
    internal = _entity(EntityType.COMPONENT, f"{PKG}.InternalWorker",
                       kind="service", exported=False)
    reachable_secret = _entity(EntityType.SECRET, "sha256:reachable")
    buried_secret = _entity(EntityType.SECRET, "sha256:buried")
    endpoint = _entity(EntityType.ENDPOINT, "https://api.example.com/v1",
                       host="api.example.com", scheme="https", path="/v1",
                       cleartext=False, private=False)
    bucket = _entity(EntityType.CLOUD_ASSET, "aws-s3:shop-uploads",
                     provider="aws-s3", bucket="shop-uploads",
                     host="shop-uploads.s3.amazonaws.com")

    entities = [app, exported, internal, reachable_secret, buried_secret,
                endpoint, bucket]
    edges = [
        Edge(src_id=app.id, dst_id=exported.id, type=EdgeType.EXPORTS),
        Edge(src_id=app.id, dst_id=internal.id, type=EdgeType.DECLARES),
        Edge(src_id=exported.id, dst_id=reachable_secret.id, type=EdgeType.USES),
        Edge(src_id=internal.id, dst_id=buried_secret.id, type=EdgeType.USES),
        Edge(src_id=exported.id, dst_id=endpoint.id, type=EdgeType.TALKS_TO),
        Edge(src_id=app.id, dst_id=bucket.id, type=EdgeType.USES),
    ]
    snapshot = GraphSnapshot(project_id="p", entities=entities, edges=edges,
                             root_id=app.id)
    return snapshot, {
        "app": app, "exported": exported, "internal": internal,
        "reachable": reachable_secret, "buried": buried_secret,
        "endpoint": endpoint, "bucket": bucket,
    }


# ------------------------------------------------------------------ sections

def test_every_entity_type_belongs_to_exactly_one_section() -> None:
    """A type in two sections would double-count every finding on it.

    The module refuses to import in that case; this asserts the other half,
    that nothing is left without a home.
    """
    for etype in EntityType:
        assert section_for_entity(etype) is not None, f"{etype.value} has no section"


def test_a_finding_lands_in_the_section_of_what_it_is_about(app_graph) -> None:
    """Not the section of the tool that found it.

    A hardcoded key is a Secrets finding whether semgrep or gitleaks noticed
    it. Grouping by reporting stage would scatter one class of issue across the
    nav, which is exactly what a tester does not want.
    """
    snapshot, nodes = app_graph
    findings = [_finding("android.secrets.service-api-key", Severity.HIGH,
                         nodes["reachable"].id)]
    views = {v.key: v for v in project(snapshot, findings)}
    assert len(views["secrets"].findings) == 1
    assert views["network"].findings == []


def test_a_finding_is_counted_once_across_all_sections(app_graph) -> None:
    """So a total across sections is a real total."""
    snapshot, nodes = app_graph
    findings = [
        _finding("android.secrets.service-api-key", Severity.HIGH,
                 nodes["reachable"].id),
        _finding("android.config.debuggable", Severity.HIGH, nodes["app"].id),
        _finding("android.network.cleartext-endpoint", Severity.HIGH,
                 nodes["endpoint"].id),
    ]
    views = project(snapshot, findings)
    assert sum(len(v.findings) for v in views) == len(findings)


def test_an_app_wide_finding_does_not_land_in_reverse_engineering(
        app_graph) -> None:
    """The App node is attached to almost everything, so it must not decide.

    "Application is debuggable" is a manifest judgement and belongs with the
    platform surface, not in the code browser.
    """
    snapshot, nodes = app_graph
    findings = [_finding("android.config.debuggable", Severity.HIGH,
                         nodes["app"].id)]
    views = {v.key: v for v in project(snapshot, findings)}
    assert len(views["platform"].findings) == 1
    assert views["code"].findings == []


def test_a_specific_entity_outranks_the_app_node(app_graph) -> None:
    """Findings usually carry the App as well as the thing they are about."""
    snapshot, nodes = app_graph
    findings = [_finding("android.secrets.private-key", Severity.CRITICAL,
                         nodes["app"].id, nodes["reachable"].id)]
    views = {v.key: v for v in project(snapshot, findings)}
    assert len(views["secrets"].findings) == 1


def test_a_section_reports_its_worst_severity(app_graph) -> None:
    """What the nav badge shows."""
    snapshot, nodes = app_graph
    findings = [
        _finding("android.secrets.high-entropy-string", Severity.LOW,
                 nodes["reachable"].id),
        _finding("android.secrets.private-key", Severity.CRITICAL,
                 nodes["buried"].id),
    ]
    views = {v.key: v for v in project(snapshot, findings)}
    assert views["secrets"].worst_severity is Severity.CRITICAL
    assert views["network"].worst_severity is None


def test_an_empty_section_says_so(app_graph) -> None:
    snapshot, _nodes = app_graph
    views = {v.key: v for v in project(snapshot, [])}
    assert views["storage"].is_empty
    assert not views["secrets"].is_empty, "it has entities even with no findings"


def test_the_sections_match_the_plans_left_nav() -> None:
    keys = [s.key for s in SECTIONS]
    assert keys == ["platform", "network", "secrets", "crypto", "storage",
                    "dependencies", "code"]


def test_counts_without_graph_matches_the_full_projection(app_graph) -> None:
    """The live view during a run counts findings per section without building
    the NetworkX graph (that rebuild on the UI thread, racing the engine, was
    a crash). It must agree with project(), or the nav badges would lie until
    the run finished and the full rebuild corrected them."""
    from themob.correlate.sections import counts_without_graph

    snapshot, nodes = app_graph
    findings = [
        _finding("android.secrets.service-api-key", Severity.HIGH,
                 nodes["reachable"].id),
        _finding("android.secrets.private-key", Severity.CRITICAL,
                 nodes["buried"].id),
        _finding("android.network.cleartext-endpoint", Severity.HIGH,
                 nodes["endpoint"].id),
        _finding("android.config.debuggable", Severity.HIGH, nodes["app"].id),
    ]
    live = counts_without_graph(snapshot.entities, findings)
    full = {v.key: len(v.findings) for v in project(snapshot, findings)}
    assert live == full
    # And it really did place them, not just agree on zeroes.
    assert live["secrets"] == 2
    assert live["network"] == 1
    assert live["platform"] == 1


# -------------------------------------------------------------------- pivots

def test_entry_points_are_the_doors_into_the_app(app_graph) -> None:
    snapshot, nodes = app_graph
    ids = {e.id for e in entry_points(snapshot)}
    assert nodes["exported"].id in ids
    assert nodes["internal"].id not in ids, "a non-exported service is not a door"


def test_a_guarded_component_is_still_an_entry_point() -> None:
    """A permission narrows who may knock; it does not remove the door.

    Treating it as closed would hide the case where the guarding permission is
    itself weak, which is a finding the config auditor already raises.
    """
    guarded = _entity(EntityType.COMPONENT, f"{PKG}.Guarded", kind="receiver",
                      exported=True, permission=f"{PKG}.permission.SYNC")
    snapshot = GraphSnapshot(project_id="p", entities=[guarded], edges=[],
                             root_id=guarded.id)
    assert [e.id for e in entry_points(snapshot)] == [guarded.id]


def test_a_secret_behind_an_exported_component_is_exposed(app_graph) -> None:
    """The question the whole module exists to answer."""
    snapshot, nodes = app_graph
    reached = exposure(snapshot, nodes["reachable"].id)
    assert reached.reachable is True
    assert reached.entry_point_id == nodes["exported"].id
    assert reached.hops == 1


def test_a_secret_behind_an_internal_component_is_not(app_graph) -> None:
    """Same severity, different exposure. This is the distinction that matters.

    The route exists through the App node, but only by walking *out* of the
    exported component and back down an unrelated branch, which is not what
    "an attacker reaches this" means.
    """
    snapshot, nodes = app_graph
    reached = exposure(snapshot, nodes["buried"].id)
    assert reached.reachable is False


def test_an_entry_point_is_exposed_to_itself(app_graph) -> None:
    snapshot, nodes = app_graph
    reached = exposure(snapshot, nodes["exported"].id)
    assert reached.reachable and reached.hops == 0


def test_exposure_of_an_unknown_entity_is_not_reachable(app_graph) -> None:
    snapshot, _nodes = app_graph
    assert exposure(snapshot, "no-such-id").reachable is False


def test_an_app_with_no_exported_surface_exposes_nothing() -> None:
    app = _entity(EntityType.APP, PKG)
    secret = _entity(EntityType.SECRET, "sha256:x")
    snapshot = GraphSnapshot(
        project_id="p", entities=[app, secret],
        edges=[Edge(src_id=app.id, dst_id=secret.id, type=EdgeType.USES)],
        root_id=app.id)
    assert entry_points(snapshot) == []
    assert exposure(snapshot, secret.id).reachable is False


def test_attack_paths_rank_reachable_findings_first(app_graph) -> None:
    snapshot, nodes = app_graph
    findings = [
        _finding("android.secrets.private-key", Severity.CRITICAL,
                 nodes["buried"].id),          # worse, but not reachable
        _finding("android.secrets.service-api-key", Severity.HIGH,
                 nodes["reachable"].id),       # reachable
    ]
    paths = attack_paths(snapshot, findings)
    assert len(paths) == 1, "only the reachable finding is an attack path"
    assert paths[0].finding.weakness_key == "android.secrets.service-api-key"


def test_an_attack_path_can_be_shown_not_just_asserted(app_graph) -> None:
    """A tester has to be able to see the route, or it is a claim."""
    snapshot, nodes = app_graph
    findings = [_finding("android.secrets.service-api-key", Severity.HIGH,
                         nodes["reachable"].id)]
    described = attack_paths(snapshot, findings)[0].describe()
    assert "PublicActivity" in described and "->" in described


def test_a_finding_on_many_entities_appears_once(app_graph) -> None:
    """Via its most exposed entity, not once per node it touches."""
    snapshot, nodes = app_graph
    findings = [_finding("android.secrets.service-api-key", Severity.HIGH,
                         nodes["reachable"].id, nodes["endpoint"].id,
                         nodes["app"].id)]
    paths = attack_paths(snapshot, findings)
    assert len(paths) == 1


def test_attack_paths_sort_by_severity_then_directness(app_graph) -> None:
    snapshot, nodes = app_graph
    findings = [
        _finding("android.secrets.service-api-key", Severity.MEDIUM,
                 nodes["reachable"].id),
        _finding("android.network.cleartext-endpoint", Severity.CRITICAL,
                 nodes["endpoint"].id),
    ]
    paths = attack_paths(snapshot, findings)
    assert [p.severity for p in paths] == [Severity.CRITICAL, Severity.MEDIUM]


def test_exposed_findings_is_the_cheap_form(app_graph) -> None:
    snapshot, nodes = app_graph
    reachable = _finding("android.secrets.service-api-key", Severity.HIGH,
                         nodes["reachable"].id)
    buried = _finding("android.secrets.private-key", Severity.HIGH,
                      nodes["buried"].id)
    assert exposed_findings(snapshot, [reachable, buried]) == {reachable.fingerprint}


# ------------------------------------------------------------------- handoff

def test_the_handoff_groups_by_host_not_by_url(app_graph) -> None:
    """A recon engine works per host; forty URLs on one host is one target."""
    snapshot, nodes = app_graph
    extra = _entity(EntityType.ENDPOINT, "https://api.example.com/v2",
                    host="api.example.com", scheme="https", path="/v2")
    snapshot = GraphSnapshot(project_id="p",
                             entities=snapshot.entities + [extra],
                             edges=snapshot.edges, root_id=nodes["app"].id)

    document = build_handoff(snapshot)
    hosts = {h["host"]: h for h in document["hosts"]}
    assert "api.example.com" in hosts
    assert sorted(hosts["api.example.com"]["paths"]) == ["/v1", "/v2"]


def test_the_handoff_carries_the_app_identity(app_graph) -> None:
    """So results can be attributed to the package they came from."""
    snapshot, _nodes = app_graph
    assert build_handoff(snapshot)["app"]["package"] == PKG


def test_a_private_address_is_marked_rather_than_dropped() -> None:
    """Scanning it from elsewhere reaches a different machine, or nothing.

    It is still exported: a release build addressing a developer's laptop is a
    real finding, and dropping it here would hide it.
    """
    app = _entity(EntityType.APP, PKG)
    dev = _entity(EntityType.ENDPOINT, "http://192.168.1.10:3000/api",
                  host="192.168.1.10", scheme="http", path="/api",
                  cleartext=True, private=True)
    snapshot = GraphSnapshot(
        project_id="p", entities=[app, dev],
        edges=[Edge(src_id=app.id, dst_id=dev.id, type=EdgeType.TALKS_TO)],
        root_id=app.id)

    host = build_handoff(snapshot)["hosts"][0]
    assert host["private"] is True and host["cleartext"] is True


def test_cloud_assets_travel_with_their_provider(app_graph) -> None:
    snapshot, _nodes = app_graph
    hosts = {h["host"]: h for h in build_handoff(snapshot)["hosts"]}
    bucket = hosts["shop-uploads.s3.amazonaws.com"]
    assert bucket["cloud_provider"] == "aws-s3"
    assert bucket["buckets"] == ["shop-uploads"]


def test_what_themob_already_knows_travels_too(app_graph) -> None:
    """So the recon engine does not spend a scan re-confirming it."""
    snapshot, nodes = app_graph
    findings = [_finding("android.network.cleartext-endpoint", Severity.HIGH,
                         nodes["endpoint"].id)]
    known = build_handoff(snapshot, findings)["known_issues"]
    assert known == [{"host": "api.example.com",
                      "weaknesses": ["android.network.cleartext-endpoint"]}]


def test_the_handoff_is_byte_stable(app_graph) -> None:
    """Two exports of one project must be diffable against each other."""
    import json

    snapshot, _nodes = app_graph
    first = json.dumps(build_handoff(snapshot), sort_keys=True)
    second = json.dumps(build_handoff(snapshot), sort_keys=True)
    assert first == second


def test_an_app_with_no_backend_exports_an_empty_document() -> None:
    app = _entity(EntityType.APP, PKG)
    snapshot = GraphSnapshot(project_id="p", entities=[app], edges=[],
                             root_id=app.id)
    document = build_handoff(snapshot)
    assert document["hosts"] == []
    assert document["counts"]["hosts"] == 0
    assert document["format"], "the format tag is what makes it readable later"


def test_the_app_node_is_not_a_conduit(app_graph) -> None:
    """The bug that made the first version of this module useless.

    Every entity hangs off the App, so treating edges as undirected let a
    traversal walk up from any exported component into the App and back down
    into every unrelated branch. Everything came out "exposed", which is the
    same as nothing being exposed.
    """
    snapshot, nodes = app_graph
    entries = entry_points(snapshot)
    reached = {e.id for e in snapshot.entities
               if exposure(snapshot, e.id, entries).reachable}

    assert nodes["app"].id not in reached, "the App is above the doors, not behind one"
    assert nodes["internal"].id not in reached
    assert nodes["buried"].id not in reached
    assert nodes["reachable"].id in reached


def test_a_deep_link_reaches_what_its_component_reaches() -> None:
    """A deep link is a route, not a place.

    themob records it as ``Activity --declares--> DeepLink``, so descending
    from the link itself reaches nothing. The traversal has to start at the
    component the link routes into.
    """
    app = _entity(EntityType.APP, PKG)
    activity = _entity(EntityType.COMPONENT, f"{PKG}.LinkActivity",
                       kind="activity", exported=True)
    link = _entity(EntityType.DEEP_LINK, "https://shop.example.com/order",
                   scheme="https", host="shop.example.com")
    secret = _entity(EntityType.SECRET, "sha256:behind-the-link")
    snapshot = GraphSnapshot(
        project_id="p", entities=[app, activity, link, secret],
        edges=[
            Edge(src_id=app.id, dst_id=activity.id, type=EdgeType.EXPORTS),
            Edge(src_id=activity.id, dst_id=link.id, type=EdgeType.DECLARES),
            Edge(src_id=activity.id, dst_id=secret.id, type=EdgeType.USES),
        ],
        root_id=app.id)

    assert link.id in {e.id for e in entry_points(snapshot)}
    # Reachable through the activity, using only the deep link as the door.
    reached = exposure(snapshot, secret.id, entries=[link])
    assert reached.reachable is True
    assert reached.entry_point_id == activity.id
