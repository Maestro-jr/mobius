"""The TOPRECON handoff, where a mistake stops being a wrong finding.

themob learns every host a package contacts. TOPRECON maps infrastructure, and
actively probes it when told to. So the tests that matter here are not about
completeness: they are about scope. An app talks to its backend and to six
companies the client has no authority over, and nothing in the package says
which is which, so the handoff must refuse to decide and must say that it is
refusing.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from themob.correlate.graph import build_snapshot
from themob.handoff import toprecon
from themob.model.entities import Entity
from themob.model.enums import EntityType, Platform
from themob.storage.repositories import Project, Repositories


PKG = "com.example.shop"


@pytest.fixture()
def project(repos: Repositories) -> Project:
    stored = repos.projects.create(Project(
        name="Example Shop", target_platform=Platform.ANDROID,
        source_path="input/shop.apk", source_sha256="a" * 64))
    repos.projects.set_authorization(stored.id, ref="ENG-42", by="tester@lab")
    return repos.projects.get(stored.id)


def _entity(repos, project, etype, key, **attrs) -> Entity:
    return repos.entities.upsert(project.id, Entity(
        type=etype, platform=Platform.ANDROID, key=key,
        label=key, attributes=attrs))


@pytest.fixture()
def graph(repos: Repositories, project: Project):
    """An app that talks to its own backend and to four other people's."""
    _entity(repos, project, EntityType.APP, PKG, package=PKG)
    _entity(repos, project, EntityType.ENDPOINT, "https://api.example.com/v1/orders",
            host="api.example.com", scheme="https", cleartext=False)
    _entity(repos, project, EntityType.ENDPOINT, "http://legacy.example.com/sync",
            host="legacy.example.com", scheme="http", cleartext=True)
    _entity(repos, project, EntityType.ENDPOINT,
            "https://graph.facebook.com/v12/me", host="graph.facebook.com")
    _entity(repos, project, EntityType.ENDPOINT,
            "https://firebase.googleapis.com/x", host="firebase.googleapis.com")
    _entity(repos, project, EntityType.ENDPOINT, "http://192.168.1.10/debug",
            host="192.168.1.10", private=True)
    _entity(repos, project, EntityType.CLOUD_ASSET, "s3:shop-uploads",
            provider="aws", bucket="shop-uploads", host="s3.amazonaws.com")
    return build_snapshot(repos, project.id)


# --------------------------------------------------------------------- scope

def test_nothing_is_in_scope_until_a_human_says_so(graph, project) -> None:
    """The single most important property of this module."""
    handoff = toprecon.build(graph, project)
    assert handoff.scope_domains == []

    document = toprecon.to_dict(handoff)
    assert document["scope_domains"] == []


def test_the_document_says_it_is_not_an_authorization(graph, project) -> None:
    """A reader must not be able to mistake this list for permission."""
    document = toprecon.to_dict(toprecon.build(graph, project))
    notice = document["notice"].lower()
    assert "does not know who owns" in notice
    assert "never an authorization" in notice
    assert "scope_domains is" in notice


def test_the_attestation_travels_with_the_handoff(graph, project) -> None:
    document = toprecon.to_dict(toprecon.build(graph, project))
    assert document["authorization"]["ref"] == "ENG-42"
    assert document["authorization"]["by"] == "tester@lab"
    assert document["sha256"] == "a" * 64


def test_a_third_party_host_is_never_a_first_party_candidate(graph,
                                                             project) -> None:
    """A shopping app contacting Facebook does not make Facebook in scope."""
    handoff = toprecon.build(graph, project)
    candidates = {s.value for s in handoff.candidates}

    assert "facebook.com" not in candidates
    assert "googleapis.com" not in candidates
    assert "amazonaws.com" not in candidates


def test_the_apps_own_apex_is_a_candidate_and_only_a_candidate(graph,
                                                               project) -> None:
    handoff = toprecon.build(graph, project)
    candidates = {s.value for s in handoff.candidates}

    assert "example.com" in candidates
    # A candidate still is not scope.
    assert handoff.scope_domains == []


def test_a_private_address_is_not_handed_over(graph, project) -> None:
    """It is somebody's LAN, not an internet asset."""
    values = {s.value for s in toprecon.build(graph, project).seeds}
    assert "192.168.1.10" not in values


# --------------------------------------------------------------------- seeds

def test_the_package_seeds_the_run(graph, project) -> None:
    seeds = toprecon.build(graph, project).seeds
    app = next(s for s in seeds if s.type == toprecon.TR_MOBILE_APP)
    assert app.value == PKG


def test_every_contacted_apex_is_offered_for_review(graph, project) -> None:
    domains = {s.value for s in toprecon.build(graph, project).seeds
               if s.type == toprecon.TR_DOMAIN}
    assert {"example.com", "facebook.com", "googleapis.com"} <= domains


def test_a_cleartext_endpoint_is_flagged_on_the_way_out(graph, project) -> None:
    urls = {s.value: s for s in toprecon.build(graph, project).seeds
            if s.type == toprecon.TR_URL}
    assert urls["http://legacy.example.com/sync"].cleartext
    assert not urls["https://api.example.com/v1/orders"].cleartext


def test_a_cloud_bucket_travels_as_a_bucket(graph, project) -> None:
    buckets = {s.value for s in toprecon.build(graph, project).seeds
               if s.type == toprecon.TR_CLOUD_BUCKET}
    assert "shop-uploads" in buckets


def test_the_export_is_stable(graph, project, tmp_path: Path) -> None:
    """Two exports of one project must diff cleanly."""
    first = toprecon.to_dict(toprecon.build(graph, project))
    second = toprecon.to_dict(toprecon.build(graph, project))
    for document in (first, second):
        document["generated_at"] = ""
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_writing_produces_a_readable_document(graph, project,
                                              tmp_path: Path) -> None:
    path = toprecon.write(toprecon.build(graph, project),
                          tmp_path / "out" / "handoff.json")
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["format"] == toprecon.FORMAT
    assert document["package"] == PKG


# ------------------------------------------------------------------- and back

def _recon_export(path: Path, nodes: list[dict]) -> Path:
    path.write_text(json.dumps({
        "tool": "TOP RECON", "generated": 1.0, "meta": {},
        "graph": {"seed": "domain:example.com", "nodes": nodes, "edges": []},
        "findings": [],
    }), encoding="utf-8")
    return path


def test_results_enrich_the_endpoint_that_already_exists(
        repos, project, graph, tmp_path: Path) -> None:
    # A node is matched by the host in its own value, so an address TOPRECON
    # resolved travels in the domain node's data rather than as a bare ip node
    # that names no host.
    path = _recon_export(tmp_path / "recon.json", [
        {"type": "domain", "value": "api.example.com",
         "data": {"ip": ["203.0.113.10"]}, "risk": "medium",
         "risk_reason": "expired certificate"},
        {"type": "web_tech", "value": "api.example.com",
         "data": {"tech": "nginx"}, "risk": None},
    ])

    report = toprecon.apply(repos, project.id, graph, path)
    assert report.ok, report.error
    assert report.enriched == 1

    after = build_snapshot(repos, project.id)
    endpoint = next(e for e in after.of_type(EntityType.ENDPOINT)
                    if e.attributes.get("host") == "api.example.com")
    recon = endpoint.attributes["recon"]
    assert "203.0.113.10" in recon["addresses"]
    assert recon["risk"] == "medium"


def test_reimporting_converges_instead_of_duplicating(
        repos, project, graph, tmp_path: Path) -> None:
    """The keys are the ones themob already assigned, so the upsert merges."""
    path = _recon_export(tmp_path / "recon.json", [
        {"type": "domain", "value": "api.example.com",
         "data": {"ip": ["203.0.113.10"]}, "risk": "low", "risk_reason": ""},
    ])
    before = len(build_snapshot(repos, project.id))

    toprecon.apply(repos, project.id, graph, path)
    toprecon.apply(repos, project.id, build_snapshot(repos, project.id), path)

    assert len(build_snapshot(repos, project.id)) == before


def test_a_host_themob_never_saw_is_reported_not_added(
        repos, project, graph, tmp_path: Path) -> None:
    """Recon finds more than the app calls; that does not become app surface."""
    path = _recon_export(tmp_path / "recon.json", [
        {"type": "domain", "value": "vpn.example.com", "data": {}, "risk": None},
    ])
    before = len(build_snapshot(repos, project.id))

    report = toprecon.apply(repos, project.id, graph, path)
    assert "vpn.example.com" in report.unmatched
    assert len(build_snapshot(repos, project.id)) == before


def test_a_malformed_export_fails_without_half_importing(
        repos, project, graph, tmp_path: Path) -> None:
    """It is a file from a program that talked to the internet."""
    for content in ("not json at all", "[]", '{"graph": {}}',
                    '{"graph": {"nodes": "not a list"}}'):
        path = tmp_path / "bad.json"
        path.write_text(content, encoding="utf-8")
        report = toprecon.apply(repos, project.id, graph, path)
        assert not report.ok, content
        assert report.enriched == 0


def test_a_missing_export_is_an_error_not_a_crash(repos, project, graph,
                                                  tmp_path: Path) -> None:
    report = toprecon.apply(repos, project.id, graph, tmp_path / "absent.json")
    assert not report.ok
    assert "error" not in report.summary.lower() or report.error


def test_hostile_node_content_cannot_crash_the_import(
        repos, project, graph, tmp_path: Path) -> None:
    path = _recon_export(tmp_path / "recon.json", [
        "not a dict", 42, None, {},
        {"type": "domain", "value": "x" * 5000, "data": {"ip": ["y" * 5000]}},
        {"type": "domain", "value": "api.example.com", "data": {"ip": "z" * 900}},
    ])
    report = toprecon.apply(repos, project.id, graph, path)
    assert report.ok, report.error

    after = build_snapshot(repos, project.id)
    endpoint = next(e for e in after.of_type(EntityType.ENDPOINT)
                    if e.attributes.get("host") == "api.example.com")
    for address in endpoint.attributes["recon"]["addresses"]:
        assert len(address) <= 200
