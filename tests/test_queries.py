"""Saved queries: the questions a tester asks twice.

The interesting tests here are the ones about being wrong in the safe
direction. A query that silently broadens is worse than one that errors:
"exported components with no permission" quietly becoming "every component"
turns a finding list into noise, and nobody notices because it still returns
rows.
"""
from __future__ import annotations

import json

import pytest

from themob.correlate import queries
from themob.correlate.graph import build_snapshot
from themob.correlate.queries import (Attribute, Query, QueryError, from_json,
                                      to_json)
from themob.model.entities import Edge, Entity
from themob.model.enums import (EdgeType, EntityType, Platform, Severity)
from themob.model.findings import Finding, FindingSource
from themob.storage.repositories import (Project, RepositoryError,
                                         Repositories)

PKG = "com.example.shop"


@pytest.fixture()
def project(repos: Repositories) -> Project:
    stored = repos.projects.create(Project(
        name="Example Shop", target_platform=Platform.ANDROID,
        source_path="input/shop.apk", source_sha256="a" * 64))
    return repos.projects.get(stored.id)


def _entity(repos, project, etype, key, **attrs) -> Entity:
    return repos.entities.upsert(project.id, Entity(
        type=etype, platform=Platform.ANDROID, key=key,
        label=key.rsplit(".", 1)[-1], attributes=attrs))


@pytest.fixture()
def world(repos: Repositories, project: Project):
    """A small app with the shapes the builtin questions are about."""
    app = _entity(repos, project, EntityType.APP, PKG, package=PKG)
    door = _entity(repos, project, EntityType.COMPONENT, f"{PKG}.Public",
                   kind="activity", exported=True)
    guarded = _entity(repos, project, EntityType.COMPONENT, f"{PKG}.Guarded",
                      kind="activity", exported=True,
                      permission="com.example.shop.PRIVATE")
    internal = _entity(repos, project, EntityType.COMPONENT, f"{PKG}.Internal",
                       kind="activity", exported=False)
    secret = _entity(repos, project, EntityType.SECRET, "sha256:abcd",
                     preview="AKIA****")
    buried = _entity(repos, project, EntityType.SECRET, "sha256:beef",
                     preview="hunter2*")
    plain = _entity(repos, project, EntityType.ENDPOINT, "http://api.example.com/x",
                    host="api.example.com", cleartext=True)
    secure = _entity(repos, project, EntityType.ENDPOINT,
                     "https://api.example.com/y", host="api.example.com",
                     cleartext=False)
    perm = _entity(repos, project, EntityType.PERMISSION,
                   "android.permission.READ_SMS", protection="dangerous")
    normal = _entity(repos, project, EntityType.PERMISSION,
                     "android.permission.INTERNET", protection="normal")
    lib = _entity(repos, project, EntityType.LIBRARY, "okhttp", version="3.12.1")

    for src, dst, kind in ((app, door, EdgeType.EXPORTS),
                           (app, guarded, EdgeType.EXPORTS),
                           (app, internal, EdgeType.DECLARES),
                           (door, secret, EdgeType.USES),
                           (door, plain, EdgeType.CALLS),
                           (internal, buried, EdgeType.USES),
                           (app, lib, EdgeType.EMBEDS),
                           (app, perm, EdgeType.REQUESTS_PERMISSION),
                           (app, normal, EdgeType.REQUESTS_PERMISSION)):
        repos.edges.upsert(project.id, Edge(src_id=src.id, dst_id=dst.id,
                                            type=kind))

    repos.findings.upsert(project.id, Finding(
        fingerprint="a" * 64, weakness_key="android.secrets.cloud-credential",
        title="Cloud credential", severity=Severity.CRITICAL, confidence=0.9,
        entity_ids=[secret.id],
        sources=[FindingSource(tool="gitleaks", rule="aws"),
                 FindingSource(tool="apkleaks", rule="AWS")]))
    repos.findings.upsert(project.id, Finding(
        fingerprint="b" * 64, weakness_key="android.dependencies.known-vulnerability",
        title="okhttp advisory", severity=Severity.MEDIUM, confidence=0.8,
        entity_ids=[lib.id],
        sources=[FindingSource(tool="grype", rule="GHSA-x")]))
    repos.findings.upsert(project.id, Finding(
        fingerprint="c" * 64, weakness_key="android.network.cleartext-endpoint",
        title="Cleartext endpoint", severity=Severity.MEDIUM, confidence=0.7,
        entity_ids=[plain.id],
        sources=[FindingSource(tool="endpoint-extract", rule="scheme")]))

    snapshot = build_snapshot(repos, project.id)
    findings = repos.findings.list(project.id)
    return snapshot, findings, {
        "app": app, "door": door, "guarded": guarded, "internal": internal,
        "secret": secret, "buried": buried, "plain": plain, "secure": secure,
        "perm": perm, "lib": lib,
    }


def _run(world, key: str):
    snapshot, findings, _nodes = world
    return queries.run(snapshot, findings, queries.builtin(key))


# ------------------------------------------------------------------- builtins

def test_every_builtin_runs_and_explains_itself(world) -> None:
    snapshot, findings, _ = world
    for query in queries.BUILTINS:
        result = queries.run(snapshot, findings, query)
        assert query.title and query.description, query.key
        assert result.summary


def test_an_exported_component_without_a_permission_is_found(world) -> None:
    keys = {e.key for e in _run(world, "exported-no-permission").entities}
    assert f"{PKG}.Public" in keys
    # Guarded by a permission, and not exported at all: neither is the question.
    assert f"{PKG}.Guarded" not in keys
    assert f"{PKG}.Internal" not in keys


def test_a_reachable_secret_is_separated_from_a_buried_one(world) -> None:
    """The distinction the whole graph exists to make."""
    keys = {e.key for e in _run(world, "reachable-secrets").entities}
    assert "sha256:abcd" in keys
    assert "sha256:beef" not in keys


def test_cleartext_endpoints_exclude_the_secure_one(world) -> None:
    keys = {e.key for e in _run(world, "cleartext-endpoints").entities}
    assert "http://api.example.com/x" in keys
    assert "https://api.example.com/y" not in keys


def test_a_dangerous_permission_is_not_every_permission(world) -> None:
    keys = {e.key for e in _run(world, "dangerous-permissions").entities}
    assert "android.permission.READ_SMS" in keys
    assert "android.permission.INTERNET" not in keys


def test_the_triage_queue_is_the_findings_one_tool_reported(world) -> None:
    result = _run(world, "single-tool-findings")
    titles = {f.title for f in result.findings}
    # Two tools agreed on the credential, so it is not in the triage queue.
    assert "Cloud credential" not in titles
    assert {"okhttp advisory", "Cleartext endpoint"} <= titles


def test_severity_floor_keeps_only_what_clears_it(world) -> None:
    result = _run(world, "critical-anywhere")
    assert {f.severity for f in result.findings} == {Severity.CRITICAL}


# ------------------------------------------------------------------ semantics

def test_an_empty_query_matches_everything(world) -> None:
    snapshot, findings, _ = world
    result = queries.run(snapshot, findings, Query(key="all"))
    assert len(result.matches) == len(snapshot)


def test_clauses_combine_with_and(world) -> None:
    snapshot, findings, _ = world
    both = queries.run(snapshot, findings, Query(
        key="x", entity_types=[EntityType.COMPONENT],
        attributes=[Attribute("exported", "truthy"),
                    Attribute("permission", "missing")]))
    assert {e.key for e in both.entities} == {f"{PKG}.Public"}


def test_an_unset_attribute_is_unknown_not_false(world) -> None:
    """Reporting an unknown as False is how a scanner invents facts."""
    snapshot, findings, nodes = world
    result = queries.run(snapshot, findings, Query(
        key="x", entity_types=[EntityType.COMPONENT],
        attributes=[Attribute("exported", "falsy")]))
    keys = {e.key for e in result.entities}

    assert f"{PKG}.Internal" in keys            # exported is explicitly False
    assert f"{PKG}.Public" not in keys          # explicitly True
    # A secret has no "exported" attribute at all, so it is not an answer here.
    assert "sha256:abcd" not in keys


def test_a_match_says_why_it_matched(world) -> None:
    result = _run(world, "reachable-secrets")
    assert result.matches
    assert any("reachable" in reason for reason in result.matches[0].reasons)


def test_a_pivot_walks_the_graph_from_one_node(world) -> None:
    """The build plan's own example of a pivot."""
    snapshot, findings, nodes = world
    result = queries.run(snapshot, findings,
                         queries.pivot_from(nodes["door"]))
    keys = {e.key for e in result.entities}

    assert {"sha256:abcd", "http://api.example.com/x"} <= keys
    # The buried secret hangs off the internal component, not this door.
    assert "sha256:beef" not in keys


def test_results_are_worst_first(world) -> None:
    snapshot, findings, _ = world
    result = queries.run(snapshot, findings,
                         Query(key="x", has_findings=True))
    severities = [m.worst for m in result.matches if m.worst]
    assert severities == sorted(severities, key=lambda s: -queries._SEVERITY_RANK[s])


def test_a_limit_is_honoured(world) -> None:
    snapshot, findings, _ = world
    result = queries.run(snapshot, findings, Query(key="x", limit=2))
    assert len(result.matches) == 2


def test_a_query_that_cannot_be_expressed_is_refused() -> None:
    for bad in (Query(key="x", limit=0),
                Query(key="x", max_tools=0),
                Query(key="x", attributes=[Attribute("", "truthy")]),
                Query(key="x", attributes=[Attribute("k", "regex")])):
        with pytest.raises(QueryError):
            bad.validate()


# ----------------------------------------------------------------- round trip

def test_every_builtin_survives_a_round_trip() -> None:
    for query in queries.BUILTINS:
        back = from_json(to_json(query))
        assert back.key == query.key
        assert back.entity_types == query.entity_types
        assert back.exposed == query.exposed
        assert back.severity_at_least == query.severity_at_least
        assert back.max_tools == query.max_tools
        assert [(a.key, a.op, a.value) for a in back.attributes] == \
               [(a.key, a.op, a.value) for a in query.attributes]


def test_a_clause_this_version_does_not_understand_is_refused() -> None:
    """Dropping it would answer a broader question than the one saved."""
    payload = json.loads(to_json(queries.builtin("exported-no-permission")))
    payload["not_a_clause_yet"] = True

    with pytest.raises(QueryError, match="broader question"):
        from_json(json.dumps(payload))


def test_a_corrupt_definition_is_refused() -> None:
    for bad in ("not json", "[]", '{"entity_types": ["not_a_type"]}',
                '{"severity_at_least": "catastrophic"}',
                '{"attributes": ["not an object"]}'):
        with pytest.raises(QueryError):
            from_json(bad)


# -------------------------------------------------------------------- storage

def test_a_saved_query_survives_the_session(repos: Repositories, world) -> None:
    snapshot, findings, _ = world
    mine = Query(key="my-question", title="Exported providers",
                 description="the ones I keep checking",
                 entity_types=[EntityType.COMPONENT],
                 attributes=[Attribute("kind", "eq", "provider")])
    repos.queries.save(mine, author="tester@lab")

    loaded = repos.queries.load("my-question")
    assert loaded is not None
    assert loaded.title == "Exported providers"
    assert queries.run(snapshot, findings, loaded).summary


def test_saving_twice_updates_rather_than_duplicates(repos: Repositories) -> None:
    repos.queries.save(Query(key="k", title="First"))
    repos.queries.save(Query(key="k", title="Second"))

    listed = repos.queries.list()
    assert len(listed) == 1
    assert listed[0].title == "Second"


def test_a_saved_query_cannot_shadow_a_builtin(repos: Repositories) -> None:
    """It would silently change what the builtin does."""
    with pytest.raises(RepositoryError, match="built-in"):
        repos.queries.save(Query(key="exported-no-permission", title="Mine"))


def test_a_query_with_no_key_is_refused(repos: Repositories) -> None:
    with pytest.raises(RepositoryError, match="needs a key"):
        repos.queries.save(Query(key="  ", title="Nameless"))


def test_a_corrupt_row_is_reported_not_silently_skipped(
        repos: Repositories) -> None:
    """"Your saved query is corrupt" is an answer; returning nothing is not."""
    repos.queries.save(Query(key="k", title="Fine"))
    repos.db.execute("UPDATE saved_queries SET definition = ? WHERE key = ?",
                     ("{ not json", "k"))

    with pytest.raises(RepositoryError, match="could not be read"):
        repos.queries.load("k")


def test_deleting_removes_it(repos: Repositories) -> None:
    repos.queries.save(Query(key="k", title="Fine"))
    repos.queries.delete("k")
    assert repos.queries.load("k") is None
    assert repos.queries.list() == []


def test_an_unknown_query_is_none_not_an_error(repos: Repositories) -> None:
    assert repos.queries.load("never-saved") is None
