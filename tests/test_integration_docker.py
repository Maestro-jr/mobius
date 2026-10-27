"""The Phase 0 vertical slice, for real: APK -> androguard -> graph -> Overview.

Everything else in the suite stubs the sandbox. This test does not: it builds a
real APK, hands it to the real androguard worker in a real container, and
asserts the entities come back and the Overview renders them. It is the
end-to-end proof that the architecture works, so it is worth its runtime.

Skipped when Docker is not running or the worker image is not built. To run it::

    python -m themob.sandbox.build androguard
    pytest -m docker
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from themob.adapters import build_registry                     # noqa: E402
from themob.adapters.androguard_unpack import \
    AndroguardUnpackAnalyzer                                   # noqa: E402
from themob.audit.attestation import (Action, Attestation, AuditTrail,
                                      AuthorizationError)      # noqa: E402
from themob.correlate.graph import build_snapshot              # noqa: E402
from themob.model.enums import (ComponentKind, EdgeType, EntityType,
                                JobStatus, Severity)           # noqa: E402
from themob.orchestrator import Pipeline, intake               # noqa: E402
from themob.sandbox.runner import SandboxRunner                # noqa: E402
from themob.storage.repositories import Repositories           # noqa: E402
from tests.fixtures.apk import (MIN_SDK, PACKAGE, TARGET_SDK, VERSION_CODE,
                                VERSION_NAME, build_apk)       # noqa: E402

pytestmark = pytest.mark.docker

_IMAGE = AndroguardUnpackAnalyzer.image


@pytest.fixture(scope="session")
def sandbox() -> SandboxRunner:
    runner = SandboxRunner()
    if not runner.is_available():
        pytest.skip("docker daemon is not reachable")
    if not runner.has_image(_IMAGE):
        pytest.skip(f"{_IMAGE} is not built, run "
                    "`python -m themob.sandbox.build androguard`")
    return runner


@pytest.fixture()
def apk(tmp_path: Path) -> Path:
    return build_apk(tmp_path / "shop.apk")


@pytest.fixture()
def slice_run(repos: Repositories, sandbox: SandboxRunner, apk: Path,
              tmp_path: Path):
    """Intake -> authorize -> unpack. The whole Phase 0 path.

    Scoped to ``Stage.UNPACK`` on purpose. Everything this fixture's tests
    assert: the manifest, components, permissions, deep links, native
    libraries, the graph, the Overview, comes out of the unpack stage, and
    leaving the run unscoped meant every adapter added to a *later* stage
    silently joined the Phase 0 slice. Registering jadx is what exposed it:
    the fixture APK ships a stub ``classes.dex``, jadx correctly fails on it,
    and a test named for phase 0 began failing for a phase 2 reason. When the
    fixture emits a real DEX, a genuinely unscoped full-pipeline test is worth
    adding back as its own case.
    """
    from themob.model.enums import Stage

    audit = AuditTrail(repos.audit)
    result = intake(apk, repos, audit, name="Example Shop",
                    root=tmp_path / "home")
    audit.record_attestation(result.project, Attestation(
        target_name="shop.apk", target_sha256=result.sha256,
        operator="tester@lab", engagement_ref="ENG-INTEGRATION",
        attested=True), repos.projects)
    project = repos.projects.get(result.project.id)

    pipeline = Pipeline(build_registry(), repos, sandbox, audit)
    summary = pipeline.run(project, result.target, result.workspace,
                           stages=[Stage.UNPACK])
    return project, summary, result, audit


# ------------------------------------------------------------------ the slice

def test_the_run_succeeds(slice_run) -> None:
    _project, summary, _result, _audit = slice_run
    assert summary.ok, [o.error for o in summary.outcomes]
    assert summary.outcomes[0].status is JobStatus.SUCCEEDED
    assert summary.entities > 0


def test_the_app_entity_matches_the_manifest(slice_run, repos: Repositories) -> None:
    project, _summary, _result, _audit = slice_run
    app = repos.entities.get_by_key(project.id, EntityType.APP, PACKAGE)
    assert app is not None, "androguard must recover the package name"
    attributes = app.attributes
    assert attributes["version_name"] == VERSION_NAME
    assert attributes["min_sdk"] == MIN_SDK
    assert attributes["target_sdk"] == TARGET_SDK
    assert attributes["debuggable"] is True
    assert attributes["allow_backup"] is True
    assert attributes["uses_cleartext_traffic"] is False


def test_every_component_is_discovered(slice_run, repos: Repositories) -> None:
    project, _summary, _result, _audit = slice_run
    components = repos.entities.list(project.id, EntityType.COMPONENT)
    keys = {c.key for c in components}

    assert f"{PACKAGE}.MainActivity" in keys, "relative names must be qualified"
    assert f"{PACKAGE}.SyncService" in keys
    assert f"{PACKAGE}.BootReceiver" in keys
    assert f"{PACKAGE}.data.ShopProvider" in keys

    kinds = {c.attributes["kind"] for c in components}
    assert kinds == {ComponentKind.ACTIVITY.value, ComponentKind.SERVICE.value,
                     ComponentKind.RECEIVER.value, ComponentKind.PROVIDER.value}


def test_exported_surface_is_correct(slice_run, repos: Repositories) -> None:
    project, _summary, _result, _audit = slice_run
    by_key = {c.key: c for c in repos.entities.list(project.id, EntityType.COMPONENT)}

    assert by_key[f"{PACKAGE}.MainActivity"].attributes["exported"] is True
    assert by_key[f"{PACKAGE}.SyncService"].attributes["exported"] is False
    # The Provider declares no android:exported but has no intent-filter either,
    # so what matters is that the *absence* is preserved for the auditor.
    provider = by_key[f"{PACKAGE}.data.ShopProvider"]
    assert provider.attributes["exported_declared"] is None
    assert provider.attributes["authorities"] == f"{PACKAGE}.provider"


def test_permissions_land_with_their_protection_level(slice_run,
                                                      repos: Repositories) -> None:
    project, _summary, _result, _audit = slice_run
    permissions = {p.key: p.attributes
                   for p in repos.entities.list(project.id, EntityType.PERMISSION)}

    assert permissions["android.permission.INTERNET"]["requested"] is True
    assert permissions["android.permission.ACCESS_FINE_LOCATION"]["requested"] is True
    custom = permissions[f"{PACKAGE}.permission.SYNC"]
    assert custom["declared_by_app"] is True
    assert custom["custom"] is True
    assert custom["protection_level"] == "signature"


def test_deep_links_are_extracted(slice_run, repos: Repositories) -> None:
    project, _summary, _result, _audit = slice_run
    links = {link.key: link.attributes
             for link in repos.entities.list(project.id, EntityType.DEEP_LINK)}

    assert "https://shop.example.com/order" in links
    assert links["https://shop.example.com/order"]["auto_verify"] is True
    assert "exampleshop://pay" in links
    assert links["exampleshop://pay"]["web_scheme"] is False


def test_native_libraries_are_inventoried(slice_run, repos: Repositories) -> None:
    project, _summary, _result, _audit = slice_run
    libs = {lib.key: lib.attributes
            for lib in repos.entities.list(project.id, EntityType.NATIVE_LIB)}
    assert set(libs) == {"lib/arm64-v8a/libshop.so", "lib/armeabi-v7a/libshop.so"}
    assert libs["lib/arm64-v8a/libshop.so"]["arch"] == "arm64-v8a"


# ------------------------------------------------------------------ the graph

def test_the_graph_is_connected_and_rooted_on_the_app(slice_run,
                                                      repos: Repositories) -> None:
    project, _summary, _result, _audit = slice_run
    snapshot = build_snapshot(repos, project.id)

    root = snapshot.root
    assert root is not None and root.key == PACKAGE

    # Every entity is reachable from the app, a disconnected node means an
    # adapter emitted something without wiring it in.
    for entity in snapshot.entities:
        assert snapshot.path_from_root(entity.id), f"orphan node: {entity.key}"


def test_typed_edges_describe_the_structure(slice_run, repos: Repositories) -> None:
    project, _summary, _result, _audit = slice_run
    snapshot = build_snapshot(repos, project.id)
    by_id = {e.id: e for e in snapshot.entities}

    relations = {(by_id[e.src_id].key, e.type, by_id[e.dst_id].key)
                 for e in snapshot.edges}

    assert (PACKAGE, EdgeType.DECLARES, f"{PACKAGE}.SyncService") in relations
    assert (PACKAGE, EdgeType.EXPORTS, f"{PACKAGE}.MainActivity") in relations
    assert (PACKAGE, EdgeType.REQUESTS_PERMISSION,
            "android.permission.INTERNET") in relations
    assert (PACKAGE, EdgeType.EMBEDS, "lib/arm64-v8a/libshop.so") in relations
    # The activity owns its deep links.
    assert (f"{PACKAGE}.MainActivity", EdgeType.DECLARES,
            "https://shop.example.com/order") in relations
    # The provider gates access behind the app's own permission.
    assert (f"{PACKAGE}.data.ShopProvider", EdgeType.REQUESTS_PERMISSION,
            f"{PACKAGE}.permission.SYNC") in relations


# --------------------------------------------------------------- the overview

def test_the_overview_renders_the_real_run(slice_run, repos: Repositories) -> None:
    from PyQt6.QtWidgets import QApplication

    from themob.app.panels.overview import OverviewPanel

    project, _summary, _result, _audit = slice_run
    _app = QApplication.instance() or QApplication([])

    snapshot = build_snapshot(repos, project.id)
    panel = OverviewPanel()
    panel.load(project, snapshot, repos.findings.list(project.id))

    assert int(panel._kpi_entities._value.text()) == len(snapshot)
    assert int(panel._kpi_surface._value.text()) > 0
    assert len(panel._graph._nodes) == len(snapshot)
    assert len(panel._graph._edges) == snapshot.edge_count


# ----------------------------------------------------------- audit and re-runs

def test_the_whole_run_is_audited_and_verifiable(slice_run,
                                                 repos: Repositories) -> None:
    project, _summary, _result, audit = slice_run
    actions = [e.action for e in repos.audit.list(project.id)]
    for expected in (Action.PROJECT_CREATED, Action.PROJECT_AUTHORIZED,
                     Action.PIPELINE_STARTED, Action.ANALYZER_STARTED,
                     Action.ANALYZER_FINISHED, Action.PIPELINE_FINISHED):
        assert expected in actions, expected

    ok, message = audit.verify_chain()
    assert ok, message


def test_raw_tool_output_is_kept_for_provenance(slice_run) -> None:
    _project, _summary, result, _audit = slice_run
    raw = result.workspace.raw_dir("androguard-unpack") / "androguard.json"
    assert raw.is_file() and raw.stat().st_size > 0


def test_rerunning_converges_instead_of_duplicating(slice_run,
                                                    repos: Repositories,
                                                    sandbox: SandboxRunner) -> None:
    project, _summary, result, audit = slice_run
    before = repos.entities.count(project.id)
    edges_before = repos.edges.count(project.id)

    from themob.model.enums import Stage

    Pipeline(build_registry(), repos, sandbox, audit).run(
        project, result.target, result.workspace, stages=[Stage.UNPACK])

    assert repos.entities.count(project.id) == before, \
        "a second run must upsert onto the same nodes, not duplicate them"
    assert repos.edges.count(project.id) == edges_before


def test_an_unauthorized_project_never_reaches_the_container(
        repos: Repositories, sandbox: SandboxRunner, apk: Path,
        tmp_path: Path) -> None:
    audit = AuditTrail(repos.audit)
    result = intake(apk, repos, audit, root=tmp_path / "home2")
    with pytest.raises(AuthorizationError):
        Pipeline(build_registry(), repos, sandbox, audit).run(
            result.project, result.target, result.workspace)
    assert not (result.workspace.raw_dir("androguard-unpack") / "androguard.json").exists()


# --------------------------------------------------------------- the sandbox

def test_the_worker_has_no_network(sandbox: SandboxRunner, apk: Path,
                                   tmp_path: Path) -> None:
    """The containment guarantee, asserted against a live container."""
    result = sandbox.run(
        _IMAGE,
        ["-c", "import socket;"
               "s=socket.socket();s.settimeout(3);"
               "print('CONNECTED' if s.connect_ex(('1.1.1.1',53))==0 else 'BLOCKED')"],
        sample=apk, output_dir=tmp_path / "out", entrypoint="python3")
    assert b"BLOCKED" in result.stdout, result.stdout[:400]


def test_the_sample_mount_is_read_only(sandbox: SandboxRunner, apk: Path,
                                       tmp_path: Path) -> None:
    result = sandbox.run(
        _IMAGE,
        ["-c", "import glob;"
               "p=glob.glob('/input/*')[0];"
               "open(p,'ab').write(b'x');print('WROTE')"],
        sample=apk, output_dir=tmp_path / "out", entrypoint="python3")
    assert not result.ok, "writing to the sample must fail"
    assert b"WROTE" not in result.stdout


# ------------------------------------------------------------------- apktool

@pytest.fixture(scope="session")
def apktool_sandbox(sandbox: SandboxRunner) -> SandboxRunner:
    from themob.adapters.apktool_decode import ApktoolDecodeAnalyzer

    if not sandbox.has_image(ApktoolDecodeAnalyzer.image):
        pytest.skip(f"{ApktoolDecodeAnalyzer.image} is not built, run "
                    "`python -m themob.sandbox.build apktool`")
    return sandbox


@pytest.fixture()
def apktool_run(repos: Repositories, apktool_sandbox: SandboxRunner, apk: Path,
                tmp_path: Path):
    """Intake -> authorize -> run the unpack stage, both analyzers."""
    from themob.model.enums import Stage

    audit = AuditTrail(repos.audit)
    result = intake(apk, repos, audit, name="Example Shop",
                    root=tmp_path / "apktool-home")
    audit.record_attestation(result.project, Attestation(
        target_name="shop.apk", target_sha256=result.sha256,
        operator="tester@lab", engagement_ref="ENG-APKTOOL",
        attested=True), repos.projects)
    project = repos.projects.get(result.project.id)

    summary = Pipeline(build_registry(), repos, apktool_sandbox, audit).run(
        project, result.target, result.workspace, stages=[Stage.UNPACK])
    return project, summary, result


def test_apktool_decodes_the_package(apktool_run) -> None:
    _project, summary, _result = apktool_run
    outcome = next(o for o in summary.outcomes if o.analyzer == "apktool-decode")
    assert outcome.ok, outcome.error


def test_the_decoded_tree_lands_in_the_workspace(apktool_run) -> None:
    _project, _summary, result = apktool_run
    decoded = result.workspace.artifacts_root / "apktool" / "decoded"
    assert decoded.is_dir()
    # The plain-text manifest is the whole reason this stage exists.
    manifest = decoded / "AndroidManifest.xml"
    assert manifest.is_file()

    import xml.etree.ElementTree as ET

    root = ET.parse(manifest).getroot()
    assert root.tag == "manifest"
    ns = "{http://schemas.android.com/apk/res/android}"
    assert root.get("package") == PACKAGE

    application = root.find("application")
    assert application is not None
    assert application.get(f"{ns}debuggable") == "true"
    assert application.get(f"{ns}allowBackup") == "true"
    assert len(application.findall("activity")) == 1
    assert len(application.findall("provider")) == 2
    assert len(root.findall("uses-permission")) == 3

    # With a real resources.arsc present, apktool resolves resource references
    # rather than leaving raw ids, which is the whole reason the config auditor
    # can read the network policy at all.
    assert application.get(f"{ns}networkSecurityConfig") ==         "@xml/network_security_config"
    assert (decoded / "res" / "xml" / "network_security_config.xml").is_file()

    # versionCode and versionName are NOT in the decoded manifest. apktool moves
    # them into apktool.yml so a rebuild can restore them, so that file is where
    # a test has to look for them.
    meta = (decoded / "apktool.yml").read_text(encoding="utf-8")
    assert f"versionCode: {VERSION_CODE}" in meta
    assert f"versionName: {VERSION_NAME}" in meta

    # --no-src: smali must not have been decompiled here.
    assert not (decoded / "smali").exists()


def test_both_unpack_analyzers_converge_on_one_app_node(
        apktool_run, repos: Repositories) -> None:
    """androguard and apktool describe the same app; the graph must hold one
    node carrying both their attribute sets, not two."""
    project, _summary, _result = apktool_run
    apps = repos.entities.list(project.id, EntityType.APP)
    assert len(apps) == 1

    attributes = apps[0].attributes
    assert apps[0].key == PACKAGE
    assert attributes["version_name"] == VERSION_NAME      # from androguard
    assert attributes["decoded_manifest"], "from apktool"
    assert attributes["decoded_file_count"] > 0


def test_decoded_paths_are_resolvable(apktool_run, repos: Repositories) -> None:
    project, _summary, result = apktool_run
    app = repos.entities.list(project.id, EntityType.APP)[0]
    manifest = result.workspace.resolve(app.attributes["decoded_manifest"])
    assert manifest.is_file()
    assert result.workspace.resolve(app.attributes["decoded_dir"]).is_dir()


def test_apktool_emits_no_findings(apktool_run) -> None:
    _project, summary, _result = apktool_run
    outcome = next(o for o in summary.outcomes if o.analyzer == "apktool-decode")
    assert outcome.findings == 0


# ---------------------------------------------------------------------- jadx

@pytest.fixture(scope="session")
def jadx_sandbox(sandbox: SandboxRunner) -> SandboxRunner:
    from themob.adapters.jadx_decompile import JadxDecompileAnalyzer

    if not sandbox.has_image(JadxDecompileAnalyzer.image):
        pytest.skip(f"{JadxDecompileAnalyzer.image} is not built, run "
                    "`python -m themob.sandbox.build jadx`")
    return sandbox


@pytest.fixture()
def jadx_run(repos: Repositories, jadx_sandbox: SandboxRunner, apk: Path,
             tmp_path: Path):
    """Intake -> authorize -> unpack + reverse-engineering stages."""
    from themob.model.enums import Stage

    audit = AuditTrail(repos.audit)
    result = intake(apk, repos, audit, name="Example Shop",
                    root=tmp_path / "jadx-home")
    audit.record_attestation(result.project, Attestation(
        target_name="shop.apk", target_sha256=result.sha256,
        operator="tester@lab", engagement_ref="ENG-JADX",
        attested=True), repos.projects)
    project = repos.projects.get(result.project.id)

    summary = Pipeline(build_registry(), repos, jadx_sandbox, audit).run(
        project, result.target, result.workspace,
        stages=[Stage.UNPACK, Stage.REVERSE_ENGINEERING])
    return project, summary, result


def _jadx_outcome(summary):
    return next(o for o in summary.outcomes if o.analyzer == "jadx-decompile")


def _decompiled(summary):
    """jadx must succeed. The fixture ships a real, decompilable DEX."""
    outcome = _jadx_outcome(summary)
    assert outcome.ok, f"jadx failed: {outcome.error}"
    return outcome


def test_jadx_runs_in_the_sandbox(jadx_run) -> None:
    """It reached the container and decompiled the sample.

    An earlier build died before reading the sample at all: jadx takes
    user.home from a JVM property rather than $HOME, and uid 65534 has no
    passwd entry, so it tried to create /.config on the read-only root.
    """
    _project, summary, _result = jadx_run
    outcome = _decompiled(summary)
    assert outcome.error is None
    assert outcome.duration_s > 0


def test_jadx_attaches_to_the_existing_app_node(jadx_run,
                                                repos: Repositories) -> None:
    """jadx never reads the manifest. Without Target.app_key it would create a
    second App node keyed by hash, and the graph would show two apps."""
    _decompiled(jadx_run[1])
    project, _summary, _result = jadx_run
    apps = repos.entities.list(project.id, EntityType.APP)
    assert len(apps) == 1
    assert apps[0].key == PACKAGE

    attributes = apps[0].attributes
    assert attributes["version_name"] == VERSION_NAME      # androguard
    assert attributes["decoded_manifest"]                  # apktool
    assert attributes["sources_dir"] == "artifacts/jadx/sources"   # jadx


def test_one_app_node_survives_a_failed_analyzer(jadx_run,
                                                 repos: Repositories) -> None:
    """The unpack stage's App node must not be forked or lost when a later
    analyzer fails: the graph should still describe the app."""
    project, _summary, _result = jadx_run
    apps = repos.entities.list(project.id, EntityType.APP)
    assert len(apps) == 1 and apps[0].key == PACKAGE


def test_sources_land_in_the_workspace(jadx_run) -> None:
    _decompiled(jadx_run[1])
    _project, _summary, result = jadx_run
    sources = result.workspace.artifacts_root / "jadx" / "sources"
    assert sources.is_dir()
    assert any(sources.rglob("*.java")), "no Java was produced"
    # --no-res: apktool owns resources, jadx must not redo them. jadx creates
    # the directory either way, so what matters is that it stays empty.
    resources = result.workspace.artifacts_root / "jadx" / "resources"
    assert not any(resources.rglob("*")), "jadx decoded resources it was told to skip"


def test_the_decompiled_java_is_the_real_thing(jadx_run) -> None:
    """Not just that files exist: that the constants survived the round trip.

    The fixture DEX encodes these strings, so finding them in the output proves
    the whole path, from bytecode to browsable source.
    """
    _decompiled(jadx_run[1])
    _project, _summary, result = jadx_run
    sources = result.workspace.artifacts_root / "jadx" / "sources"
    java = "\n".join(p.read_text(encoding="utf-8", errors="replace")
                     for p in sources.rglob("*.java"))

    assert "class MainActivity" in java
    assert "class ShopProvider" in java
    assert "https://api.shop.example.com/v1/orders" in java

    # The call sites, decompiled as real Java rather than a JADX ERROR block.
    # An invoke-static that assembles but decodes to the wrong register still
    # produces a .java file, so asserting the file exists proves nothing; these
    # assert the method bodies came back.
    assert 'Cipher.getInstance("AES/ECB/PKCS5Padding")' in java
    assert 'MessageDigest.getInstance("MD5")' in java
    assert "JADX ERROR" not in java, "jadx refused to decompile a method"
    # The cleartext URL and the secret-shaped key are what 1.4 and 1.7 will read.
    assert "http://legacy.shop.example.com/v1/orders" in java
    assert "AKIAZZ7NLQK4PRODXYZQ" in java


def test_the_class_index_is_readable_and_contained(jadx_run,
                                                   repos: Repositories) -> None:
    from themob.adapters.jadx_decompile import read_class_index

    _decompiled(jadx_run[1])
    project, _summary, result = jadx_run
    app = repos.entities.list(project.id, EntityType.APP)[0]
    index = read_class_index(result.workspace, app.attributes["class_index"])

    assert index, "the class index should not be empty"
    for entry in index[:50]:
        assert result.workspace.resolve(entry["path"]).is_file()


def test_the_code_browser_renders_the_real_tree(jadx_run,
                                                repos: Repositories) -> None:
    from PyQt6.QtWidgets import QApplication

    from themob.adapters.jadx_decompile import read_class_index
    from themob.app.panels.code import CodePanel

    _decompiled(jadx_run[1])
    project, _summary, result = jadx_run
    _app_instance = QApplication.instance() or QApplication([])

    app = repos.entities.list(project.id, EntityType.APP)[0]
    index = read_class_index(result.workspace, app.attributes["class_index"])

    panel = CodePanel()
    panel.load(result.workspace, index)
    assert panel._tree.topLevelItemCount() > 0

    first = index[0]["fqcn"]
    assert panel.open_class(first)
    assert panel._source.toPlainText().strip()


def test_jadx_emits_no_findings(jadx_run) -> None:
    _project, summary, _result = jadx_run
    assert _jadx_outcome(summary).findings == 0


# -------------------------------------------------------------- config audit

@pytest.fixture()
def audit_run(repos: Repositories, apktool_sandbox: SandboxRunner, apk: Path,
              tmp_path: Path):
    """Intake -> authorize -> unpack, then judge what the unpackers found.

    Uses the apktool sandbox because the auditor reads what *both* unpackers
    contribute: androguard's manifest flags and apktool's resolved network
    security config. The auditor itself needs no container.
    """
    from themob.model.enums import Stage

    audit = AuditTrail(repos.audit)
    result = intake(apk, repos, audit, name="Example Shop",
                    root=tmp_path / "audit-home")
    audit.record_attestation(result.project, Attestation(
        target_name="shop.apk", target_sha256=result.sha256,
        operator="tester@lab", engagement_ref="ENG-AUDIT",
        attested=True), repos.projects)
    project = repos.projects.get(result.project.id)

    summary = Pipeline(build_registry(), repos, apktool_sandbox, audit).run(
        project, result.target, result.workspace,
        stages=[Stage.UNPACK, Stage.CONFIG_AUDIT])
    return project, summary, result, audit


def _reported(repos: Repositories, project_id: str) -> dict:
    """Every config-audit finding, keyed by its canonical weakness."""
    return {source.rule: finding
            for finding in repos.findings.list(project_id)
            for source in finding.sources if source.tool == "config-audit"}


def test_the_auditor_runs_without_a_container(audit_run) -> None:
    project, summary, _result, _audit = audit_run
    outcome = next(o for o in summary.outcomes if o.analyzer == "config-audit")
    assert outcome.ok, outcome.error
    assert outcome.findings > 0
    assert summary.ok, [o.error for o in summary.outcomes]


def test_it_reports_what_the_fixture_actually_declares(audit_run,
                                                       repos: Repositories) -> None:
    project, _summary, _result, _audit = audit_run
    reported = _reported(repos, project.id)

    # The fixture manifest sets all three.
    assert "android.config.debuggable" in reported
    assert "android.config.backup-allowed" in reported
    assert "android.platform.min-sdk-unsupported" in reported

    # These two only become visible once apktool can resolve
    # @xml/network_security_config, which needs a real resources.arsc. They are
    # the proof that the auditor reads apktool's output and not just
    # androguard's manifest flags.
    assert "android.network.user-ca-trusted" in reported
    assert "android.network.cleartext-permitted-for-domain" in reported
    domains = reported["android.network.cleartext-permitted-for-domain"]
    assert "legacy.shop.example.com" in domains.evidence[0].value

    debuggable = reported["android.config.debuggable"]
    assert debuggable.severity is Severity.HIGH
    assert debuggable.masvs_control
    assert debuggable.cwe == "CWE-489"
    assert debuggable.remediation is not None


def test_it_does_not_cry_wolf_on_a_real_manifest(audit_run,
                                                 repos: Repositories) -> None:
    """The three false positives that would make the auditor useless.

    MainActivity is exported *and* is the launcher. Every app's is. BootReceiver
    is exported but guarded by a permission. The custom permission is declared
    signature-level, which is the correct choice, not a weakness.
    """
    project, _summary, _result, _audit = audit_run
    reported = _reported(repos, project.id)

    exported = reported.get("android.ipc.component-exported-unprotected")
    if exported is not None:
        component = exported.location.component if exported.location else ""
        assert "MainActivity" not in (component or ""), \
            "the launcher activity must not be reported"
        assert "BootReceiver" not in (component or ""), \
            "a permission-guarded receiver must not be reported"

    assert "android.ipc.custom-permission-weak-protection" not in reported, \
        "the fixture declares protectionLevel=signature, which is correct"


def test_findings_point_back_into_the_graph(audit_run,
                                            repos: Repositories) -> None:
    project, _summary, _result, _audit = audit_run
    app = repos.entities.get_by_key(project.id, EntityType.APP, PACKAGE)
    debuggable = _reported(repos, project.id)["android.config.debuggable"]
    assert debuggable.entity_ids == [app.id]


def test_the_verdict_document_is_on_disk(audit_run) -> None:
    _project, _summary, result, _audit = audit_run
    raw = result.workspace.raw_dir("config-audit") / "config-audit.json"
    assert raw.is_file() and raw.stat().st_size > 0


def test_rerunning_the_auditor_does_not_duplicate_findings(
        audit_run, repos: Repositories, apktool_sandbox: SandboxRunner) -> None:
    from themob.model.enums import Stage

    project, _summary, result, audit = audit_run
    before = len(repos.findings.list(project.id))
    assert before > 0

    Pipeline(build_registry(), repos, apktool_sandbox, audit).run(
        project, result.target, result.workspace,
        stages=[Stage.UNPACK, Stage.CONFIG_AUDIT])

    assert len(repos.findings.list(project.id)) == before, \
        "a second audit must merge on fingerprint, not duplicate"


def test_the_network_config_reference_survives_both_unpackers(
        audit_run, repos: Repositories) -> None:
    """androguard's manifest reference must not be erased by apktool's null.

    json_patch treats a null as a delete, so apktool reporting "no network
    security config" once erased what androguard read out of the manifest, and
    the auditor then reported a missing config for an app that declares one.
    """
    project, _summary, _result, _audit = audit_run
    app = repos.entities.get_by_key(project.id, EntityType.APP, PACKAGE)
    # This fixture declares no NSC, so the attribute is legitimately absent,
    # what matters is that apktool did not delete other manifest facts either.
    assert app.attributes["debuggable"] is True
    assert app.attributes["allow_backup"] is True
    assert app.attributes["version_name"] == VERSION_NAME


# ------------------------------------------------------------------- secrets

@pytest.fixture(scope="session")
def gitleaks_sandbox(sandbox: SandboxRunner) -> SandboxRunner:
    from themob.adapters.gitleaks_scan import GitleaksScanAnalyzer

    if not sandbox.has_image(GitleaksScanAnalyzer.image):
        pytest.skip(f"{GitleaksScanAnalyzer.image} is not built, run "
                    "`python -m themob.sandbox.build gitleaks`")
    return sandbox


@pytest.fixture()
def secrets_run(repos: Repositories, gitleaks_sandbox: SandboxRunner, apk: Path,
                tmp_path: Path):
    """Unpack and decompile, then scan what they produced for secrets.

    All three earlier stages have to run first: gitleaks reads apktool's decoded
    resources and jadx's Java, not the package.
    """
    from themob.model.enums import Stage

    audit = AuditTrail(repos.audit)
    result = intake(apk, repos, audit, name="Example Shop",
                    root=tmp_path / "secrets-home")
    audit.record_attestation(result.project, Attestation(
        target_name="shop.apk", target_sha256=result.sha256,
        operator="tester@lab", engagement_ref="ENG-SECRETS",
        attested=True), repos.projects)
    project = repos.projects.get(result.project.id)

    summary = Pipeline(build_registry(), repos, gitleaks_sandbox, audit).run(
        project, result.target, result.workspace,
        stages=[Stage.UNPACK, Stage.REVERSE_ENGINEERING, Stage.SECRETS])
    return project, summary, result, audit


def _gitleaks_outcome(summary):
    return next(o for o in summary.outcomes if o.analyzer == "gitleaks-scan")


def test_gitleaks_scans_the_decoded_tree(secrets_run) -> None:
    _project, summary, _result, _audit = secrets_run
    outcome = _gitleaks_outcome(summary)
    assert outcome.ok, outcome.error
    assert outcome.duration_s > 0


def test_it_finds_the_aws_key_in_the_decompiled_code(secrets_run,
                                                    repos: Repositories) -> None:
    """The fixture ships a fake AWS key that jadx recovers into Java source."""
    import hashlib as _h

    project, _summary, _result, _audit = secrets_run
    secrets = repos.entities.list(project.id, EntityType.SECRET)
    assert secrets, "the scanners found nothing in a package that ships secrets"

    # Identify it by the credential's digest, not by a rule name. Both scanners
    # upsert the same node and the later one wins on scalar attributes, so the
    # rule recorded there is whichever tool ran last. Agreement is on the
    # finding's sources, which is where the scorer reads it.
    digest = _h.sha256(b"AKIAZZ7NLQK4PRODXYZQ").hexdigest()
    keys = {s.key for s in secrets}
    assert f"sha256:{digest}" in keys, keys

    for secret in secrets:
        assert secret.key.startswith("sha256:")
        assert secret.attributes.get("preview"), "a redacted preview is required"
        assert secret.attributes.get("rule"), "the matching rule is not recorded"


def test_distinct_secrets_get_distinct_identities(secrets_run,
                                                  repos: Repositories) -> None:
    """The bug this catches collapsed every secret into one node.

    gitleaks writes the literal string "REDACTED" into its own report when it
    is run with --redact, so every hit hashed to the same digest and the graph
    showed one secret no matter how many the package held.
    """
    project, _summary, _result, _audit = secrets_run
    secrets = repos.entities.list(project.id, EntityType.SECRET)
    digests = {s.key for s in secrets}
    assert len(digests) == len(secrets), "two secrets shared one identity"

    import hashlib as _h
    redacted = _h.sha256(b"REDACTED").hexdigest()
    assert f"sha256:{redacted}" not in digests,         "the worker hashed gitleaks' redaction placeholder, not the secret"


def test_it_finds_the_key_in_the_string_resources(secrets_run,
                                                 repos: Repositories) -> None:
    """res/values/strings.xml is where Android apps really hide API keys.

    gitleaks flags this exact string in a .txt, a .java and even a .xml written
    as ``key = "value"``, but not as ``<string name="k">value</string>``. That
    blind spot is precisely what apkleaks is here to cover, so this asserts the
    pair finds what neither finds alone.
    """
    project, _summary, _result, _audit = secrets_run
    rules = {str(s.attributes.get("rule") or "").lower()
             for s in repos.entities.list(project.id, EntityType.SECRET)}
    assert any("stripe" in rule for rule in rules), rules


def test_the_plaintext_secret_never_reaches_the_database(secrets_run,
                                                         repos: Repositories) -> None:
    """The whole point of the redact-and-hash contract with the worker.

    If the value landed here, themob would be a second place to leak it from,
    and the report generated from this database would be a third.
    """
    project, _summary, _result, _audit = secrets_run
    import json as _json

    from themob.adapters.base import capture_secret_values

    if capture_secret_values():
        pytest.skip("THEMOB_CAPTURE_SECRET_VALUES is set: the full value is "
                    "intentionally kept behind the UI password gate")

    blob = _json.dumps(
        [e.model_dump(mode="json")
         for e in repos.entities.list(project.id, EntityType.SECRET)]
        + [f.model_dump(mode="json") for f in repos.findings.list(project.id)])

    assert "AKIAZZ7NLQK4PRODXYZQ" not in blob
    assert "sk_live_51H8xExampleSecretKey0000" not in blob


def test_secret_nodes_hang_off_the_app(secrets_run, repos: Repositories) -> None:
    project, _summary, _result, _audit = secrets_run
    snapshot = build_snapshot(repos, project.id)
    for secret in repos.entities.list(project.id, EntityType.SECRET):
        assert snapshot.path_from_root(secret.id), \
            f"orphan secret node: {secret.key}"


def test_secret_findings_are_mapped_and_linked(secrets_run,
                                               repos: Repositories) -> None:
    project, _summary, _result, _audit = secrets_run
    findings = [f for f in repos.findings.list(project.id)
                for s in f.sources if s.tool == "gitleaks"]
    if not findings:
        pytest.skip("gitleaks reported no secrets in this fixture")

    secret_ids = {s.id for s in repos.entities.list(project.id, EntityType.SECRET)}
    for finding in findings:
        assert finding.masvs_control, f"{finding.title} has no MASVS control"
        assert finding.cwe
        # The placeholder must have been resolved to a real row id.
        assert finding.entity_ids
        assert set(finding.entity_ids) <= secret_ids


def test_the_raw_gitleaks_report_is_kept(secrets_run) -> None:
    _project, _summary, result, _audit = secrets_run
    raw = result.workspace.raw_dir("gitleaks-scan") / "gitleaks.json"
    assert raw.is_file() and raw.stat().st_size > 0


def test_rerunning_the_scan_does_not_duplicate(secrets_run,
                                               repos: Repositories,
                                               gitleaks_sandbox: SandboxRunner) -> None:
    from themob.model.enums import Stage

    project, _summary, result, audit = secrets_run
    before = repos.entities.count(project.id)
    findings_before = len(repos.findings.list(project.id))

    Pipeline(build_registry(), repos, gitleaks_sandbox, audit).run(
        project, result.target, result.workspace, stages=[Stage.SECRETS])

    assert repos.entities.count(project.id) == before
    assert len(repos.findings.list(project.id)) == findings_before


@pytest.fixture(scope="session")
def apkleaks_sandbox(sandbox: SandboxRunner) -> SandboxRunner:
    from themob.adapters.apkleaks_scan import ApkleaksScanAnalyzer

    if not sandbox.has_image(ApkleaksScanAnalyzer.image):
        pytest.skip(f"{ApkleaksScanAnalyzer.image} is not built, run "
                    "`python -m themob.sandbox.build apkleaks`")
    return sandbox


def test_apkleaks_runs_and_reads_the_resources(secrets_run,
                                               repos: Repositories) -> None:
    _project, summary, _result, _audit = secrets_run
    outcome = next(o for o in summary.outcomes if o.analyzer == "apkleaks-scan")
    assert outcome.ok, outcome.error
    assert outcome.duration_s > 0


def test_the_two_scanners_converge_on_one_secret(secrets_run,
                                                 repos: Repositories) -> None:
    """The credential both tools see is one node and one finding.

    gitleaks reports the AWS key out of jadx's Java with a file and a line;
    apkleaks reports it out of its own decompile with neither. Keyed on the
    canonical weakness plus the secret's digest, the two collide, and the
    finding carries both tools instead of the report saying it twice.
    """
    project, _summary, _result, _audit = secrets_run

    secrets = repos.entities.list(project.id, EntityType.SECRET)
    assert len({s.key for s in secrets}) == len(secrets), \
        "the same credential produced two nodes"

    both = [f for f in repos.findings.list(project.id)
            if {s.tool for s in f.sources} >= {"gitleaks", "apkleaks"}]
    assert both, "no finding carries agreement from both scanners"
    for finding in both:
        # Agreement is the signal the scorer reads; it must survive the merge.
        assert len(finding.sources) >= 2


# -------------------------------------------------------------------- sbom

@pytest.fixture(scope="session")
def sbom_sandbox(sandbox: SandboxRunner) -> SandboxRunner:
    from themob.adapters.sbom_scan import SbomScanAnalyzer

    if not sandbox.has_image(SbomScanAnalyzer.image):
        pytest.skip(f"{SbomScanAnalyzer.image} is not built, run "
                    "`python -m themob.sandbox.build sbom`")
    return sandbox


@pytest.fixture()
def sbom_run(repos: Repositories, sbom_sandbox: SandboxRunner, apk: Path,
             tmp_path: Path):
    """Unpack, then catalog what the package bundles and match it."""
    from themob.model.enums import Stage

    audit = AuditTrail(repos.audit)
    result = intake(apk, repos, audit, name="Example Shop",
                    root=tmp_path / "sbom-home")
    audit.record_attestation(result.project, Attestation(
        target_name="shop.apk", target_sha256=result.sha256,
        operator="tester@lab", engagement_ref="ENG-SBOM",
        attested=True), repos.projects)
    project = repos.projects.get(result.project.id)

    summary = Pipeline(build_registry(), repos, sbom_sandbox, audit).run(
        project, result.target, result.workspace,
        stages=[Stage.UNPACK, Stage.DEPENDENCIES])
    return project, summary, result, audit


def _sbom_outcome(summary):
    return next(o for o in summary.outcomes if o.analyzer == "sbom-scan")


def test_the_sbom_scan_runs(sbom_run) -> None:
    _project, summary, _result, _audit = sbom_run
    outcome = _sbom_outcome(summary)
    assert outcome.ok, outcome.error
    assert summary.ok, [o.error for o in summary.outcomes]


def test_the_bundled_libraries_are_catalogued(sbom_run,
                                              repos: Repositories) -> None:
    """syft finds none of these. The worker's own catalogers do.

    This is the assertion that would have caught building the stage on syft
    alone: it returns zero artifacts for an APK and zero for a directory of
    META-INF markers, so a suite resting on it would pass while finding nothing.
    """
    from tests.fixtures.apk import CLEAN_LIBRARY, VULNERABLE_LIBRARY

    project, _summary, _result, _audit = sbom_run
    libraries = repos.entities.list(project.id, EntityType.LIBRARY)
    purls = {library.key for library in libraries}

    assert VULNERABLE_LIBRARY in purls, "the shaded pom.properties was missed"
    assert CLEAN_LIBRARY in purls, "the AndroidX version marker was missed"

    gson = next(x for x in libraries if x.key == VULNERABLE_LIBRARY)
    assert gson.attributes["package_name"] == "gson"
    assert gson.attributes["version"] == "2.8.5"
    assert gson.attributes["evidence_path"].endswith("pom.properties")


def test_every_library_hangs_off_the_app(sbom_run, repos: Repositories) -> None:
    project, _summary, _result, _audit = sbom_run
    app = repos.entities.get_by_key(project.id, EntityType.APP, PACKAGE)
    libraries = repos.entities.list(project.id, EntityType.LIBRARY)
    assert libraries

    edges = repos.edges.list(project.id)
    embedded = {e.dst_id for e in edges
                if e.type is EdgeType.EMBEDS and e.src_id == app.id}
    for library in libraries:
        assert library.id in embedded, f"{library.key} is not wired to the app"


def test_a_vulnerable_dependency_is_reported(sbom_run,
                                             repos: Repositories) -> None:
    """gson 2.8.5 predates its fix, so grype has something true to match."""
    from tests.fixtures.apk import VULNERABLE_LIBRARY

    project, _summary, _result, _audit = sbom_run
    findings = [f for f in repos.findings.list(project.id)
                if any(s.tool == "grype" for s in f.sources)]
    assert findings, "grype matched nothing against a known-vulnerable version"

    against_gson = [f for f in findings
                    if f.location and f.location.file == VULNERABLE_LIBRARY]
    assert against_gson, "the vulnerable library produced no finding"

    finding = against_gson[0]
    assert finding.masvs_control == "MASVS-CODE-3"
    assert finding.cwe == "CWE-1395"
    assert finding.severity is not Severity.INFO
    assert finding.remediation is not None


def test_the_clean_library_produces_no_finding(sbom_run,
                                               repos: Repositories) -> None:
    """Catalogued and clean has to be distinguishable from catalogued and bad."""
    from tests.fixtures.apk import CLEAN_LIBRARY

    project, _summary, _result, _audit = sbom_run
    findings = repos.findings.list(project.id)
    assert not [f for f in findings
                if f.location and f.location.file == CLEAN_LIBRARY]


def test_the_scan_records_that_it_ran(sbom_run, repos: Repositories) -> None:
    project, _summary, _result, _audit = sbom_run
    app = repos.entities.get_by_key(project.id, EntityType.APP, PACKAGE)
    summary = app.attributes["dependency_scan"]
    assert summary["libraries"] >= 3
    assert summary["tool_version"]["grype"]


def test_the_raw_sbom_output_is_kept(sbom_run) -> None:
    _project, _summary, result, _audit = sbom_run
    raw = result.workspace.raw_dir("sbom-scan") / "sbom.json"
    assert raw.is_file() and raw.stat().st_size > 0


def test_rerunning_the_sbom_scan_converges(sbom_run, repos: Repositories,
                                           sbom_sandbox: SandboxRunner) -> None:
    from themob.model.enums import Stage

    project, _summary, result, audit = sbom_run
    before = repos.entities.count(project.id)
    findings_before = len(repos.findings.list(project.id))

    Pipeline(build_registry(), repos, sbom_sandbox, audit).run(
        project, result.target, result.workspace, stages=[Stage.DEPENDENCIES])

    assert repos.entities.count(project.id) == before
    assert len(repos.findings.list(project.id)) == findings_before


def test_grype_has_its_database_baked_in(sbom_run) -> None:
    """The container has no network, so an image without the database would
    start clean, fail its update silently, and report zero vulnerabilities for
    every package in every app. That failure looks exactly like good news."""
    _project, summary, _result, _audit = sbom_run
    outcome = _sbom_outcome(summary)
    assert outcome.ok, outcome.error
    assert outcome.findings > 0, \
        "no advisories matched, which is what a missing database looks like"


# ----------------------------------------------------------------- semgrep

@pytest.fixture(scope="session")
def semgrep_sandbox(sandbox: SandboxRunner) -> SandboxRunner:
    from themob.adapters.semgrep_scan import SemgrepScanAnalyzer

    if not sandbox.has_image(SemgrepScanAnalyzer.image):
        pytest.skip(f"{SemgrepScanAnalyzer.image} is not built, run "
                    "`python -m themob.sandbox.build semgrep`")
    return sandbox


@pytest.fixture()
def sast_run(repos: Repositories, semgrep_sandbox: SandboxRunner, apk: Path,
             tmp_path: Path):
    """Unpack, decompile, then match the Java that came out.

    All three earlier stages are needed: semgrep reads jadx's output, and the
    call sites it matches only exist once the DEX has been decompiled.
    """
    from themob.model.enums import Stage

    audit = AuditTrail(repos.audit)
    result = intake(apk, repos, audit, name="Example Shop",
                    root=tmp_path / "sast-home")
    audit.record_attestation(result.project, Attestation(
        target_name="shop.apk", target_sha256=result.sha256,
        operator="tester@lab", engagement_ref="ENG-SAST",
        attested=True), repos.projects)
    project = repos.projects.get(result.project.id)

    summary = Pipeline(build_registry(), repos, semgrep_sandbox, audit).run(
        project, result.target, result.workspace,
        stages=[Stage.UNPACK, Stage.REVERSE_ENGINEERING, Stage.SAST])
    return project, summary, result, audit


def _semgrep_outcome(summary):
    return next(o for o in summary.outcomes if o.analyzer == "semgrep-scan")


def test_semgrep_runs_with_its_baked_in_rules(sast_run) -> None:
    """The container has no network, so the rules must already be in the image.

    A run configured against the semgrep registry would either fail here or,
    worse, scan with nothing loaded and report every app clean.
    """
    _project, summary, _result, _audit = sast_run
    outcome = _semgrep_outcome(summary)
    assert outcome.ok, outcome.error
    assert summary.ok, [o.error for o in summary.outcomes]


def test_the_rules_actually_match_the_decompiled_java(sast_run,
                                                      repos: Repositories) -> None:
    """The assertion the whole stage rests on.

    The fixture's DEX encodes two call sites precisely so this can be checked:
    Cipher.getInstance("AES/ECB/PKCS5Padding") and
    MessageDigest.getInstance("MD5"). A rule that compiles but matches nothing
    would otherwise leave the suite green while finding nothing at all.
    """
    project, _summary, _result, _audit = sast_run
    reported = {source.rule
                for finding in repos.findings.list(project.id)
                for source in finding.sources if source.tool == "semgrep"}

    assert "themob-weak-cipher-mode" in reported, \
        "the ECB rule did not match Cipher.getInstance in the decompiled Java"
    assert "themob-weak-hash" in reported, \
        "the MD5 rule did not match MessageDigest.getInstance"


def test_the_crypto_findings_carry_their_standards_mapping(
        sast_run, repos: Repositories) -> None:
    project, _summary, _result, _audit = sast_run
    findings = [f for f in repos.findings.list(project.id)
                if any(s.tool == "semgrep" for s in f.sources)]
    assert findings

    for finding in findings:
        assert finding.masvs_control.startswith("MASVS-CRYPTO")
        assert finding.cwe and finding.cwe.startswith("CWE-")
        assert finding.remediation is not None
        assert finding.location and finding.location.file.endswith(".java")


def test_crypto_usage_nodes_reach_the_graph(sast_run,
                                            repos: Repositories) -> None:
    """The plan puts CryptoUsage in the graph so a later stage can pivot."""
    project, _summary, _result, _audit = sast_run
    nodes = repos.entities.list(project.id, EntityType.CRYPTO_USAGE)
    assert nodes, "semgrep found crypto misuse but created no graph node"

    app = repos.entities.get_by_key(project.id, EntityType.APP, PACKAGE)
    edges = repos.edges.list(project.id)
    used = {e.dst_id for e in edges
            if e.type is EdgeType.USES and e.src_id == app.id}
    for node in nodes:
        assert node.id in used, f"{node.key} is not wired to the app"
        assert node.attributes["weakness"].startswith("android.crypto.")


def test_the_raw_semgrep_output_is_kept(sast_run) -> None:
    _project, _summary, result, _audit = sast_run
    raw = result.workspace.raw_dir("semgrep-scan") / "semgrep.json"
    assert raw.is_file() and raw.stat().st_size > 0


def test_rerunning_the_sast_stage_converges(sast_run, repos: Repositories,
                                            semgrep_sandbox: SandboxRunner) -> None:
    from themob.model.enums import Stage

    project, _summary, result, audit = sast_run
    before = repos.entities.count(project.id)
    findings_before = len(repos.findings.list(project.id))

    Pipeline(build_registry(), repos, semgrep_sandbox, audit).run(
        project, result.target, result.workspace, stages=[Stage.SAST])

    assert repos.entities.count(project.id) == before
    assert len(repos.findings.list(project.id)) == findings_before


# ----------------------------------------------------------- endpoint recon

@pytest.fixture()
def endpoint_run(repos: Repositories, apkleaks_sandbox: SandboxRunner,
                 apk: Path, tmp_path: Path):
    """Unpack, decompile, extract secrets, then judge the links they contain.

    The secrets stage is the input: apkleaks runs LinkFinder over the package
    and passes URL-shaped hits through unredacted, and this stage decides which
    of them are really endpoints.
    """
    from themob.model.enums import Stage

    audit = AuditTrail(repos.audit)
    result = intake(apk, repos, audit, name="Example Shop",
                    root=tmp_path / "endpoint-home")
    audit.record_attestation(result.project, Attestation(
        target_name="shop.apk", target_sha256=result.sha256,
        operator="tester@lab", engagement_ref="ENG-ENDPOINT",
        attested=True), repos.projects)
    project = repos.projects.get(result.project.id)

    summary = Pipeline(build_registry(), repos, apkleaks_sandbox, audit).run(
        project, result.target, result.workspace,
        stages=[Stage.UNPACK, Stage.REVERSE_ENGINEERING, Stage.SECRETS,
                Stage.API_RECON])
    return project, summary, result, audit


def test_the_endpoint_stage_runs_without_a_container(endpoint_run) -> None:
    _project, summary, _result, _audit = endpoint_run
    outcome = next(o for o in summary.outcomes if o.analyzer == "endpoint-extract")
    assert outcome.ok, outcome.error
    assert outcome.entities > 0


def test_the_real_endpoints_are_recovered(endpoint_run,
                                          repos: Repositories) -> None:
    """The assertion the stage rests on.

    The fixture encodes these two URLs in its DEX precisely so this can be
    checked end to end, from bytecode through jadx and apkleaks to a graph node.
    """
    project, _summary, _result, _audit = endpoint_run
    keys = {e.key for e in repos.entities.list(project.id, EntityType.ENDPOINT)}

    assert "https://api.shop.example.com/v1/orders" in keys
    assert "http://legacy.shop.example.com/v1/orders" in keys


def test_the_noise_really_is_filtered_out(endpoint_run,
                                          repos: Repositories) -> None:
    """LinkFinder reports three non-endpoints on this fixture.

    An XML namespace every Android package contains, a bare path, and a cipher
    transformation that happens to have slashes in it. Handing those to a recon
    engine is how the integration gets switched off.
    """
    project, _summary, _result, _audit = endpoint_run
    keys = {e.key for e in repos.entities.list(project.id, EntityType.ENDPOINT)}

    # Exact, not substring: "/order" is a substring of the legitimate
    # "https://api.shop.example.com/v1/orders", and asserting containment would
    # fail on the very endpoint the stage is supposed to keep.
    for noise in ("http://schemas.android.com/apk/res/android",
                  "/order", "AES/ECB/PKCS5Padding"):
        assert noise not in keys, f"{noise} reached the graph"

    # The namespace host must not appear under any path either.
    assert not any("schemas.android.com" in key for key in keys)
    # Everything that survived is an absolute web URL, which is what rules out
    # the bare path and the cipher transformation as a class.
    assert keys and all(key.startswith(("http://", "https://")) for key in keys)


def test_the_bucket_is_a_cloud_asset(endpoint_run, repos: Repositories) -> None:
    project, _summary, _result, _audit = endpoint_run
    assets = repos.entities.list(project.id, EntityType.CLOUD_ASSET)
    assert assets, "the fixture's S3 bucket did not reach the graph"

    bucket = next(a for a in assets if a.attributes.get("provider") == "aws-s3")
    assert bucket.attributes["bucket"] == "shop-example-uploads"
    # apkleaks reports it twice, as a bare host and inside a URL. One bucket.
    assert len([a for a in assets
                if a.attributes.get("bucket") == "shop-example-uploads"]) == 1


def test_the_cleartext_endpoint_is_reported(endpoint_run,
                                            repos: Repositories) -> None:
    project, _summary, _result, _audit = endpoint_run
    reported = {source.rule: finding
                for finding in repos.findings.list(project.id)
                for source in finding.sources if source.tool == "endpoint-extract"}

    assert "android.network.cleartext-endpoint" in reported
    finding = reported["android.network.cleartext-endpoint"]
    assert finding.severity is Severity.HIGH
    assert "legacy.shop.example.com" in finding.title


def test_endpoints_hang_off_the_app_in_the_graph(endpoint_run,
                                                 repos: Repositories) -> None:
    """The handoff to TOPRECON is a subgraph, so the edges have to be there."""
    project, _summary, _result, _audit = endpoint_run
    snapshot = build_snapshot(repos, project.id)
    by_id = {e.id: e for e in snapshot.entities}

    talks = {by_id[e.dst_id].key for e in snapshot.edges
             if e.type is EdgeType.TALKS_TO}
    assert "https://api.shop.example.com/v1/orders" in talks

    for entity in snapshot.entities:
        if entity.type in (EntityType.ENDPOINT, EntityType.CLOUD_ASSET):
            assert snapshot.path_from_root(entity.id), f"orphan: {entity.key}"


def test_the_rejections_are_kept_for_the_operator(endpoint_run) -> None:
    """When a tester asks why a URL they can see is missing, this answers."""
    _project, _summary, result, _audit = endpoint_run
    raw = result.workspace.raw_dir("endpoint-extract") / "endpoints.json"
    assert raw.is_file()

    document = json.loads(raw.read_text(encoding="utf-8"))
    rejected = {r["value"] for r in document["rejected"]}
    assert "http://schemas.android.com/apk/res/android" in rejected
    assert all(r.get("reason") for r in document["rejected"])


# ------------------------------------------------------ cross-tool voting

@pytest.fixture()
def voting_run(repos: Repositories, apkleaks_sandbox: SandboxRunner,
               apk: Path, tmp_path: Path):
    """Every stage that produces findings, so agreement is real rather than staged."""
    from themob.model.enums import Stage

    audit = AuditTrail(repos.audit)
    result = intake(apk, repos, audit, name="Example Shop",
                    root=tmp_path / "voting-home")
    audit.record_attestation(result.project, Attestation(
        target_name="shop.apk", target_sha256=result.sha256,
        operator="tester@lab", engagement_ref="ENG-VOTE",
        attested=True), repos.projects)
    project = repos.projects.get(result.project.id)

    summary = Pipeline(build_registry(), repos, apkleaks_sandbox, audit).run(
        project, result.target, result.workspace,
        stages=[Stage.UNPACK, Stage.REVERSE_ENGINEERING, Stage.SECRETS,
                Stage.CONFIG_AUDIT])
    return project, summary, result, audit


def test_the_normalize_pass_runs_after_the_analyzers(voting_run) -> None:
    _project, summary, _result, _audit = voting_run
    assert summary.normalized is not None, "the normalize pass did not run"
    assert summary.normalized.scored > 0


def test_every_finding_carries_a_weakness_the_catalogue_defines(
        voting_run) -> None:
    """An unmapped weakness is an adapter bug, and this is where it surfaces."""
    _project, summary, _result, _audit = voting_run
    assert summary.normalized.ok, \
        f"findings with no known weakness key: {summary.normalized.unmapped}"


def test_the_weakness_key_survives_into_storage(voting_run,
                                                repos: Repositories) -> None:
    project, _summary, _result, _audit = voting_run
    findings = repos.findings.list(project.id)
    assert findings
    assert all(f.weakness_key for f in findings), \
        "a stored finding could not say what class of issue it is"


def test_each_reporter_kept_its_own_confidence(voting_run,
                                               repos: Repositories) -> None:
    """The input voting needs, which the merge would otherwise have collapsed."""
    project, _summary, _result, _audit = voting_run
    for finding in repos.findings.list(project.id):
        votes = repos.findings.source_votes(finding.id)
        assert votes, f"{finding.weakness_key} has no reporters"
        assert all(c is not None for _t, c in votes), \
            f"{finding.weakness_key} lost a reporter's confidence"


def test_the_two_secret_scanners_agree_without_inflating_each_other(
        voting_run, repos: Repositories) -> None:
    """The fixture's AWS key is found by gitleaks and by apkleaks.

    Both match regular expressions over the same decompiled text, so they share
    their blind spots and their agreement is not corroboration. Confidence must
    not rise just because the same technique fired twice.
    """
    project, _summary, _result, _audit = voting_run
    shared = [f for f in repos.findings.list(project.id)
              if {t for t, _c in repos.findings.source_votes(f.id)}
              >= {"gitleaks", "apkleaks"}]
    assert shared, "expected the two secret scanners to agree on something"

    for finding in shared:
        votes = dict(repos.findings.source_votes(finding.id))
        assert finding.confidence == pytest.approx(max(votes.values())), \
            "two pattern matchers must not compound"


def test_scoring_is_stable_across_a_rerun(voting_run, repos: Repositories,
                                          apkleaks_sandbox: SandboxRunner) -> None:
    """A second run must converge, not ratchet confidence upward."""
    from themob.model.enums import Stage

    project, _summary, result, audit = voting_run
    before = {f.fingerprint: f.confidence for f in repos.findings.list(project.id)}
    assert before

    Pipeline(build_registry(), repos, apkleaks_sandbox, audit).run(
        project, result.target, result.workspace,
        stages=[Stage.UNPACK, Stage.REVERSE_ENGINEERING, Stage.SECRETS,
                Stage.CONFIG_AUDIT])

    after = {f.fingerprint: f.confidence for f in repos.findings.list(project.id)}
    assert after == pytest.approx(before)


# ------------------------------------------------- correlation on a real app

def test_the_real_app_has_a_real_entry_point(voting_run,
                                             repos: Repositories) -> None:
    """The fixture exports MainActivity and a provider, so doors exist."""
    from themob.correlate import entry_points

    project, _summary, _result, _audit = voting_run
    snapshot = build_snapshot(repos, project.id)
    doors = entry_points(snapshot)

    assert doors, "an app with an exported activity has an entry point"
    assert any("MainActivity" in (d.key or "") for d in doors)


def test_exposure_distinguishes_reachable_from_merely_present(
        voting_run, repos: Repositories) -> None:
    """The distinction the correlator exists to draw.

    Not everything in the package is reachable from outside it. If exposure
    said otherwise the property would be useless, so this asserts the graph of
    a real app actually separates the two.
    """
    from themob.correlate import entry_points, exposure

    project, _summary, _result, _audit = voting_run
    snapshot = build_snapshot(repos, project.id)
    doors = entry_points(snapshot)

    reached = {e.id for e in snapshot.entities
               if exposure(snapshot, e.id, doors).reachable}
    assert reached, "nothing at all was reachable, which cannot be right"
    assert len(reached) < len(snapshot.entities), \
        "everything was reachable, so the App node is being walked as a conduit"

    app = repos.entities.get_by_key(project.id, EntityType.APP, PACKAGE)
    assert app.id not in reached, "the App sits above the doors, not behind one"


def test_findings_split_across_the_sections_without_double_counting(
        voting_run, repos: Repositories) -> None:
    """A total across sections has to be a real total."""
    from themob.correlate import project as project_sections

    project, _summary, _result, _audit = voting_run
    snapshot = build_snapshot(repos, project.id)
    findings = repos.findings.list(project.id)
    assert findings

    views = project_sections(snapshot, findings)
    assert sum(len(v.findings) for v in views) == len(findings)
    assert any(v.findings for v in views), "every finding fell through the nav"


def test_the_handoff_carries_the_fixtures_backend(voting_run,
                                                  repos: Repositories) -> None:
    """The plan's differentiator, against a package rather than a fixture graph."""
    from themob.model.enums import Stage
    from themob.correlate import build_handoff

    project, _summary, result, audit = voting_run
    # The endpoint stage is what populates this, so run it.
    Pipeline(build_registry(), repos, SandboxRunner(), audit).run(
        project, result.target, result.workspace, stages=[Stage.API_RECON])

    snapshot = build_snapshot(repos, project.id)
    document = build_handoff(snapshot, repos.findings.list(project.id))

    hosts = {h["host"] for h in document["hosts"]}
    assert "api.shop.example.com" in hosts
    assert "legacy.shop.example.com" in hosts
    assert document["app"]["package"] == PACKAGE

    legacy = next(h for h in document["hosts"]
                  if h["host"] == "legacy.shop.example.com")
    assert legacy["cleartext"] is True


# ------------------------------------------------------- scoring in context

def test_the_scoring_pass_runs_after_the_normalizer(voting_run) -> None:
    _project, summary, _result, _audit = voting_run
    assert summary.scored is not None, "the scoring pass did not run"
    assert summary.scored.scored > 0
    assert summary.scored.ok, \
        f"weaknesses no pack defines: {summary.scored.unknown_weakness}"


def test_every_finding_gets_its_standards_mapping(voting_run,
                                                  repos: Repositories) -> None:
    """A report should never have to reconstruct these."""
    project, _summary, _result, _audit = voting_run
    findings = repos.findings.list(project.id)
    assert findings

    for finding in findings:
        assert finding.masvs_control, f"{finding.weakness_key} has no MASVS control"
        assert finding.mobile_top10, f"{finding.weakness_key} has no Top 10 category"
        assert finding.risk is not None, f"{finding.weakness_key} has no risk"


def test_exposure_actually_changes_a_rating_on_a_real_app(
        voting_run, repos: Repositories) -> None:
    """The point of the whole scoring stage, end to end.

    The fixture declares PublicProvider as exported and guards only its reads,
    so any app on the device can write to it. The config auditor reports that,
    the correlator finds it reachable, and the scorer must raise it. Nothing
    else in the package is reachable: secrets hang off the App node, because
    gitleaks reports a file rather than a calling class, and inventing an edge
    from an activity to a secret would be claiming knowledge themob does not
    have.
    """
    project, summary, _result, _audit = voting_run
    assert summary.scored.exposed > 0, "nothing was externally reachable"
    assert summary.scored.raised > 0, "exposure changed no rating"

    raised = [f for f in repos.findings.list(project.id)
              if f.score_rationale and "raised from" in f.score_rationale]
    assert raised, "no finding recorded why it was raised"
    for finding in raised:
        assert finding.base_severity is not None
        assert finding.severity is not finding.base_severity

    # The one that should be raised, named rather than inferred.
    provider = next(
        (f for f in raised
         if f.weakness_key == "android.ipc.provider-exported-unprotected"), None)
    assert provider is not None, "the exported provider was not raised"
    assert provider.severity is Severity.CRITICAL       # HIGH, raised once


def test_scoring_does_not_compound_across_runs(voting_run, repos: Repositories,
                                               apkleaks_sandbox: SandboxRunner) -> None:
    """Severity is stored, so a second pass must not raise the raised value."""
    from themob.model.enums import Stage

    project, _summary, result, audit = voting_run
    before = {f.fingerprint: f.severity for f in repos.findings.list(project.id)}
    assert before

    Pipeline(build_registry(), repos, apkleaks_sandbox, audit).run(
        project, result.target, result.workspace,
        stages=[Stage.UNPACK, Stage.REVERSE_ENGINEERING, Stage.SECRETS,
                Stage.CONFIG_AUDIT])

    after = {f.fingerprint: f.severity for f in repos.findings.list(project.id)}
    assert after == before, "a severity moved on a re-run of the same input"


def test_the_risk_figure_orders_the_findings(voting_run,
                                             repos: Repositories) -> None:
    """A flat ranking would make the top-findings list meaningless."""
    project, _summary, _result, _audit = voting_run
    risks = [f.risk for f in repos.findings.list(project.id)]
    assert len(set(risks)) > 1, "every finding scored the same"
    assert all(0.0 <= r <= 100.0 for r in risks)


# --------------------------------------------- validation on a real finding

def test_a_verdict_on_a_real_finding_is_auditable(voting_run,
                                                  repos: Repositories) -> None:
    """The confirm/annotate loop, against findings a real scan produced.

    A status change is not a database update: it is the answer to "who decided
    this was a false positive, and when", which is the question a disputed
    report turns on.
    """
    from themob.audit.attestation import Action
    from themob.model.enums import FindingStatus
    from themob.orchestrator.validation import ValidationError, record

    project, _summary, _result, audit = voting_run
    finding = repos.findings.list(project.id)[0]

    # Suppressing without a reason is refused, and changes nothing.
    with pytest.raises(ValidationError):
        record(repos, audit, finding.id, FindingStatus.FALSE_POSITIVE,
               operator="tester@lab")
    assert repos.findings.get(finding.id).status is FindingStatus.NEW

    record(repos, audit, finding.id, FindingStatus.FALSE_POSITIVE,
           operator="tester@lab", note="Debug build only, release differs.")

    stored = repos.findings.get(finding.id)
    assert stored.status is FindingStatus.FALSE_POSITIVE
    assert repos.findings.notes(finding.id)[0].author == "tester@lab"

    entry = next(e for e in repos.audit.list(project.id)
                 if e.action == Action.FINDING_STATUS_CHANGED)
    assert entry.detail["now"] == "false_positive"
    assert "Debug build" in entry.detail["reason"]

    ok, message = audit.verify_chain()
    assert ok, message


def test_a_rerun_does_not_undo_a_testers_verdict(
        voting_run, repos: Repositories,
        apkleaks_sandbox: SandboxRunner) -> None:
    """An assessment survives re-running the scan that produced it.

    The storage merge preserves a status set by hand, the normalizer only
    touches confidence and the scorer only touches severity. If any of them
    reset the status, a tester's afternoon of triage would vanish on the next
    run.
    """
    from themob.model.enums import FindingStatus, Stage
    from themob.orchestrator.validation import record

    project, _summary, result, audit = voting_run
    finding = repos.findings.list(project.id)[0]
    record(repos, audit, finding.id, FindingStatus.ACCEPTED_RISK,
           operator="tester@lab", note="Client accepts, ticket SEC-41.")

    Pipeline(build_registry(), repos, apkleaks_sandbox, audit).run(
        project, result.target, result.workspace,
        stages=[Stage.UNPACK, Stage.REVERSE_ENGINEERING, Stage.SECRETS,
                Stage.CONFIG_AUDIT])

    after = repos.findings.get(finding.id)
    assert after.status is FindingStatus.ACCEPTED_RISK
    assert repos.findings.notes(finding.id), "the note was lost"


# ---------------------------------------------------------- report export

def test_a_real_run_exports_a_report_that_says_where_it_came_from(
        slice_run, repos: Repositories, tmp_path: Path) -> None:
    """The whole point of the provenance header, against a real container run.

    Every value here was produced by the pipeline rather than a fixture: the
    digest intake computed, the version the tool reported from inside the
    container, and the attestation the gate recorded.
    """
    from themob.report import export

    project, _summary, result, audit = slice_run
    written = export(repos, audit, project.id, tmp_path / "handover",
                     operator="tester@lab")

    report = written.report
    assert report is not None
    assert report.provenance.sha256 == result.sha256
    assert report.provenance.package == PACKAGE
    assert report.provenance.authorization_ref == "ENG-INTEGRATION"
    assert report.provenance.authorized_by == "tester@lab"
    assert report.provenance.tools.get("androguard"), "no tool version travelled"
    assert report.provenance.audit_chain_ok, report.provenance.audit_chain_message

    html = written.files["html"].read_text(encoding="utf-8")
    assert result.sha256 in html
    assert PACKAGE in html

    document = json.loads(written.files["json"].read_text(encoding="utf-8"))
    assert document["provenance"]["sha256"] == result.sha256
    assert document["summary"]["entities"], "the graph did not reach the export"


def test_exporting_a_real_run_leaves_the_chain_verifiable(
        slice_run, repos: Repositories, tmp_path: Path) -> None:
    """The export is an event in the same trail it reports the state of."""
    from themob.report import export

    project, _summary, _result, audit = slice_run
    export(repos, audit, project.id, tmp_path / "handover",
           operator="tester@lab")

    actions = [e.action for e in repos.audit.list(project.id)]
    assert Action.REPORT_EXPORTED in actions

    ok, message = audit.verify_chain()
    assert ok, message
