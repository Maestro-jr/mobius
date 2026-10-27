"""The apktool worker's parsing logic, tested outside the container.

``workers/apktool/analyze.py`` runs inside Docker, but its parsers are plain
stdlib and are the part most likely to be wrong: resolving an Android resource
reference through qualified directories, and reading a network-security config.
Both are exercised here directly so a bug in them does not have to wait for a
Docker run to surface.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_WORKER = (Path(__file__).resolve().parent.parent
           / "workers" / "apktool" / "analyze.py")


@pytest.fixture(scope="module")
def worker():
    """Load the worker script as a module without installing it."""
    spec = importlib.util.spec_from_file_location("themob_apktool_worker", _WORKER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _decoded_tree(root: Path, files: dict[str, str]) -> Path:
    decoded = root / "decoded"
    for relative, content in files.items():
        path = decoded / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return decoded


# ------------------------------------------------------ resource resolution

def test_resolves_a_plain_resource_reference(worker, tmp_path: Path) -> None:
    decoded = _decoded_tree(tmp_path, {"res/xml/nsc.xml": "<x/>"})
    resolved = worker.resolve_resource(str(decoded), "@xml/nsc")
    assert resolved is not None and Path(resolved).name == "nsc.xml"


def test_resolves_through_a_qualified_directory(worker, tmp_path: Path) -> None:
    """Real apps put the config in res/xml-v24/ and friends; a resolver that
    only looks in res/xml/ silently reports 'no network policy'."""
    decoded = _decoded_tree(tmp_path, {"res/xml-v24/nsc.xml": "<x/>"})
    assert worker.resolve_resource(str(decoded), "@xml/nsc") is not None


def test_resolves_a_namespaced_reference(worker, tmp_path: Path) -> None:
    decoded = _decoded_tree(tmp_path, {"res/xml/nsc.xml": "<x/>"})
    assert worker.resolve_resource(str(decoded), "@android:xml/nsc") is not None


@pytest.mark.parametrize("reference", [
    "", "nsc", "@xml", "@/nsc", "@xml/../../etc/passwd", "@xml/nsc extra", None,
])
def test_rejects_references_that_are_not_resource_references(
        worker, tmp_path: Path, reference) -> None:
    decoded = _decoded_tree(tmp_path, {"res/xml/nsc.xml": "<x/>"})
    assert worker.resolve_resource(str(decoded), reference) is None


def test_missing_resource_returns_none(worker, tmp_path: Path) -> None:
    decoded = _decoded_tree(tmp_path, {"res/xml/other.xml": "<x/>"})
    assert worker.resolve_resource(str(decoded), "@xml/nsc") is None


# ------------------------------------------------ network security config

_NSC = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors><certificates src="system"/></trust-anchors>
    </base-config>
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">legacy.example.com</domain>
    </domain-config>
    <domain-config>
        <domain>api.example.com</domain>
        <pin-set expiration="2027-01-01">
            <pin digest="SHA-256">abc=</pin>
            <pin digest="SHA-256">def=</pin>
        </pin-set>
        <trust-anchors>
            <certificates src="@raw/my_ca"/>
            <certificates src="system"/>
        </trust-anchors>
    </domain-config>
    <debug-overrides>
        <trust-anchors><certificates src="user"/></trust-anchors>
    </debug-overrides>
</network-security-config>
"""


def test_parses_every_scope(worker, tmp_path: Path) -> None:
    path = tmp_path / "nsc.xml"
    path.write_text(_NSC, encoding="utf-8")
    parsed = worker.parse_network_security_config(str(path))

    scopes = [c["scope"] for c in parsed["configs"]]
    assert scopes == ["base", "domain", "domain", "debug"]


def test_captures_the_cleartext_policy_per_domain(worker, tmp_path: Path) -> None:
    path = tmp_path / "nsc.xml"
    path.write_text(_NSC, encoding="utf-8")
    configs = worker.parse_network_security_config(str(path))["configs"]

    base = configs[0]
    assert base["cleartext_permitted"] is False
    legacy = configs[1]
    assert legacy["cleartext_permitted"] is True
    assert legacy["domains"] == ["legacy.example.com"]
    # Unset is not the same as false: the default depends on the target SDK,
    # so the auditor needs to know it was never declared.
    assert configs[2]["cleartext_permitted"] is None


def test_captures_pins_and_trust_anchors(worker, tmp_path: Path) -> None:
    path = tmp_path / "nsc.xml"
    path.write_text(_NSC, encoding="utf-8")
    configs = worker.parse_network_security_config(str(path))["configs"]

    pinned = configs[2]
    assert pinned["pins"] == ["abc=", "def="]
    assert pinned["trust_anchors"] == ["@raw/my_ca", "system"]
    # A user-installed CA trusted in debug overrides is exactly the kind of
    # thing the auditor will want; make sure it survives parsing.
    assert configs[3]["trust_anchors"] == ["user"]


def test_malformed_xml_is_reported_not_raised(worker, tmp_path: Path) -> None:
    path = tmp_path / "nsc.xml"
    path.write_text("<network-security-config><domain-config>", encoding="utf-8")
    parsed = worker.parse_network_security_config(str(path))
    assert "parse_error" in parsed and "configs" not in parsed


def test_missing_file_is_reported_not_raised(worker, tmp_path: Path) -> None:
    parsed = worker.parse_network_security_config(str(tmp_path / "nope.xml"))
    assert "parse_error" in parsed


def test_empty_domains_are_dropped(worker, tmp_path: Path) -> None:
    path = tmp_path / "nsc.xml"
    path.write_text(
        "<network-security-config><domain-config>"
        "<domain>  </domain><domain>ok.example.com</domain>"
        "</domain-config></network-security-config>", encoding="utf-8")
    configs = worker.parse_network_security_config(str(path))["configs"]
    assert configs[0]["domains"] == ["ok.example.com"]


# ------------------------------------------------------------------ inventory

def test_inventory_counts_resources_assets_and_locales(worker,
                                                       tmp_path: Path) -> None:
    decoded = _decoded_tree(tmp_path, {
        "AndroidManifest.xml": "<manifest/>",
        "res/values/strings.xml": "<r/>",
        "res/values-fr/strings.xml": "<r/>",
        "res/values-de-rDE/strings.xml": "<r/>",
        "res/drawable/icon.xml": "<r/>",
        "res/drawable-hdpi/icon.xml": "<r/>",
        "assets/config.json": "{}",
        "assets/fonts/x.ttf": "font",
    })
    files, resources, assets = worker.inventory(str(decoded))

    assert files["file_count"] == 8
    assert files["extensions"]["xml"] == 6
    assert resources["directories"]["values"] == 1
    assert set(resources["locales"]) == {"fr", "de-rDE"}
    # -hdpi is a density qualifier, not a locale, and must not be counted as one.
    assert "hdpi" not in resources["locales"]
    assert sorted(assets) == ["assets/config.json", "assets/fonts/x.ttf"]


def test_inventory_of_an_empty_tree(worker, tmp_path: Path) -> None:
    decoded = tmp_path / "decoded"
    decoded.mkdir()
    files, resources, assets = worker.inventory(str(decoded))
    assert files["file_count"] == 0 and resources["locale_count"] == 0
    assert assets == []


# ------------------------------------------------------------------ apktool.yml

def test_reads_apktool_metadata(worker, tmp_path: Path) -> None:
    pytest.importorskip("yaml")
    decoded = _decoded_tree(tmp_path, {"apktool.yml": """!!brut.androlib.meta.MetaInfo
version: 2.11.1
apkFileName: shop.apk
isFrameworkApk: false
sparseResources: true
sdkInfo:
  minSdkVersion: '24'
  targetSdkVersion: '34'
versionInfo:
  versionCode: '3021'
  versionName: 3.2.1
doNotCompress:
- resources.arsc
- png
"""})
    meta = worker.read_meta(str(decoded))
    assert meta["apktool_version"] == "2.11.1"
    assert meta["sparse_resources"] is True
    assert meta["is_framework_apk"] is False
    assert meta["min_sdk_version"] == "24"
    assert meta["version_name"] == "3.2.1"
    assert meta["do_not_compress"] == ["resources.arsc", "png"]


def test_missing_or_malformed_metadata_is_empty_not_fatal(worker,
                                                          tmp_path: Path) -> None:
    decoded = tmp_path / "decoded"
    decoded.mkdir()
    assert worker.read_meta(str(decoded)) == {}
    (decoded / "apktool.yml").write_text("!!!not: [valid", encoding="utf-8")
    assert worker.read_meta(str(decoded)) == {}


# ------------------------------------------------------------------- contract

def test_clip_bounds_every_string(worker) -> None:
    assert len(worker.clip("x" * 10_000)) == worker.MAX_STRING
    assert worker.clip(None) is None
    assert worker.clip(1234) == "1234"


def test_decode_never_asks_for_smali(worker) -> None:
    """--no-src is load-bearing: decompiling code here would double the slowest
    stage of the pipeline, and jadx owns that job."""
    source = _WORKER.read_text(encoding="utf-8")
    assert '"--no-src"' in source
    assert '"--force"' in source


def test_safe_loader_still_refuses_object_construction(worker, tmp_path: Path) -> None:
    """Tag tolerance must not become arbitrary construction.

    Mapping unknown tags to plain values is the point; a loader that actually
    instantiated what a tag names would let a crafted apktool.yml run code in
    the worker.
    """
    pytest.importorskip("yaml")
    import yaml

    loader = worker._tolerant_yaml_loader()
    assert issubclass(loader, yaml.SafeLoader)

    value = yaml.load("!!python/object/apply:os.system ['echo pwned']",
                      Loader=loader)
    assert not callable(value)
    assert value == ["echo pwned"], "the tag must be dropped, not honoured"


def test_tolerant_loader_leaves_ordinary_scalars_alone(worker) -> None:
    pytest.importorskip("yaml")
    import yaml

    parsed = yaml.load("a: 1\nb: true\nc: [x, y]\nd: 'no'\n",
                       Loader=worker._tolerant_yaml_loader())
    assert parsed == {"a": 1, "b": True, "c": ["x", "y"], "d": "no"}
