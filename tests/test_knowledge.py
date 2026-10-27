"""The weakness rule packs, and the loader that refuses to trust them blindly.

A security tool that silently runs with half its checks because a rule pack was
malformed is worse than one that refuses to start, so every failure here is
loud. The other half of this file guards the thing the whole catalogue exists
for: an adapter emitting a key no pack defines produces a finding with no
severity and no standards reference, and nobody notices until it is in a report.
"""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import pytest

from themob.knowledge import (KNOWLEDGE_DIR, WeaknessPackError, catalogue, get,
                              keys, load)
from themob.model.enums import MASVSCategory, Severity

_KEY_SHAPE = re.compile(r"^[a-z0-9]+(\.[a-z0-9-]+)+$")


def _pack(directory: Path, name: str, weaknesses: list[dict]) -> Path:
    path = directory / name
    path.write_text(json.dumps({"weaknesses": weaknesses}), encoding="utf-8")
    return path


def _valid(key: str = "android.test.thing", **overrides) -> dict:
    doc = {
        "key": key,
        "title": "A test weakness",
        "severity": "medium",
        "masvs_category": "MASVS-PLATFORM",
        "masvs_control": "MASVS-PLATFORM-1",
        "description": "Something is wrong.",
        "remediation": "Stop doing it.",
    }
    doc.update(overrides)
    return doc


# ------------------------------------------------------------- shipped packs

def test_the_shipped_packs_load() -> None:
    loaded = catalogue()
    assert loaded, "themob ships with no weaknesses"
    assert set(loaded) == set(keys())


def test_every_shipped_weakness_is_well_formed() -> None:
    for key, weakness in catalogue().items():
        assert _KEY_SHAPE.match(key), f"{key} is not a canonical key"
        assert weakness.key == key
        assert isinstance(weakness.severity, Severity)
        assert isinstance(weakness.masvs_category, MASVSCategory)
        # The control must belong to the category it claims.
        assert weakness.masvs_control.startswith(weakness.masvs_category.value), \
            f"{key}: {weakness.masvs_control} is not in {weakness.masvs_category}"
        assert weakness.title and weakness.description and weakness.remediation
        if weakness.cwe:
            assert weakness.cwe.startswith("CWE-")


_TOP10 = {f"M{n}" for n in range(1, 11)}


def test_every_weakness_carries_a_mobile_top10_category() -> None:
    """Filled in 1.11, from the OWASP Mobile Top 10 (2024).

    A finding with no category cannot be grouped in a report, and the ten
    categories are stable and short enough to be mapped by hand with
    confidence. The reasoning for each mapping is recorded beside it in
    knowledge/android-weaknesses.json.
    """
    for key, weakness in catalogue().items():
        assert weakness.mobile_top10 in _TOP10,             f"{key} has no Mobile Top 10 category"


def test_maswe_ids_are_still_absent_rather_than_guessed() -> None:
    """The half of the mapping that could not be verified from here.

    MASWE ids are specific numbers, and unlike the Top 10 categories they
    cannot be derived from the weakness itself. Writing plausible ones would
    put a wrong standards reference in a pentest report, which is worse than a
    missing one. The loader carries the field through, so filling it is a data
    edit against https://mas.owasp.org/MASWE/ with no code change.

    This test is the tripwire: it fails the moment someone adds an id, so doing
    so has to be deliberate and verified.
    """
    for key, weakness in catalogue().items():
        assert weakness.maswe_id is None,             f"{key} gained a MASWE id: verify it against the OWASP source"


def test_the_packs_live_where_the_plan_puts_them() -> None:
    """Section 13: knowledge/ sits beside workers/ and shared/, not in the engine."""
    assert KNOWLEDGE_DIR.is_dir()
    assert (KNOWLEDGE_DIR.parent / "workers").is_dir()
    assert list(KNOWLEDGE_DIR.glob("*-weaknesses.json"))


# ------------------------------------------------- adapters agree with packs

def test_every_key_the_config_auditor_can_emit_is_defined() -> None:
    """Catches a typo in a branch no test happens to reach.

    ``_check`` validates at runtime, but only for the checks that actually fire.
    This reads the source instead, so a misspelled key in a rarely-taken branch
    fails here rather than in somebody's report.
    """
    from themob.adapters import config_audit

    source = Path(config_audit.__file__).read_text(encoding="utf-8")
    literals = {node.value for node in ast.walk(ast.parse(source))
                if isinstance(node, ast.Constant) and isinstance(node.value, str)
                and _KEY_SHAPE.match(node.value) and node.value.startswith("android.")}
    # Sanity: the scan must actually find something, or it proves nothing.
    assert len(literals) >= 5, f"the key scan found too little: {literals}"

    undefined = sorted(literals - keys())
    assert not undefined, f"config_audit emits keys no pack defines: {undefined}"


# ------------------------------------------------------------ loader refuses

def test_a_missing_directory_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(WeaknessPackError, match="no weakness packs"):
        load(tmp_path / "nowhere")


def test_an_empty_directory_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(WeaknessPackError, match="no weakness packs"):
        load(tmp_path)


def test_malformed_json_is_an_error(tmp_path: Path) -> None:
    (tmp_path / "x-weaknesses.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(WeaknessPackError, match="could not be read"):
        load(tmp_path)


def test_a_missing_required_field_names_the_weakness(tmp_path: Path) -> None:
    broken = _valid()
    del broken["remediation"]
    _pack(tmp_path, "x-weaknesses.json", [broken])
    with pytest.raises(WeaknessPackError, match="android.test.thing.*remediation"):
        load(tmp_path)


def test_an_unknown_severity_is_an_error(tmp_path: Path) -> None:
    _pack(tmp_path, "x-weaknesses.json", [_valid(severity="catastrophic")])
    with pytest.raises(WeaknessPackError, match="not a severity"):
        load(tmp_path)


def test_an_unknown_masvs_category_is_an_error(tmp_path: Path) -> None:
    _pack(tmp_path, "x-weaknesses.json", [_valid(masvs_category="MASVS-VIBES")])
    with pytest.raises(WeaknessPackError, match="not a MASVS category"):
        load(tmp_path)


def test_a_duplicate_key_within_a_pack_is_an_error(tmp_path: Path) -> None:
    """Silently letting the last one win is how voting quietly stops working."""
    _pack(tmp_path, "x-weaknesses.json", [_valid(), _valid()])
    with pytest.raises(WeaknessPackError, match="duplicate weakness keys"):
        load(tmp_path)


def test_a_key_defined_by_two_packs_is_an_error(tmp_path: Path) -> None:
    _pack(tmp_path, "a-weaknesses.json", [_valid()])
    _pack(tmp_path, "b-weaknesses.json", [_valid()])
    with pytest.raises(WeaknessPackError, match="already defined by another pack"):
        load(tmp_path)


def test_two_packs_with_distinct_keys_both_load(tmp_path: Path) -> None:
    """Android and iOS packs must be able to sit side by side."""
    _pack(tmp_path, "android-weaknesses.json", [_valid("android.test.one")])
    _pack(tmp_path, "ios-weaknesses.json", [_valid("ios.test.two")])
    loaded = load(tmp_path)
    assert set(loaded) == {"android.test.one", "ios.test.two"}


def test_a_weaknesses_list_of_the_wrong_shape_is_an_error(tmp_path: Path) -> None:
    (tmp_path / "x-weaknesses.json").write_text(
        json.dumps({"weaknesses": {"nope": 1}}), encoding="utf-8")
    with pytest.raises(WeaknessPackError, match="must be a list"):
        load(tmp_path)


# ------------------------------------------------------------------- lookups

def test_an_unknown_key_says_what_to_do_about_it() -> None:
    with pytest.raises(KeyError, match="unknown weakness key"):
        get("android.config.does-not-exist")


def test_the_catalogue_is_a_copy() -> None:
    """Callers must not be able to mutate the loaded packs."""
    catalogue().clear()
    assert catalogue(), "mutating the returned dict emptied the catalogue"
