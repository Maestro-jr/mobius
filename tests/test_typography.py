"""The typography gate, enforced by the suite as well as by CI.

CLAUDE.md bans the em dash and its relatives. A global hook blocks them on the
author's machine, but that hook is not in the repository. This test makes the
rule portable: it fails locally, for anyone, the moment a banned character lands
in tracked source or docs.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]


def _checker():
    spec = importlib.util.spec_from_file_location(
        "check_typography", _ROOT / "tools" / "check_typography.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_tree_carries_no_machine_written_punctuation() -> None:
    checker = _checker()
    hits: list[str] = []
    for path in checker.walk(_ROOT):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for number, code in checker.offending_lines(text):
            hits.append(f"{path.relative_to(_ROOT)}:{number}: U+{code:04X}")
    assert not hits, "banned characters found:\n" + "\n".join(hits)


def test_the_checker_actually_catches_a_banned_character() -> None:
    """A gate that cannot fail is not a gate."""
    checker = _checker()
    # An em dash, built by code point so this test file stays clean.
    sample = "a " + chr(0x2014) + " b"
    assert checker.offending_lines(sample) == [(1, 0x2014)]
