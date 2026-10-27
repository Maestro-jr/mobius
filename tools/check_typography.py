"""Fail if any tracked source or doc carries a machine-written punctuation mark.

The project bans the em dash and its relatives (see CLAUDE.md). On the author's
machine a global hook blocks them at write time, but that hook is not in the
repository and does not run for a contributor or in CI. This is the same rule
made portable: a check any clone can run and the pipeline enforces, so the
convention survives leaving one laptop.

Run it from the repository root::

    python tools/check_typography.py

Exit code 0 when clean, 1 when anything is found, with file:line for each hit.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Banned code points, named by hex so this file contains none of them itself.
BANNED = {
    0x2014: "em dash (recast the sentence)",
    0x2013: "en dash (use 'to' or a hyphen)",
    0x2018: "curly quote (use a plain ')",
    0x2019: "curly apostrophe (use a plain ')",
    0x201C: "curly quote (use a plain \")",
    0x201D: "curly quote (use a plain \")",
    0x2026: "ellipsis character (use three periods)",
    0x2192: "arrow (use ->)",
    0x2190: "arrow (use <-)",
}

# Extensions worth checking: code, docs, data, config.
SUFFIXES = {".py", ".md", ".txt", ".json", ".yml", ".yaml", ".sql", ".js",
            ".toml", ".cfg", ".ini"}

# Directories never worth walking.
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", ".mypy_cache",
             ".ruff_cache", "node_modules", "dist", "build", ".venv", "venv"}

# Files deliberately left as delivered. TOPMOBILE-build-plan.md is the author's
# source brief and keeps its original punctuation; LICENSE is the verbatim GPL.
SKIP_FILES = {"TOPMOBILE-build-plan.md", "LICENSE"}


def offending_lines(text: str) -> list[tuple[int, int]]:
    """(line number, code point) for every banned character in *text*."""
    hits: list[tuple[int, int]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        for char in line:
            if ord(char) in BANNED:
                hits.append((number, ord(char)))
    return hits


def walk(root: Path):
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.name in SKIP_FILES:
            continue
        if path.suffix.lower() in SUFFIXES:
            yield path


def main(argv: list[str] | None = None) -> int:
    root = Path(argv[0]) if argv else Path(__file__).resolve().parent.parent
    found = 0
    for path in walk(root):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for number, code in offending_lines(text):
            rel = path.relative_to(root)
            print(f"{rel}:{number}: U+{code:04X} {BANNED[code]}")
            found += 1

    if found:
        print(f"\n{found} banned character(s). Recast the text; do not swap "
              "one dash for another.", file=sys.stderr)
        return 1
    print("typography clean")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
