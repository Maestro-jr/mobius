"""themob: an authorization-gated mobile attack-surface intelligence engine.

The version is read from the installed package metadata rather than duplicated
here, so ``pyproject.toml`` stays the single place it is declared. A checkout
that was never installed has no metadata to read, and reports "0.0.0+unknown"
rather than guessing: a report that names a version it cannot prove is worse
than one that admits it does not know.
"""
from __future__ import annotations

__all__ = ["__version__"]


def __getattr__(name: str) -> str:
    # Computed on first access, not at import: reading package metadata drags in
    # importlib.metadata and the whole email stack (~300ms), and nothing at
    # startup needs the version, so importing themob should not pay for it.
    if name == "__version__":
        try:
            from importlib.metadata import PackageNotFoundError, version
            return version("themob")
        except PackageNotFoundError:                      # pragma: no cover
            return "0.0.0+unknown"
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
