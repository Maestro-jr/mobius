"""themob intelligence: learning from the operator's own scans, locally.

This package is the local-first intelligence layer. It reads the findings themob
already produced across the operator's projects and turns them into a corpus:
which weaknesses are most common, how often each is confirmed or dismissed, which
ones travel together, and how the picture changes over time. Nothing here leaves
the machine, and nothing here changes a deterministic finding: it is an advisory
read model on top of the engine, never inside it.

A later, explicitly opted-in telemetry export (categories and counts only, never
app content or identifiers) is a projection over this same corpus; it is not
built here.
"""
from __future__ import annotations

from . import telemetry
from .corpus import Corpus, WeaknessStat, build, summarize

__all__ = ["Corpus", "WeaknessStat", "build", "summarize", "telemetry"]
