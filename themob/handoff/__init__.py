"""Handing the app's external surface to a recon engine, and taking results back.

One module today: :mod:`themob.handoff.toprecon`. It is deliberately not an
import of TOPRECON. The two are separate programs that exchange a file, which is
the same arms-length rule every tool integration here follows.
"""
from __future__ import annotations

from .toprecon import (FORMAT, Handoff, HostFacts, ImportReport, Seed, apply,
                       build, read_results, to_dict, write)

__all__ = [
    "FORMAT", "Handoff", "HostFacts", "ImportReport", "Seed", "apply", "build",
    "read_results", "to_dict", "write",
]
