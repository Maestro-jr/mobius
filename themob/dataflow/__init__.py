"""Where a flagged value ends up, and what that is worth.

``trace`` follows one finding's value through the decompiled sources; ``run``
applies the result to a whole project's findings as confidence. Neither is
dataflow analysis in the compiler sense, and ``trace``'s own docstring is blunt
about the difference.
"""
from __future__ import annotations

from .pass_ import DataflowReport, confidence_for, run, traceable
from .trace import (REACHES_SINK, UNDETERMINED, UNUSED, USED, Flow, Use, trace)

__all__ = [
    "DataflowReport", "Flow", "REACHES_SINK", "UNDETERMINED", "UNUSED", "USED",
    "Use", "confidence_for", "run", "trace", "traceable",
]
