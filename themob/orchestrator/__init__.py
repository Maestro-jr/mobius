"""Orchestration: intake, the analysis pipeline, and its event stream.

Deliberately free of Qt: the engine is unit-testable headless, and
``app/signals.py`` is the only place events become Qt signals.
"""
from __future__ import annotations

from .events import Event, EventType, LogLevel, PipelineState, noop_emit
from .intake import (IntakeError, IntakeResult, MAX_SAMPLE_BYTES,
                     detect_platform, intake, target_for, validate_sample)
from .pipeline import (AnalyzerOutcome, Pipeline, PipelineError, RunSummary)
from .validation import (VERDICTS, VERDICT_LABELS, ValidationError,
                         Verdict, record as record_verdict)

__all__ = [
    "AnalyzerOutcome", "Event", "EventType", "IntakeError", "IntakeResult",
    "LogLevel", "MAX_SAMPLE_BYTES", "Pipeline", "PipelineError",
    "PipelineState", "RunSummary", "VERDICTS", "VERDICT_LABELS",
    "ValidationError", "Verdict", "detect_platform", "intake", "noop_emit",
    "record_verdict", "target_for", "validate_sample",
]
