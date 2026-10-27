"""Pipeline events.

The orchestrator is GUI-agnostic: it reports progress through a single
``emit(Event)`` callback. Keeping events as plain dataclasses means the whole
engine is unit-testable with no Qt imported at all; ``app/signals.py`` is the
one adapter that turns them into Qt signals.

Mirrors TOPRECON's ``core/events.py``.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from ..model.enums import Stage


class EventType:
    PIPELINE_STARTED = "pipeline_started"
    PIPELINE_FINISHED = "pipeline_finished"
    STAGE_STARTED = "stage_started"
    STAGE_FINISHED = "stage_finished"
    ANALYZER_STARTED = "analyzer_started"
    ANALYZER_FINISHED = "analyzer_finished"
    ANALYZER_SKIPPED = "analyzer_skipped"
    ENTITIES_ADDED = "entities_added"      # a batch landed in the graph
    FINDINGS_ADDED = "findings_added"
    GRAPH_CHANGED = "graph_changed"        # coarse "reload the graph" signal
    STATS = "stats"
    LOG = "log"
    STATE = "state"


class PipelineState:
    IDLE = "IDLE"
    RUNNING = "RUNNING"
    STOPPING = "STOPPING"
    DONE = "DONE"
    FAILED = "FAILED"


class LogLevel:
    INFO = "info"
    DISCOVERY = "discovery"
    WARN = "warn"
    ERROR = "error"


@dataclass
class Event:
    """One thing that happened during a run."""
    kind: str
    ts: float = field(default_factory=time.time)
    project_id: str = ""
    stage: Stage | None = None
    analyzer: str = ""
    text: str = ""
    level: str = LogLevel.INFO
    payload: dict[str, Any] = field(default_factory=dict)


def noop_emit(_event: Event) -> None:
    """Default sink, so the pipeline runs headless with no wiring."""
