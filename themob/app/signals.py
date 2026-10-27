"""Engine -> Qt bridge.

The orchestrator speaks plain :class:`themob.orchestrator.events.Event`; the GUI
speaks Qt signals. This QObject is the single adapter, exactly as TOPRECON's
``gui/signals.py`` is: the pipeline's ``emit`` callback is
:meth:`EngineBridge.dispatch`, and each event kind fans out to a typed signal
the panels connect to.

The bridge is created on the **main** thread while the pipeline runs on a
worker thread, so every connection resolves to a queued one and the panels are
only ever touched from the UI thread.
"""
from __future__ import annotations

from PyQt6.QtCore import QObject, pyqtSignal

from ..orchestrator.events import Event, EventType


class EngineBridge(QObject):
    """Turns pipeline events into Qt signals."""

    pipeline_started = pyqtSignal(dict)          # payload
    pipeline_finished = pyqtSignal(dict)         # payload
    stage_started = pyqtSignal(str)              # stage value
    stage_finished = pyqtSignal(str)
    analyzer_started = pyqtSignal(str)           # analyzer name
    analyzer_finished = pyqtSignal(str, dict)    # analyzer name, payload
    analyzer_skipped = pyqtSignal(str, str)      # analyzer name, reason
    graph_changed = pyqtSignal()                 # reload the graph and the counts
    log = pyqtSignal(dict)                       # {ts, text, level}
    state = pyqtSignal(str)                      # PipelineState

    def dispatch(self, event: Event) -> None:
        """Called from the engine thread; delivery is queued to the UI thread."""
        kind = event.kind
        if kind == EventType.PIPELINE_STARTED:
            self.pipeline_started.emit(event.payload)
        elif kind == EventType.PIPELINE_FINISHED:
            self.pipeline_finished.emit(event.payload)
        elif kind == EventType.STAGE_STARTED:
            self.stage_started.emit(event.stage.value if event.stage else "")
        elif kind == EventType.STAGE_FINISHED:
            self.stage_finished.emit(event.stage.value if event.stage else "")
        elif kind == EventType.ANALYZER_STARTED:
            self.analyzer_started.emit(event.analyzer)
        elif kind == EventType.ANALYZER_FINISHED:
            self.analyzer_finished.emit(event.analyzer, event.payload)
        elif kind == EventType.ANALYZER_SKIPPED:
            self.analyzer_skipped.emit(event.analyzer, event.text)
        elif kind == EventType.GRAPH_CHANGED:
            self.graph_changed.emit()
        elif kind == EventType.LOG:
            self.log.emit({"ts": event.ts, "text": event.text, "level": event.level})
        elif kind == EventType.STATE:
            self.state.emit(event.text)
