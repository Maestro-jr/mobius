"""The background engine thread.

HiveDefend's pattern: a ``QThread`` subclass that does the slow work and reports
back through ``pyqtSignal``, so the UI never blocks. themob's slow work is a
whole analysis pipeline dispatching to Docker workers, which is exactly the case
that must not run on the GUI thread.

Threading notes that matter here:

* the pipeline gets its **own** :class:`Repositories` over the same database
  file. ``Database`` hands out a per-thread SQLite connection, and WAL lets the
  UI keep reading while the engine writes;
* progress reaches the UI only through :class:`EngineBridge`, whose signals are
  queued because the bridge lives on the main thread;
* ``stop()`` is cooperative: the pipeline finishes the analyzer in flight and
  then unwinds, so no container is orphaned.
"""
from __future__ import annotations

import logging
from typing import Sequence

from PyQt6.QtCore import QThread, pyqtSignal

from ..adapters.base import AnalyzerRegistry, Target
from ..audit.attestation import AuditTrail, AuthorizationError
from ..model.enums import Stage
from ..orchestrator.pipeline import Pipeline, RunSummary
from ..sandbox.runner import SandboxRunner
from ..storage.db import Database
from ..storage.repositories import Project, Repositories
from ..storage.workspace import Workspace
from .signals import EngineBridge

logger = logging.getLogger(__name__)


class EngineThread(QThread):
    """Runs one pipeline pass off the GUI thread."""

    finished_ok = pyqtSignal(object)        # RunSummary
    failed = pyqtSignal(str)                # human-readable reason

    def __init__(self, *, database: Database, registry: AnalyzerRegistry,
                 sandbox: SandboxRunner, bridge: EngineBridge,
                 project: Project, target: Target, workspace: Workspace,
                 stages: Sequence[Stage] | None = None,
                 analyzers: Sequence[str] | None = None,
                 parent=None) -> None:
        super().__init__(parent)
        self._database = database
        self._registry = registry
        self._sandbox = sandbox
        self._bridge = bridge
        self._project = project
        self._target = target
        self._workspace = workspace
        self._stages = stages
        self._analyzers = analyzers
        self._pipeline: Pipeline | None = None

    # ------------------------------------------------------------------- run

    def run(self) -> None:                                     # noqa: D102, QThread
        repos = Repositories(self._database)          # a connection for THIS thread
        pipeline = Pipeline(self._registry, repos, self._sandbox,
                            AuditTrail(repos.audit), self._bridge.dispatch)
        self._pipeline = pipeline
        try:
            summary: RunSummary = pipeline.run(
                self._project, self._target, self._workspace,
                stages=self._stages, analyzers=self._analyzers)
        except AuthorizationError as exc:
            logger.warning("run refused: %s", exc)
            self.failed.emit(str(exc))
        except Exception as exc:                       # noqa: BLE001
            logger.exception("engine thread failed")
            self.failed.emit(f"{type(exc).__name__}: {exc}")
        else:
            self.finished_ok.emit(summary)
        finally:
            self._pipeline = None
            # Release this thread's SQLite connection; the thread is about to die.
            self._database.close()

    # --------------------------------------------------------------- control

    def stop(self, wait_ms: int = 30_000) -> None:
        """Ask the run to stop, then wait for the analyzer in flight to unwind."""
        pipeline = self._pipeline
        if pipeline is not None:
            pipeline.stop()
        if self.isRunning():
            self.wait(wait_ms)
