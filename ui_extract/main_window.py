"""The main window: themob's shell.

HiveDefend's layout: a frameless window with a drawn title bar, a collapsible
sidebar driving a ``QStackedWidget``, and a status footer. The window owns the
engine wiring (registry, sandbox, database, audit trail) and hands it to an
:class:`EngineThread` for each run, so the GUI thread only ever renders.

Every destination is one page in that stack: Overview, the six section pages,
Graph, Code and Activity, plus a finding detail the sections open into. The
section pages are generated from ``correlate.sections`` rather than listed
here, so the rail cannot disagree with the queries that fill it.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import QEvent, Qt, QTimer
from PyQt6.QtWidgets import (QFileDialog, QFrame, QHBoxLayout, QLabel,
                             QMainWindow, QProgressBar, QPushButton,
                             QStackedWidget, QVBoxLayout, QWidget)

from ..adapters import build_registry
from ..audit.attestation import Action, AuditTrail, current_operator
from ..adapters.jadx_decompile import read_class_index
from ..correlate.graph import build_snapshot, empty_snapshot
from ..correlate.sections import SECTIONS, project as project_sections
from ..model.enums import EntityType, Severity
from ..orchestrator.intake import IntakeResult, target_for
from ..orchestrator.pipeline import RunSummary
from ..report import export as export_report, failed_stages
from ..sandbox.runner import SandboxRunner
from ..storage.db import Database
from ..storage.repositories import Project, Repositories
from ..storage.workspace import Workspace
from . import theme
from .engine_thread import EngineThread
from .panels.activity import ActivityPanel
from .panels.code import CodePanel
from .panels.graph_panel import GraphPanel
from .panels.overview import OverviewPanel
from .panels.queries_panel import QueriesPanel
from .panels.dynamic_panel import DynamicPanel
from .panels.finding_detail import FindingDetail
from .panels.section_panel import SectionPanel
from .signals import EngineBridge
from .widgets.common import Rule, caption, label
from .widgets.dialog import MessageDialog
from .widgets.logo import app_icon
from .widgets.sidebar import Sidebar
from .widgets.titlebar import TitleBar

logger = logging.getLogger(__name__)

# The nav, in reading order: the summary, then the sections a tester works
# through, then the tools that cut across all of them.
#
# The seven section entries are generated from correlate.sections rather than
# listed here. They are projections of one graph, and a second hand-written list
# would be a second place for them to disagree with the queries that fill them.
_NAV_TOP = [
    ("overview", "Overview", "▣"),
]
_NAV_BOTTOM = [
    ("code", "Code", "❰❱"),
    ("graph", "Graph", "⬡"),
    ("queries", "Questions", "◉"),
    ("dynamic", "Dynamic", "◐"),
    ("activity", "Activity", "≡"),
]

# A glyph per section. Geometric, not emoji: the house style bans emoji as
# iconography, and these have to read at 12px on a collapsed rail.
_SECTION_GLYPHS = {
    "platform": "◫",
    "network": "◈",
    "secrets": "⬢",
    "crypto": "⬗",
    "storage": "▤",
    "dependencies": "❖",
}

# "Reverse engineering" is already the Code page, so its section is drawn there
# rather than duplicated as a seventh nav entry pointing at the same content.
_SECTION_KEYS = [s.key for s in SECTIONS if s.key in _SECTION_GLYPHS]


class MainWindow(QMainWindow):
    """themob's console."""

    def __init__(self, database: Database, workspace_root: Path,
                 parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("themob")
        self.setMinimumSize(1180, 760)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)
        # Translucent so the rounded corners on #root are genuinely cut out
        # rather than drawn over an opaque square, which is what makes the
        # outline look soft instead of clipped.
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        # What the taskbar and the window's hover preview show. Without it the
        # app is a blank placeholder next to every other program.
        icon = app_icon()
        if icon is not None:
            self.setWindowIcon(icon)

        self._database = database
        self._workspace_root = workspace_root
        self._repos = Repositories(database)
        self._audit = AuditTrail(self._repos.audit)
        self._registry = build_registry()
        self._sandbox = SandboxRunner()

        self._project: Project | None = None
        self._workspace: Workspace | None = None
        self._target = None
        self._engine: EngineThread | None = None
        self._bridge = EngineBridge()

        self._build()
        self._wire()
        self._refresh_sandbox_banner()

    # ------------------------------------------------------------------ build

    def _build(self) -> None:
        central = QWidget()
        central.setObjectName("root")
        self.setCentralWidget(central)

        column = QVBoxLayout(central)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(0)

        self._titlebar = TitleBar()
        self._titlebar.minimize_requested.connect(self.showMinimized)
        self._titlebar.maximize_requested.connect(self._toggle_maximized)
        self._titlebar.close_requested.connect(self.close)
        column.addWidget(self._titlebar)

        body = QWidget()
        body_row = QHBoxLayout(body)
        body_row.setContentsMargins(0, 0, 0, 0)
        body_row.setSpacing(0)

        self._sidebar = Sidebar()
        for key, text, glyph in _NAV_TOP:
            self._sidebar.add_item(key, text, glyph)
        for section in SECTIONS:
            if section.key in _SECTION_GLYPHS:
                self._sidebar.add_item(f"section:{section.key}", section.title,
                                       _SECTION_GLYPHS[section.key])
        for key, text, glyph in _NAV_BOTTOM:
            self._sidebar.add_item(key, text, glyph)
        self._sidebar.page_changed.connect(self._on_nav)
        self._sidebar.set_footer_widget(self._build_run_controls())
        self._sidebar.collapsed_changed.connect(self._on_sidebar_collapsed)
        body_row.addWidget(self._sidebar)
        # Parented to the body, not the sidebar, so the round toggle can sit
        # half over the boundary instead of being clipped by the rail it moves.
        self._sidebar.attach_toggle(body)

        self._stack = QStackedWidget()
        self._overview = OverviewPanel()
        self._graph = GraphPanel()
        self._code = CodePanel()
        self._activity = ActivityPanel()
        self._queries = QueriesPanel()
        self._queries.bind(self._repos)
        self._dynamic = DynamicPanel()
        self._dynamic.bind(self._repos, self._audit)
        self._pages: dict[str, QWidget] = {
            "overview": self._overview,
            "graph": self._graph,
            "code": self._code,
            "queries": self._queries,
            "dynamic": self._dynamic,
            "activity": self._activity,
        }
        # One panel per section: a section is a query, not a screen, so they
        # differ only by the view handed to load().
        self._sections: dict[str, SectionPanel] = {}
        for key in _SECTION_KEYS:
            panel = SectionPanel()
            panel.entity_selected.connect(self._focus_entity)
            panel.finding_selected.connect(self._open_finding)
            self._sections[key] = panel
            self._pages[f"section:{key}"] = panel

        # Not a nav destination: a finding takes you here, and Back returns to
        # wherever you came from. Giving it a rail entry would invite clicking
        # it with nothing selected.
        self._detail = FindingDetail()
        self._detail.back_requested.connect(self._close_finding)
        self._detail.verdict_requested.connect(self._on_verdict)
        self._detail.location_requested.connect(self._offer_class)
        self._pages["finding"] = self._detail
        self._detail_return_to = "overview"
        for widget in self._pages.values():
            self._stack.addWidget(widget)
        body_row.addWidget(self._stack, 1)
        column.addWidget(body, 1)

        column.addWidget(self._build_footer())
        self._sidebar.select("overview")

    def _build_run_controls(self) -> QWidget:
        holder = QWidget()
        inner = QVBoxLayout(holder)
        inner.setContentsMargins(10, 8, 10, 4)
        inner.setSpacing(6)
        inner.addWidget(Rule())

        self._run_state = caption("Idle")
        inner.addWidget(self._run_state)

        self._progress = QProgressBar()
        self._progress.setRange(0, 0)            # indeterminate while running
        self._progress.setVisible(False)
        inner.addWidget(self._progress)

        self._analyze = QPushButton("Analyze")
        self._analyze.setObjectName("primary")
        self._analyze.setToolTip("Analyze")
        self._analyze.clicked.connect(lambda: self.start_run())
        inner.addWidget(self._analyze)

        self._stop = QPushButton("Stop")
        self._stop.setEnabled(False)
        self._stop.setToolTip("Stop")
        self._stop.clicked.connect(self._on_stop)
        inner.addWidget(self._stop)

        # Beside the run controls because it is the last step of the same job:
        # analyze, then hand someone the result. Disabled until there is a
        # project, so it cannot produce an empty document.
        self._export = QPushButton("Export report")
        self._export.setEnabled(False)
        self._export.setToolTip("Export report")
        self._export.clicked.connect(self._on_export)
        inner.addWidget(self._export)

        self._run_controls = holder
        self._run_margins = (10, 8, 10, 4)
        return holder

    def _on_sidebar_collapsed(self, collapsed: bool) -> None:
        """Keep the run controls usable on the 52px rail.

        Collapsed, "Analyze" and "Stop" have nowhere to render and came out as
        two blank buttons, which is worse than no buttons: the actions are still
        there and still clickable, they just stop saying what they are. On the
        rail they become their glyphs and keep their tooltips.
        """
        self._analyze.setText("▶" if collapsed else "Analyze")
        self._stop.setText("■" if collapsed else "Stop")
        self._export.setText("▼" if collapsed else "Export report")
        self._run_state.setVisible(not collapsed)
        margins = (6, 8, 6, 4) if collapsed else self._run_margins
        self._run_controls.layout().setContentsMargins(*margins)

    def _build_footer(self) -> QFrame:
        footer = QFrame()
        footer.setObjectName("footer")
        row = QHBoxLayout(footer)
        row.setContentsMargins(18, 0, 18, 0)
        row.setSpacing(18)
        self._footer_left = caption("")
        self._footer_right = caption("")
        row.addWidget(self._footer_left)
        row.addStretch()
        row.addWidget(self._footer_right)
        return footer

    def _wire(self) -> None:
        self._bridge.log.connect(self._activity.append_log)
        self._bridge.state.connect(self._on_state)
        self._bridge.graph_changed.connect(self.refresh)
        self._bridge.analyzer_started.connect(
            lambda name: self._activity.set_analyzer_status(
                name, "Running", theme.ACCENT))
        self._bridge.analyzer_finished.connect(self._on_analyzer_finished)
        self._bridge.analyzer_skipped.connect(
            lambda name, why: self._activity.set_analyzer_status(name, why, theme.WARN))
        self._overview.open_graph_requested.connect(
            lambda: self._sidebar.select("graph"))
        self._overview.entity_selected.connect(self._focus_entity)
        self._overview.finding_selected.connect(self._open_finding)
        self._graph.entity_selected.connect(self._offer_source)
        self._queries.entity_selected.connect(self._focus_entity)
        self._queries.finding_selected.connect(self._open_finding)
        self._dynamic.findings_merged.connect(self.refresh)
        self._activity.rerun_requested.connect(self._on_rerun)

    # ------------------------------------------------------------------ project

    def load_project(self, result: IntakeResult) -> None:
        """Adopt the project the authorization gate produced.

        Re-read it rather than trusting the caller's copy: the attestation is
        stamped on the row after intake builds the result, so a stale object
        would render as unauthorized even though the gate was completed.
        """
        stored = self._repos.projects.get(result.project.id)
        result.project = stored or result.project
        self._project = result.project
        self._workspace = result.workspace
        self._target = result.target

        self._titlebar.set_target(
            f"{result.project.name}   ·   {result.project.source_sha256[:16]}...")
        self._activity.bind_audit(self._audit, result.project.id)
        self._activity.set_analyzers(self._registry.all(), self._sandbox)
        self._activity.apply_jobs(self._repos.jobs.list(result.project.id))
        self._footer_left.setText(
            f"workspace: {result.workspace.path}")
        self._export.setEnabled(True)
        self.refresh()

    def refresh(self) -> None:
        """Rebuild every view from the database. Cheap at one-app sizes."""
        if self._project is None:
            self._overview.clear()
            self._graph.clear()
            self._code.clear()
            self._queries.clear()
            self._dynamic.clear()
            for panel in self._sections.values():
                panel.clear()
            return
        snapshot = build_snapshot(self._repos, self._project.id)
        findings = self._repos.findings.list(self._project.id)
        self._overview.load(self._project, snapshot, findings)
        self._graph.load(snapshot)
        self._queries.load(snapshot, findings)
        self._dynamic.load(self._project.id, self._workspace)
        self._refresh_code(snapshot)
        self._refresh_sections(snapshot, findings)
        self._activity.refresh_audit()

        self._sidebar.set_badge("graph", str(len(snapshot)) if len(snapshot) else "")
        self._sidebar.set_badge("overview",
                                str(len(findings)) if findings else "")
        self._footer_right.setText(
            f"{len(snapshot)} entities · {snapshot.edge_count} edges · "
            f"{len(findings)} findings")

    def _refresh_sections(self, snapshot, findings) -> None:
        """Fill each section panel, and badge its nav entry with its count.

        The badge is the finding count rather than the entity count: a tester
        scanning the rail is looking for where the problems are, and "12
        permissions" competing with "1 exported provider" buries the one that
        matters.
        """
        for view in project_sections(snapshot, findings):
            panel = self._sections.get(view.key)
            if panel is None:
                continue
            panel.load(view, snapshot)
            self._sidebar.set_badge(f"section:{view.key}",
                                    str(len(view.findings)) if view.findings else "")

    def _refresh_code(self, snapshot) -> None:
        """Point the code browser at whatever jadx last produced."""
        app = snapshot.root
        if app is None or self._workspace is None:
            self._code.clear()
            return
        index_path = app.attributes.get("class_index")
        if not index_path:
            self._code.clear()
            self._sidebar.set_badge("code", "")
            return
        index = read_class_index(self._workspace, str(index_path))
        self._code.load(self._workspace, index,
                        partial=bool(app.attributes.get("decompilation_partial")))
        self._sidebar.set_badge("code", f"{len(index):,}" if index else "")

    # ---------------------------------------------------------------- running

    def start_run(self, analyzers: list[str] | None = None) -> None:
        if self._project is None or self._workspace is None:
            MessageDialog.show_error(self, "No project is loaded.")
            return
        if self._engine is not None and self._engine.isRunning():
            MessageDialog.show_info(self, "An analysis run is already in progress.")
            return

        try:
            target = self._target or target_for(self._project, self._workspace)
        except Exception as exc:                   # noqa: BLE001
            MessageDialog.show_error(self, "The sample could not be located.",
                                     str(exc))
            return

        self._activity.clear_log()
        self._set_running(True)
        self._engine = EngineThread(
            database=self._database, registry=self._registry,
            sandbox=self._sandbox, bridge=self._bridge, project=self._project,
            target=target, workspace=self._workspace, analyzers=analyzers,
            parent=self)
        self._engine.finished_ok.connect(self._on_run_finished)
        self._engine.failed.connect(self._on_run_failed)
        self._engine.start()

    def _on_stop(self) -> None:
        if self._engine is not None and self._engine.isRunning():
            self._stop.setEnabled(False)
            self._run_state.setText("Stopping")
            self._engine.stop()

    def _on_rerun(self, analyzer: str) -> None:
        self._sidebar.select("activity")
        self.start_run(analyzers=[analyzer])

    def _on_run_finished(self, summary: RunSummary) -> None:
        self._set_running(False)
        self.refresh()
        if summary.failed:
            names = ", ".join(o.analyzer for o in summary.failed)
            MessageDialog.show_error(
                self, f"The run completed with {len(summary.failed)} failure(s).",
                f"{names}\n\n" + "\n".join(
                    f"{o.analyzer}: {o.error}" for o in summary.failed),
                title="themob: run completed with failures")

    def _on_run_failed(self, reason: str) -> None:
        self._set_running(False)
        self._run_state.setText("Failed")
        MessageDialog.show_error(self, "The analysis run could not start.", reason)

    def _on_analyzer_finished(self, name: str, payload: dict) -> None:
        ok = payload.get("status") == "succeeded"
        self._activity.set_analyzer_status(
            name, "Done" if ok else "Failed", theme.OK if ok else theme.ERROR)
        self._activity.set_analyzer_result(
            name, f"{payload.get('entities', 0)} entities · "
                  f"{payload.get('findings', 0)} findings · "
                  f"{payload.get('duration_s', 0.0):.1f}s")

    def _set_running(self, running: bool) -> None:
        self._analyze.setEnabled(not running)
        self._stop.setEnabled(running)
        # A report written mid-run would read as a finished assessment while
        # analyzers that have not reported yet are simply absent from it.
        self._export.setEnabled(not running and self._project is not None)
        self._progress.setVisible(running)
        self._run_state.setText("Running" if running else "Idle")
        self._run_state.setStyleSheet(
            f"color:{theme.ACCENT if running else theme.TEXT_MUTED};"
            "font-size:11px;")
        self._titlebar.set_status("analysis running..." if running else "")

    def _on_state(self, state: str) -> None:
        if state:
            self._run_state.setText(state.title())

    # ---------------------------------------------------------------- misc UI

    def _refresh_sandbox_banner(self) -> None:
        """Tell the operator up front if Docker is missing. Everything needs it."""
        if self._sandbox.is_available():
            return
        QTimer.singleShot(400, lambda: MessageDialog.show_error(
            self,
            "Docker is not available, so no analyzer can run.",
            "themob parses untrusted app packages only inside network-less, "
            "resource-limited containers. It will not fall back to parsing them "
            "in this process. Start Docker Desktop (or the docker daemon), then "
            "build the worker images and reopen themob.",
            title="themob: sandbox unavailable"))

    def _on_nav(self, key: str) -> None:
        page = self._pages.get(key)
        if page is not None:
            self._stack.setCurrentWidget(page)

    def _open_finding(self, fingerprint: str) -> None:
        """Show one finding in full, remembering where to go back to."""
        if self._project is None:
            return
        finding = self._repos.findings.get_by_fingerprint(
            self._project.id, fingerprint)
        if finding is None:
            return
        self._detail_return_to = self._sidebar.current() or "overview"
        self._detail.load(finding,
                          self._repos.findings.notes(finding.id),
                          self._repos.findings.source_votes(finding.id))
        self._stack.setCurrentWidget(self._detail)

    def _close_finding(self) -> None:
        self._sidebar.select(self._detail_return_to)

    def _on_verdict(self, finding_id: str, status, note: str) -> None:
        """Record the tester's verdict, and say plainly when it is refused.

        The engine refuses an unexplained suppression. Swallowing that would
        leave the tester thinking the click worked.
        """
        from ..orchestrator.validation import ValidationError, record

        try:
            verdict = record(self._repos, self._audit, finding_id, status,
                             operator=current_operator(), note=note)
        except ValidationError as exc:
            MessageDialog.show_error(
                self, "That verdict was not recorded.", str(exc),
                title="themob: verdict refused")
            return

        self._detail.load(verdict.finding,
                          self._repos.findings.notes(finding_id),
                          self._repos.findings.source_votes(finding_id))
        self._activity.refresh_audit()
        self.refresh()

    def _on_export(self) -> None:
        """Write the HTML and JSON report to a directory the operator picks.

        The confirmation repeats the report's own caveats rather than saying
        only that files were written. Someone is about to forward this, and an
        incomplete assessment that looks complete is the failure mode worth
        spending a dialog on.
        """
        if self._project is None:
            return

        start = (self._workspace.reports_dir if self._workspace is not None
                 else Path.home())
        start.mkdir(parents=True, exist_ok=True)
        chosen = QFileDialog.getExistingDirectory(
            self, "Export report to", str(start))
        if not chosen:
            return

        try:
            written = export_report(self._repos, self._audit, self._project.id,
                                    chosen, operator=current_operator(),
                                    workspace=self._workspace)
        except Exception as exc:                       # noqa: BLE001
            logger.exception("report export failed")
            MessageDialog.show_error(
                self, "The report could not be written.", str(exc))
            return

        self._activity.refresh_audit()
        report = written.report
        detail = "\n".join(str(path) for path in written.files.values())

        caveats: list[str] = []
        if report is not None:
            failed = failed_stages(report)
            if failed:
                names = ", ".join(str(s.get("analyzer") or s.get("stage"))
                                  for s in failed)
                caveats.append(f"{names} did not finish, so the report says its "
                               "coverage is incomplete.")
            if not report.provenance.audit_chain_ok:
                caveats.append("The audit chain does not verify, and the report "
                               "says so on its first page.")
            if not report.provenance.authorized:
                caveats.append("This project carries no authorization "
                               "attestation.")

        total = report.total if report is not None else 0
        summary = f"Report written: {total} findings"
        if report is not None and report.suppressed:
            summary += f", {len(report.suppressed)} dismissed"
        summary += "."
        if caveats:
            summary += " " + " ".join(caveats)

        MessageDialog(self, title="themob", message=summary, detail=detail,
                      tone="warn" if caveats else "info").exec()

    def _offer_class(self, fqcn: str) -> None:
        """Jump from a finding's location to the decompiled class."""
        if self._code.open_class(fqcn):
            self._sidebar.select("code")

    def _focus_entity(self, entity_id: str) -> None:
        self._sidebar.select("graph")
        self._graph.focus_entity(entity_id)

    def _offer_source(self, entity_id: str) -> None:
        """Selecting a component in the graph pre-loads its decompiled class.

        It does not steal focus to the Code page, a tester panning the graph
        would find that infuriating: it just means the source is already there
        when they switch.
        """
        if self._project is None or not entity_id:
            return
        entity = self._repos.entities.get(entity_id)
        if entity is None or entity.type is not EntityType.COMPONENT:
            return
        if self._code.has_class(entity.key):
            self._code.open_class(entity.key)
            self._sidebar.set_badge("code", "●")

    def _toggle_maximized(self) -> None:
        self.showNormal() if self.isMaximized() else self.showMaximized()
        self._sync_window_shape()

    def _sync_window_shape(self) -> None:
        """A maximised window has square corners; a floating one is rounded.

        Keeping the radius while maximised leaves four transparent notches over
        the desktop, which reads as a rendering fault rather than a style.
        """
        maximized = self.isMaximized()
        self._titlebar.set_maximized(maximized)
        root = self.findChild(QWidget, "root")
        if root is not None:
            root.setProperty("maximized", "true" if maximized else "false")
            root.style().unpolish(root)
            root.style().polish(root)

    def changeEvent(self, event) -> None:                      # noqa: N802
        super().changeEvent(event)
        if event.type() == QEvent.Type.WindowStateChange:
            self._sync_window_shape()

    def closeEvent(self, event) -> None:                       # noqa: N802
        if self._engine is not None and self._engine.isRunning():
            self._engine.stop()
        if self._project is not None:
            try:
                self._audit.record(Action.PIPELINE_FINISHED,
                                   project_id=self._project.id,
                                   state="session_closed")
            except Exception:                      # noqa: BLE001. Never block exit
                logger.debug("closing audit entry failed", exc_info=True)
        self._database.close_all()
        super().closeEvent(event)
