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

from PyQt6.QtCore import QEvent, QSize, Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QKeySequence, QShortcut
from PyQt6.QtWidgets import (QApplication, QFileDialog, QFrame, QHBoxLayout,
                             QLabel, QMainWindow, QProgressBar, QPushButton,
                             QStackedWidget, QVBoxLayout, QWidget)

from ..adapters import build_registry
from ..adapters.base import Availability
from ..audit.attestation import Action, AuditTrail, current_operator
from ..adapters.jadx_decompile import read_class_index
from ..correlate.graph import build_snapshot, empty_snapshot
from ..correlate.sections import (SECTIONS, counts_without_graph,
                                  project as project_sections)
from ..model.enums import EntityType, Severity
from ..orchestrator.intake import IntakeError, IntakeResult, target_for
from ..orchestrator.pipeline import RunSummary
from ..report import export as export_report, failed_stages
from ..sandbox.runner import SandboxRunner
from ..storage.db import Database
from ..storage.repositories import Project, Repositories
from ..storage.workspace import Workspace, WorkspaceError
from . import icons, theme
from .winframe import WindowsFrame
from .engine_thread import EngineThread


class _SandboxProbe(QThread):
    """Probe Docker off the UI thread, for the roster and the missing-Docker
    banner both.

    The probe shells out to the docker CLI, which can block for seconds (or
    until a timeout) when the daemon is down or slow. Sweeping every analyzer's
    availability on the UI thread, inside ``load_project`` before the window is
    shown, was the startup hang the operator reported: one ``is_available``
    check plus a cold ``image inspect`` per analyzer, in series. Doing it here
    lets the window appear at once; the real statuses follow when this returns.
    """

    done = pyqtSignal(bool, dict)

    def __init__(self, sandbox, analyzers, parent=None) -> None:
        super().__init__(parent)
        self._sandbox = sandbox
        self._analyzers = list(analyzers)

    def run(self) -> None:                                     # noqa: D102
        statuses: dict[str, str] = {}
        try:
            available = self._sandbox.is_available()
            if available:
                # One `docker images` for the whole roster beats a cold inspect
                # per analyzer, each carrying a 30s timeout.
                self._sandbox.prime_images(
                    [a.image for a in self._analyzers if a.image])
            for analyzer in self._analyzers:
                statuses[analyzer.name] = analyzer.availability(self._sandbox)
        except Exception:                                      # noqa: BLE001
            available = False
        self.done.emit(available, statuses)


class _SnapshotWorker(QThread):
    """Build the graph read model off the UI thread, for live updates.

    During a run the console cannot build the snapshot on the UI thread: the
    engine thread builds its own graph for the analyzers that judge it, and two
    builds at once (plus the UI's NumPy layout) crashed the process. So the live
    rebuild happens here instead, serialised with the engine by ``GRAPH_LOCK``
    inside ``build_snapshot``; the finished snapshot (plain data) is handed back
    to the UI thread, which only has to draw it.
    """

    done = pyqtSignal(str, object, object)        # project_id, snapshot, findings

    def __init__(self, repos, project_id: str, parent=None) -> None:
        super().__init__(parent)
        self._repos = repos
        self._project_id = project_id

    def run(self) -> None:                                     # noqa: D102
        try:
            snapshot = build_snapshot(self._repos, self._project_id)
            findings = self._repos.findings.list(self._project_id)
        except Exception:                                      # noqa: BLE001
            return
        self.done.emit(self._project_id, snapshot, findings)
from .panels.activity import ActivityPanel
from .panels.assistant import AssistantPanel
from .panels.trends import TrendsPanel
from .panels.verdict import VerdictPanel
from .panels.code import CodePanel
from .panels.graph_panel import GraphPanel
from .panels.overview import OverviewPanel
from .panels.queries_panel import QueriesPanel
from .panels.dynamic_panel import DynamicPanel
from .panels.finding_detail import FindingDetail
from .panels.section_panel import SectionPanel
from .signals import EngineBridge
from .widgets.common import Rule, caption, label
from .widgets.dialog import ConfirmDialog, MessageDialog
from .widgets.scan_picker import ScanPicker
from .widgets.secret_gate import SecretGate
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
    ("overview", "Overview", "overview"),
    ("verdict", "Verdict", "verification"),
]
_NAV_BOTTOM = [
    ("code", "Code", "code"),
    ("graph", "Graph", "graph"),
    ("queries", "Questions", "questions"),
    ("dynamic", "Dynamic", "dynamic"),
    ("activity", "Activity", "activity"),
    ("trends", "Trends", "analytics"),
    ("assistant", "Assistant", "assistant"),
]

# A drawn icon per section (icons.py). Geometric strokes, recoloured on
# selection, so nothing in the rail is a Unicode glyph that could render as a box.
_SECTION_ICONS = {
    "platform": "platform",
    "network": "network",
    "secrets": "secrets",
    "crypto": "crypto",
    "storage": "storage",
    "dependencies": "dependencies",
}

# "Reverse engineering" is already the Code page, so its section is drawn there
# rather than duplicated as a seventh nav entry pointing at the same content.
_SECTION_KEYS = [s.key for s in SECTIONS if s.key in _SECTION_ICONS]


class MainWindow(QMainWindow):
    """themob's console."""

    def __init__(self, database: Database, workspace_root: Path,
                 parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("themob")
        self.setMinimumSize(1180, 760)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)
        # No translucency and no painted radius: the native frame (winframe)
        # draws the border, the drop shadow and the rounded corners, and gives
        # the window back Aero Snap, edge resize and the snap-layouts menu.
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
        # Signature of the class index last loaded into the code browser, so a
        # refresh does not rebuild a tens-of-thousands-of-class tree every time
        # the graph changes during a run. None means "nothing loaded".
        self._code_sig: tuple | None = None
        # Per-analyzer availability, computed off the UI thread by the sandbox
        # probe. None until the probe returns; the roster shows "checking" until
        # then and is repainted by _apply_availability once it arrives.
        self._availability: dict[str, str] | None = None
        # True while an analysis run is in flight. The UI must not rebuild the
        # NetworkX read model on the main thread during a run: the engine thread
        # does its own graph work, and the two racing in NetworkX/NumPy (NumPy
        # drops the GIL) corrupted the heap into a native access violation. See
        # refresh() and _refresh_live_counts().
        self._run_active = False
        # Centre the window once, on first show (see _center_on_screen). A
        # frameless window is not placed by the OS, so without this it opens
        # pinned to the top-left corner.
        self._centered = False
        # A scan the operator asked to open while a run was still in flight. The
        # switch waits for the engine to stop; _consume_pending_open performs it
        # once the run has finished, so a switch never orphans a live analyzer.
        self._pending_open: str | None = None
        # The background graph builder for live updates during a run, and a flag
        # that a newer rebuild was requested while one was in flight (coalesced
        # so builds never pile up). See _start_live_snapshot.
        self._snapshot_worker: "_SnapshotWorker | None" = None
        self._snapshot_again = False

        self._build()
        self._wire()

        # The native Windows frame. Installed on first show, once the window has
        # a real handle; the max button is hit-tested for the snap-layouts menu.
        self._frame = WindowsFrame(self, 64, self._titlebar.max_button)
        self._frame_installed = False

        self._install_shortcuts()
        # Probe Docker off the UI thread so the window appears at once; the
        # warning, if any, follows when the probe returns.
        # The probe can outlive this window (it is closed, or in a test
        # collected, while the docker CLI is still responding), and destroying a
        # running QThread aborts the process on Windows. Parent it to the
        # application rather than this window, so collecting the window never
        # destroys it mid-probe; it disposes of itself once finished.
        self._sandbox_probe = _SandboxProbe(
            self._sandbox, self._registry.all(), QApplication.instance() or self)
        self._sandbox_probe.done.connect(self._on_sandbox_probed)
        self._sandbox_probe.finished.connect(self._sandbox_probe.deleteLater)
        self._sandbox_probe.start()

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
        for key, text, icon_name in _NAV_TOP:
            self._sidebar.add_item(key, text, icon_name)
        for section in SECTIONS:
            if section.key in _SECTION_ICONS:
                self._sidebar.add_item(f"section:{section.key}", section.title,
                                       _SECTION_ICONS[section.key])
        for key, text, icon_name in _NAV_BOTTOM:
            self._sidebar.add_item(key, text, icon_name)
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
        self._assistant = AssistantPanel()
        self._assistant.bind(self._workspace_root)
        self._trends = TrendsPanel()
        self._trends.bind(self._workspace_root)
        self._verdict = VerdictPanel()
        self._pages: dict[str, QWidget] = {
            "overview": self._overview,
            "graph": self._graph,
            "code": self._code,
            "queries": self._queries,
            "dynamic": self._dynamic,
            "activity": self._activity,
            "trends": self._trends,
            "assistant": self._assistant,
            "verdict": self._verdict,
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
        self._detail.set_secret_gate(SecretGate(self._workspace_root))
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

        # Open and authorize another app without restarting: the gate runs
        # again, intake makes a new project, and the window switches to it.
        self._new_scan = QPushButton("New scan")
        self._new_scan.setToolTip("Scan another app (Ctrl+O)")
        self._new_scan.setIcon(icons.icon("add", 16, theme.TEXT_SECONDARY))
        self._new_scan.setIconSize(QSize(16, 16))
        self._new_scan.clicked.connect(self.new_scan)
        inner.addWidget(self._new_scan)

        # Reopen a finished scan, restored to the state it ended in. Enabled
        # during a run on purpose: choosing one then prompts to stop the run
        # first, which is how a tester switches between scans.
        self._open_scan = QPushButton("Open scan")
        self._open_scan.setToolTip("Open a saved scan (Ctrl+Shift+O)")
        self._open_scan.setIcon(icons.icon("clock", 16, theme.TEXT_SECONDARY))
        self._open_scan.setIconSize(QSize(16, 16))
        self._open_scan.clicked.connect(self.open_scan)
        inner.addWidget(self._open_scan)

        self._analyze = QPushButton("Analyze")
        self._analyze.setObjectName("primary")
        self._analyze.setToolTip("Analyze (Ctrl+R)")
        self._analyze.setIcon(icons.icon("play", 16, theme.ON_ACCENT))
        self._analyze.setIconSize(QSize(16, 16))
        self._analyze.clicked.connect(lambda: self.start_run())
        inner.addWidget(self._analyze)

        self._stop = QPushButton("Stop")
        self._stop.setEnabled(False)
        self._stop.setToolTip("Stop")
        self._stop.setIcon(icons.icon("stop", 16, theme.TEXT_SECONDARY))
        self._stop.setIconSize(QSize(16, 16))
        self._stop.clicked.connect(self._on_stop)
        inner.addWidget(self._stop)

        # Beside the run controls because it is the last step of the same job:
        # analyze, then hand someone the result. Disabled until there is a
        # project, so it cannot produce an empty document.
        self._export = QPushButton("Export report")
        self._export.setEnabled(False)
        self._export.setToolTip("Export report (Ctrl+E)")
        self._export.setIcon(icons.icon("export", 16, theme.TEXT_SECONDARY))
        self._export.setIconSize(QSize(16, 16))
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
        # Collapsed, the buttons keep their drawn icons and drop their labels.
        self._new_scan.setText("" if collapsed else "New scan")
        self._open_scan.setText("" if collapsed else "Open scan")
        self._analyze.setText("" if collapsed else "Analyze")
        self._stop.setText("" if collapsed else "Stop")
        self._export.setText("" if collapsed else "Export report")
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
        # A run emits graph_changed once per analyzer, and refresh() rebuilds
        # every view from the database. On a large package those rebuilds pile
        # up on the UI thread, so coalesce the live ones: restart a short
        # single-shot timer on each event and rebuild once it goes quiet. The
        # final, authoritative refresh still runs in _on_run_finished.
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setSingleShot(True)
        self._refresh_timer.setInterval(600)
        self._refresh_timer.timeout.connect(self.refresh)
        self._bridge.graph_changed.connect(self._schedule_refresh)
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
        # An approved 'rescan' proposal from the agent re-runs analysis on the
        # already-authorized project, the same as the Analyze button.
        self._assistant.rescan_requested.connect(lambda: self.start_run())
        self._activity.rerun_requested.connect(self._on_rerun)

    def _install_shortcuts(self) -> None:
        """Keyboard paths for the actions the mouse reaches, each named in its
        control's tooltip (section 12b). Ctrl+1..9 jump to a section, Ctrl+B
        toggles the rail, F11 maximizes, and Ctrl+R / Ctrl+E run and export,
        each only when its button is enabled.

        Ctrl+O opens another app: the same authorization gate as startup, now
        reachable in-session so a tester does not restart to scan the next one.
        """
        def bind(sequence: str, handler) -> None:
            QShortcut(QKeySequence(sequence), self, activated=handler)

        order = [key for key, _text, _icon in _NAV_TOP]
        order += [f"section:{s.key}" for s in SECTIONS if s.key in _SECTION_ICONS]
        order += [key for key, _text, _icon in _NAV_BOTTOM]
        for index, key in enumerate(order[:9]):
            bind(f"Ctrl+{index + 1}", lambda k=key: self._sidebar.select(k))
            button = self._sidebar._buttons.get(key)
            if button is not None:
                button.setToolTip(f"{button.toolTip()} (Ctrl+{index + 1})")

        bind("Ctrl+B", self._sidebar.toggle)
        bind("F11", self._toggle_maximized)
        bind("Ctrl+O", lambda: self._new_scan.isEnabled() and self.new_scan())
        bind("Ctrl+Shift+O", self.open_scan)
        bind("Ctrl+R", lambda: self._analyze.isEnabled() and self.start_run())
        bind("Ctrl+E", lambda: self._export.isEnabled() and self._on_export())

    # ------------------------------------------------------------------ project

    def new_scan(self) -> None:
        """Authorize and open another app in place, no restart.

        Runs the same mandatory gate as startup, so a new target is still
        attested and intaken through one path; then the window loads the new
        project. Refused while a run is in flight, so a switch never orphans it.
        """
        if self._engine is not None and self._engine.isRunning():
            MessageDialog.show_info(
                self, "A run is in progress.",
                "Stop the current analysis before opening another app.")
            return

        from .auth_gate import AuthorizationGate, authorize
        from ..orchestrator.intake import IntakeError

        gate = AuthorizationGate(self)
        if gate.exec() != AuthorizationGate.DialogCode.Accepted:
            return
        decision = gate.result()
        if decision is None:
            return
        try:
            result = authorize(decision, self._repos, self._audit,
                               root=self._workspace_root)
        except (IntakeError, PermissionError) as exc:
            MessageDialog.show_error(self, "The target could not be accepted.",
                                     str(exc))
            return
        self.load_project(result)

    def load_project(self, result: IntakeResult) -> None:
        """Adopt the project the authorization gate produced.

        Re-read it rather than trusting the caller's copy: the attestation is
        stamped on the row after intake builds the result, so a stale object
        would render as unauthorized even though the gate was completed.
        """
        stored = self._repos.projects.get(result.project.id)
        self._adopt(stored or result.project, result.workspace, result.target)

    def _adopt(self, project: Project, workspace: Workspace, target) -> None:
        """Make a project the one the window shows, and rebuild every view.

        The single path both a fresh intake (load_project) and reopening a
        saved scan (open_project) go through, so the two cannot drift. A reopen
        may have no live sample on disk, so target is allowed to be None: it is
        needed to re-run analysis, not to browse a finished result.
        """
        self._project = project
        self._workspace = workspace
        self._target = target

        self._titlebar.set_target(
            f"{project.name}   ·   {project.source_sha256[:16]}...")
        self._activity.bind_audit(self._audit, project.id)
        self._activity.set_analyzers(self._registry.all())
        self._apply_availability()     # paint now if the probe already finished
        self._activity.apply_jobs(self._repos.jobs.list(project.id))
        self._footer_left.setText(f"workspace: {workspace.path}")
        self._export.setEnabled(True)
        # Land on the overview: reopening a scan must not leave a finding detail
        # from the scan we just switched away from on screen.
        self._sidebar.select("overview")
        self.refresh()

    def open_scan(self) -> None:
        """Pick a finished scan and reopen it, restored to how it finished."""
        picker = ScanPicker(self, self._repos)
        if picker.exec() != ScanPicker.DialogCode.Accepted:
            return
        if picker.chosen:
            self.open_project(picker.chosen)

    def open_project(self, project_id: str) -> None:
        """Reopen a saved scan by id, prompting to stop any running scan first.

        Everything a scan produces is persisted: its findings, entities and
        graph in the database under the project id, and its artifacts in the
        workspace on disk. So reopening is just adopting that project again and
        rebuilding the views, which restores the scan to the state it finished
        in. A run in flight must end first, or the engine would keep writing
        into a project the window no longer shows, so the switch waits for it.
        """
        if self._engine is not None and self._engine.isRunning():
            if not ConfirmDialog.ask(
                    self, "Stop the running analysis?",
                    "A scan is still running. Opening another scan stops it "
                    "first; the results it has already produced are kept.",
                    title="themob: switch scans",
                    confirm_text="Stop and switch", cancel_text="Keep running"):
                return
            self._pending_open = project_id
            self._on_stop()
            return
        self._do_open_project(project_id)

    def _do_open_project(self, project_id: str) -> None:
        stored = self._repos.projects.get(project_id)
        if stored is None:
            MessageDialog.show_error(
                self, "That scan could not be opened.",
                "Its record is no longer in the database.")
            return
        workspace = Workspace(self._workspace_root, project_id)
        try:
            target = target_for(stored, workspace)
        except (IntakeError, WorkspaceError, OSError):
            # The original sample is gone (moved, deleted, or never kept). The
            # frozen result stays fully browsable; only a re-run needs a sample.
            target = None
        self._adopt(stored, workspace, target)

    def _consume_pending_open(self) -> None:
        """Perform a scan switch that was waiting for a running scan to stop."""
        project_id = self._pending_open
        self._pending_open = None
        if project_id is not None:
            self._do_open_project(project_id)

    def _schedule_refresh(self) -> None:
        """Coalesce a burst of graph_changed events into one rebuild."""
        self._refresh_timer.start()        # restarts the single-shot timer

    def refresh(self) -> None:
        """Rebuild every view from the database."""
        if self._project is None:
            self._overview.clear()
            self._graph.clear()
            self._code.clear()
            self._queries.clear()
            self._dynamic.clear()
            self._assistant.clear()
            self._trends.clear()
            for panel in self._sections.values():
                panel.clear()
            return
        # During a run, move the live numbers at once (cheap DB counts) and
        # build the full read model off the UI thread: the engine thread builds
        # its own graph for the analyzers that judge it, and two NetworkX builds
        # on one thread (plus the UI's NumPy layout) crashed the process. The
        # background build is serialised with the engine by GRAPH_LOCK, and its
        # result is rendered here on the UI thread. The final, authoritative
        # rebuild still runs synchronously in _on_run_finished once the flag is
        # clear, so the end state never depends on a late worker.
        if self._run_active:
            self._refresh_live_counts()
            self._start_live_snapshot()
            return
        snapshot = build_snapshot(self._repos, self._project.id)
        findings = self._repos.findings.list(self._project.id)
        self._render_views(snapshot, findings)

    def _render_views(self, snapshot, findings) -> None:
        """Draw every view from an already-built snapshot. No NetworkX build
        happens here; the graph layout it triggers is serialised by GRAPH_LOCK."""
        if self._project is None:
            return
        self._overview.load(self._project, snapshot, findings)
        self._graph.load(snapshot)
        self._queries.load(snapshot, findings)
        self._dynamic.load(self._project.id, self._workspace)
        self._assistant.load(self._project.id)
        self._trends.load()        # cheap: marks the corpus stale, recomputed on show
        self._refresh_code(snapshot)
        self._refresh_sections(snapshot, findings)
        self._activity.refresh_audit()

        self._sidebar.set_badge("graph", str(len(snapshot)) if len(snapshot) else "")
        self._sidebar.set_badge("overview",
                                str(len(findings)) if findings else "")
        self._footer_right.setText(
            f"{len(snapshot)} entities · {snapshot.edge_count} edges · "
            f"{len(findings)} findings")

    def _start_live_snapshot(self) -> None:
        """Rebuild the views during a run, off the UI thread.

        Coalesced: while a build is in flight, a newer request only sets a flag,
        and one more build runs when it returns, so the work never piles up and
        the views still settle on the latest state.
        """
        if self._project is None:
            return
        if self._snapshot_worker is not None and self._snapshot_worker.isRunning():
            self._snapshot_again = True
            return
        self._snapshot_again = False
        worker = _SnapshotWorker(self._repos, self._project.id,
                                 QApplication.instance() or self)
        worker.done.connect(self._on_live_snapshot)
        worker.finished.connect(self._on_snapshot_finished)
        worker.finished.connect(worker.deleteLater)
        self._snapshot_worker = worker
        worker.start()

    def _on_live_snapshot(self, project_id: str, snapshot, findings) -> None:
        """Render a background build, if it is still the project on screen."""
        if self._project is not None and project_id == self._project.id:
            self._render_views(snapshot, findings)

    def _on_snapshot_finished(self) -> None:
        self._snapshot_worker = None
        # A rebuild was asked for while this one ran, and we are still live.
        if self._snapshot_again and self._run_active:
            self._start_live_snapshot()

    def _refresh_live_counts(self) -> None:
        """Move every nav count during a run without building the NetworkX graph.

        Plain database reads (thread-local connection, WAL), so they are safe
        alongside the engine's writes; the crash was NetworkX on the UI thread,
        not SQLite. The per-section counts come from counts_without_graph, which
        assigns each finding to its section from entity types and the weakness
        key alone, exactly as the full rebuild does but with no graph. Everything
        heavier (the graph render, the code tree) waits for the run to finish.
        """
        if self._project is None:
            return
        try:
            entities = self._repos.entities.list(self._project.id)
            findings = self._repos.findings.list(self._project.id)
        except Exception:                                  # noqa: BLE001
            return
        self._sidebar.set_badge("overview", str(len(findings)) if findings else "")
        self._sidebar.set_badge("graph", str(len(entities)) if entities else "")
        section_counts = counts_without_graph(entities, findings)
        for key in _SECTION_KEYS:
            count = section_counts.get(key, 0)
            self._sidebar.set_badge(f"section:{key}", str(count) if count else "")
        self._footer_right.setText(
            f"{len(entities)} entities · {len(findings)} findings  ·  analysing")

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
        """Point the code browser at whatever jadx last produced.

        Reading the index and rebuilding the class tree is the most expensive
        part of a refresh, and jadx writes the index once. So skip it entirely
        when the file on disk has not changed since the last load: that is what
        stops a refresh during a run from rebuilding a huge tree over and over.
        """
        app = snapshot.root
        if app is None or self._workspace is None:
            self._code.clear()
            self._code_sig = None
            return
        index_path = app.attributes.get("class_index")
        if not index_path:
            self._code.clear()
            self._sidebar.set_badge("code", "")
            self._code_sig = None
            return

        sig = self._code_index_signature(str(index_path))
        if sig is not None and sig == self._code_sig:
            return                          # unchanged: the tree is already built

        index = read_class_index(self._workspace, str(index_path))
        self._code.load(self._workspace, index,
                        partial=bool(app.attributes.get("decompilation_partial")))
        self._sidebar.set_badge("code", f"{len(index):,}" if index else "")
        self._code_sig = sig

    def _code_index_signature(self, index_path: str) -> tuple | None:
        """A cheap fingerprint of the index file (path, mtime, size), or None."""
        if self._workspace is None:
            return None
        try:
            resolved = self._workspace.resolve(index_path)
            stat = resolved.stat()
            return (str(resolved), stat.st_mtime_ns, stat.st_size)
        except (OSError, WorkspaceError):
            return None

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

        if not self._confirm_disk_space():
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

    def _confirm_disk_space(self) -> bool:
        """Warn before a run when free space is low.

        Decompiling and scanning an app can write several GB, and a full disk
        does not fail fast: analyzers error or time out one after another (the
        WinError 112 / ENOSPC cascade). A quick free-space check turns half an
        hour of timeouts into one upfront choice. Override the floor with
        THEMOB_MIN_FREE_DISK_GB; the check never blocks when it cannot read it.
        """
        import os
        import shutil
        try:
            free = shutil.disk_usage(self._workspace_root).free
        except OSError:
            return True
        try:
            floor_gb = float(os.environ.get("THEMOB_MIN_FREE_DISK_GB", "") or 2.0)
        except ValueError:
            floor_gb = 2.0
        if free >= floor_gb * (1024 ** 3):
            return True
        return ConfirmDialog.ask(
            self, "Low disk space.",
            f"Only {free / (1024 ** 3):.1f} GB is free where themob writes its "
            f"work ({self._workspace_root}). Decompiling and scanning an app can "
            "need several GB, and a full disk makes analyzers fail or time out "
            "one after another. Analyze anyway?",
            title="themob: low disk space",
            confirm_text="Analyze anyway", cancel_text="Cancel")

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
        self._refresh_timer.stop()         # the final rebuild supersedes any pending one
        self.refresh()
        if summary.failed:
            names = ", ".join(o.analyzer for o in summary.failed)
            MessageDialog.show_error(
                self, f"The run completed with {len(summary.failed)} failure(s).",
                f"{names}\n\n" + "\n".join(
                    f"{o.analyzer}: {o.error}" for o in summary.failed),
                title="themob: run completed with failures")
        # A switch the operator asked for while this run was still going now
        # proceeds, with the engine stopped and the final state persisted.
        self._consume_pending_open()

    def _on_run_failed(self, reason: str) -> None:
        self._set_running(False)
        self._run_state.setText("Failed")
        MessageDialog.show_error(self, "The analysis run could not start.", reason)
        self._consume_pending_open()

    def _on_analyzer_finished(self, name: str, payload: dict) -> None:
        ok = payload.get("status") == "succeeded"
        self._activity.set_analyzer_status(
            name, "Done" if ok else "Failed", theme.OK if ok else theme.ERROR)
        self._activity.set_analyzer_result(
            name, f"{payload.get('entities', 0)} entities · "
                  f"{payload.get('findings', 0)} findings · "
                  f"{payload.get('duration_s', 0.0):.1f}s")

    def _set_running(self, running: bool) -> None:
        # Gate the read-model rebuild (see refresh). Set before everything else
        # so a graph_changed that lands during this call already sees the state.
        self._run_active = running
        self._analyze.setEnabled(not running)
        # Opening another app mid-run would orphan the analyzer in flight.
        self._new_scan.setEnabled(not running)
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

    def _apply_availability(self) -> None:
        """Paint the roster's status column from the probe's verdict.

        Idempotent and order-independent: called both when the probe returns
        (rows may or may not exist yet) and when a project loads (the verdict
        may or may not be in yet). Whichever happens second does the painting.
        """
        if self._availability is None:
            return
        for name, status in self._availability.items():
            color = theme.OK if status == Availability.READY else theme.WARN
            self._activity.set_analyzer_status(name, status, color)

    def _on_sandbox_probed(self, available: bool, statuses: dict) -> None:
        """Record the roster verdict and warn if Docker is missing.

        The statuses were computed off the UI thread; apply them here, where
        touching widgets is safe.
        """
        self._availability = statuses
        self._apply_availability()
        if available:
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

    def _toggle_maximized(self) -> None:
        self.showNormal() if self.isMaximized() else self.showMaximized()

    def changeEvent(self, event) -> None:                      # noqa: N802
        super().changeEvent(event)
        if event.type() == QEvent.Type.WindowStateChange:
            # Swap the maximise glyph for restore. The native frame draws the
            # corners and insets the maximized client area itself.
            self._titlebar.set_maximized(self.isMaximized())

    def nativeEvent(self, event_type, message):                # noqa: N802
        """Route native Windows messages to the frame for Aero Snap, edge
        resize and the snap-layouts menu.

        Never call ``super().nativeEvent`` here: during window creation it
        crashes with an access violation. Return ``(False, 0)`` for anything the
        frame does not claim.
        """
        frame = getattr(self, "_frame", None)
        if frame is not None and event_type == "windows_generic_MSG":
            handled, result = frame.handle(message)
            if handled:
                return True, result
        return False, 0

    def showEvent(self, event) -> None:                        # noqa: N802
        super().showEvent(event)
        if not self._frame_installed:
            # Installed on first show, once the window has a real native handle.
            self._frame.install()
            self._frame_installed = True
        if not self._centered:
            self._center_on_screen()
            self._centered = True

    def _center_on_screen(self) -> None:
        """Place the window in the middle of its screen, once, on first show.

        A frameless window is not positioned by the OS, so it otherwise opens
        pinned to the top-left corner. Centre it within the work area (which
        excludes the taskbar), and never let the top-left go negative, so a
        window larger than the screen keeps its title bar on screen.
        """
        screen = self.screen() or QApplication.primaryScreen()
        if screen is None:
            return
        available = screen.availableGeometry()
        frame = self.frameGeometry()
        frame.moveCenter(available.center())
        self.move(max(available.left(), frame.left()),
                  max(available.top(), frame.top()))

    def closeEvent(self, event) -> None:                       # noqa: N802
        if self._engine is not None and self._engine.isRunning():
            self._engine.stop()
        self._verdict.shutdown()
        # Let the sandbox probe finish before exit; a running QThread destroyed
        # with the application aborts the process. It may already be gone (it
        # deleteLater's itself when done), so guard the dangling-wrapper case.
        try:
            if self._sandbox_probe.isRunning():
                self._sandbox_probe.wait(3000)
        except RuntimeError:
            pass
        # Same for a live graph build in flight.
        try:
            if self._snapshot_worker is not None and self._snapshot_worker.isRunning():
                self._snapshot_worker.wait(3000)
        except RuntimeError:
            pass
        if self._project is not None:
            try:
                self._audit.record(Action.PIPELINE_FINISHED,
                                   project_id=self._project.id,
                                   state="session_closed")
            except Exception:                      # noqa: BLE001. Never block exit
                logger.debug("closing audit entry failed", exc_info=True)
        self._database.close_all()
        super().closeEvent(event)
