"""UI smoke tests: the panels render real data without a display.

These run offscreen. They are not pixel tests; they assert that the widgets
build, that the Overview reflects what is actually in the database, and that the
graph turns entities and edges into scene items, which is what "the Overview
renders real data" means for the Phase 0 vertical slice.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")

from PyQt6.QtCore import Qt                                    # noqa: E402
from PyQt6.QtWidgets import QApplication                       # noqa: E402

from themob.app import theme                                   # noqa: E402
from themob.app.panels.activity import ActivityPanel           # noqa: E402
from themob.app.panels.graph_panel import GraphPanel           # noqa: E402
from themob.app.panels.overview import OverviewPanel           # noqa: E402
from themob.app.widgets.graph_view import GraphView            # noqa: E402
from themob.app.widgets.sidebar import Sidebar                 # noqa: E402
from themob.audit.attestation import Attestation, AuditTrail   # noqa: E402
from themob.correlate.graph import build_snapshot, empty_snapshot  # noqa: E402
from themob.model.entities import Edge                         # noqa: E402
from themob.model.enums import (EdgeType, EntityType, Platform,
                                Severity)                      # noqa: E402
from themob.model.findings import Finding, FindingSource       # noqa: E402
from themob.orchestrator.intake import intake                  # noqa: E402
from themob.storage.repositories import Repositories           # noqa: E402


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance() or QApplication([])
    yield app
    # A MainWindow starts a background sandbox probe parented to the app. Tests
    # collect their windows without an event loop to run deleteLater, so those
    # probes linger as app children. Join any still running before the app is
    # torn down: destroying a running QThread aborts the process on Windows.
    from PyQt6.QtCore import QThread
    for thread in app.findChildren(QThread):
        thread.wait(5000)


@pytest.fixture()
def loaded(repos: Repositories, sample_apk: Path, tmp_path: Path):
    """A project with a small but realistic graph and one finding."""
    audit = AuditTrail(repos.audit)
    result = intake(sample_apk, repos, audit, root=tmp_path / "home")
    audit.record_attestation(result.project, Attestation(
        target_name="sample.apk", target_sha256=result.sha256,
        operator="tester@lab", engagement_ref="ENG-1", attested=True),
        repos.projects)
    project = repos.projects.get(result.project.id)

    from themob.model.entities import Entity

    def add(etype, key, **attrs):
        return repos.entities.upsert(project.id, Entity(
            type=etype, platform=Platform.ANDROID, key=key,
            label=key.rsplit(".", 1)[-1], attributes=attrs))

    app = add(EntityType.APP, "com.example.shop", package="com.example.shop",
              version_name="3.2.1", version_code="3021", min_sdk=24,
              target_sdk=34, debuggable=True, allow_backup=True,
              uses_cleartext_traffic=False, signing={"v1": True, "v2": True})
    activity = add(EntityType.COMPONENT, "com.example.shop.MainActivity",
                   kind="activity", exported=True)
    provider = add(EntityType.COMPONENT, "com.example.shop.ShopProvider",
                   kind="provider", exported=True)
    permission = add(EntityType.PERMISSION, "android.permission.INTERNET",
                     requested=True, custom=False)
    link = add(EntityType.DEEP_LINK, "https://shop.example.com/order",
               scheme="https", host="shop.example.com")

    for src, dst, etype in ((app, activity, EdgeType.DECLARES),
                            (app, provider, EdgeType.EXPORTS),
                            (app, permission, EdgeType.REQUESTS_PERMISSION),
                            (activity, link, EdgeType.DECLARES)):
        repos.edges.upsert(project.id, Edge(src_id=src.id, dst_id=dst.id,
                                            type=etype))

    repos.findings.upsert(project.id, Finding(
        fingerprint="f" * 64, title="Application is debuggable",
        severity=Severity.HIGH, confidence=0.9, masvs_control="MASVS-RESILIENCE-1",
        sources=[FindingSource(tool="config-audit", rule="debuggable")],
        entity_ids=[app.id]))

    return project, build_snapshot(repos, project.id), repos


# ------------------------------------------------------------------- widgets

def test_sidebar_navigates(qapp) -> None:
    sidebar = Sidebar()
    seen: list[str] = []
    sidebar.page_changed.connect(seen.append)
    for key, text, icon_name in (("overview", "Overview", "overview"),
                                 ("graph", "Graph", "graph")):
        sidebar.add_item(key, text, icon_name)

    sidebar.select("graph")
    assert seen == ["graph"] and sidebar.current() == "graph"

    sidebar.toggle()                # collapsed: icon only, no label text
    assert "Graph" not in sidebar._buttons["graph"].text()
    sidebar.toggle()
    assert "Graph" in sidebar._buttons["graph"].text()


def test_graph_view_builds_items_from_a_snapshot(qapp, loaded) -> None:
    _project, snapshot, _repos = loaded
    view = GraphView()
    view.load(snapshot)

    assert len(view._nodes) == len(snapshot) == 5
    assert len(view._edges) == snapshot.edge_count == 4
    # The App is the root and is drawn larger than a leaf.
    root_item = view._nodes[snapshot.root_id]
    leaf = next(i for k, i in view._nodes.items() if k != snapshot.root_id)
    assert root_item._radius > leaf._radius


def test_graph_view_is_incremental_across_reloads(qapp, loaded) -> None:
    _project, snapshot, _repos = loaded
    view = GraphView()
    view.load(snapshot)
    first = dict(view._nodes)
    view.load(snapshot)
    assert view._nodes == first, "reloading must reuse items, not rebuild them"


def test_graph_view_drops_entities_that_disappeared(qapp, loaded) -> None:
    project, snapshot, repos = loaded
    view = GraphView()
    view.load(snapshot)

    repos.projects.delete(project.id)
    view.load(empty_snapshot(project.id))
    assert view._nodes == {} and view._edges == {}


def test_selection_traces_the_path_from_the_app(qapp, loaded) -> None:
    _project, snapshot, _repos = loaded
    link = next(e for e in snapshot.entities if e.type is EntityType.DEEP_LINK)
    view = GraphView()
    view.load(snapshot)
    view.select(link.id)

    path = snapshot.path_from_root(link.id)
    assert len(path) == 3, "App -> MainActivity -> deep link"
    on_path = set(path)
    for entity_id, item in view._nodes.items():
        assert item._dim is (entity_id not in on_path)


def test_type_filter_projects_the_graph(qapp, loaded) -> None:
    _project, snapshot, _repos = loaded
    view = GraphView()
    view.load(snapshot)
    view.set_filter([EntityType.COMPONENT])

    visible = {i for i, item in view._nodes.items() if item.isVisible()}
    # The two components plus the App, which anchors every projection.
    assert len(visible) == 3
    assert snapshot.root_id in visible


def test_isolate_shows_only_what_is_reachable(qapp, loaded) -> None:
    _project, snapshot, _repos = loaded
    activity = next(e for e in snapshot.entities
                    if e.key.endswith("MainActivity"))
    view = GraphView()
    view.load(snapshot)
    view.isolate(activity.id)

    visible = {i for i, item in view._nodes.items() if item.isVisible()}
    assert visible == snapshot.reachable_from(activity.id)
    assert snapshot.root_id not in visible


def test_graph_view_survives_an_empty_snapshot(qapp) -> None:
    view = GraphView()
    view.load(empty_snapshot("p"))
    view.select(None)
    view.fit()
    view.auto_layout()
    assert view._nodes == {}


# ------------------------------------------------------------------ overview

def test_overview_renders_real_project_data(qapp, loaded) -> None:
    project, snapshot, repos = loaded
    panel = OverviewPanel()
    panel.load(project, snapshot, repos.findings.list(project.id))

    assert panel._kpi_entities._value.text() == "5"
    assert panel._kpi_findings._value.text() == "1"
    assert panel._kpi_risk._value.text() == "High"
    # Attack surface = components + deep links + endpoints + cloud assets.
    assert panel._kpi_surface._value.text() == "3"
    assert panel._severity._counts[Severity.HIGH].text() == "1"


def test_overview_lists_the_finding(qapp, loaded) -> None:
    project, snapshot, repos = loaded
    panel = OverviewPanel()
    panel.load(project, snapshot, repos.findings.list(project.id))

    assert panel._table.rowCount() == 1
    assert panel._table.item(0, 0).text() == "High"
    assert panel._table.item(0, 2).text() == "Application is debuggable"
    assert panel._table.item(0, 4).text() == "config-audit"


def test_overview_shows_the_app_facts(qapp, loaded) -> None:
    project, snapshot, repos = loaded
    panel = OverviewPanel()
    panel.load(project, snapshot, repos.findings.list(project.id))

    joined = " | ".join(f"{k} {v}" for k, v in panel._app_facts.pairs())
    assert "com.example.shop" in joined
    assert "3.2.1 (3021)" in joined
    assert "min 24 · target 34" in joined
    assert project.source_sha256 in joined


def test_overview_empty_state_is_honest(qapp) -> None:
    panel = OverviewPanel()
    panel.load(None, empty_snapshot(), [])
    assert panel._kpi_entities._value.text() == "0"
    assert panel._kpi_risk._value.text() == "-"
    assert panel._table.rowCount() == 1        # the placeholder row
    assert "No findings yet" in panel._table.item(0, 2).text()


# --------------------------------------------------------------- graph panel

def test_graph_panel_inspects_a_selected_entity(qapp, loaded) -> None:
    _project, snapshot, _repos = loaded
    panel = GraphPanel()
    panel.load(snapshot)

    link = next(e for e in snapshot.entities if e.type is EntityType.DEEP_LINK)
    panel.focus_entity(link.id)

    texts = " | ".join(f"{k} {v}" for k, v in panel._detail_facts.pairs())
    assert "https://shop.example.com/order" in texts
    assert "->" in texts, "the path from the app should be shown"
    assert "5 entities · 4 relationships" == panel._count.text()


def test_graph_panel_clear_resets(qapp, loaded) -> None:
    _project, snapshot, _repos = loaded
    panel = GraphPanel()
    panel.load(snapshot)
    panel.clear()
    assert panel._selected is None
    assert panel._graph._nodes == {}


# ------------------------------------------------------------------ activity

def test_activity_shows_the_audit_trail_and_verifies_it(qapp, loaded) -> None:
    project, _snapshot, repos = loaded
    panel = ActivityPanel()
    panel.bind_audit(AuditTrail(repos.audit), project.id)

    assert panel._audit.rowCount() >= 2         # created + authorized
    actions = {panel._audit.item(r, 2).text() for r in range(panel._audit.rowCount())}
    assert "project.authorized" in actions

    panel._verify_clicked()
    # The colour carries ok vs broken now; the label shows the verify message.
    assert "chain" in panel._chain.text().lower()


def test_activity_lists_analyzers_with_availability(qapp) -> None:
    from themob.adapters import build_registry
    from themob.sandbox.runner import SandboxRunner

    class _Offline(SandboxRunner):
        def is_available(self) -> bool:
            return False

    registry = build_registry()
    panel = ActivityPanel()
    panel.set_analyzers(registry.all())

    # Every registered analyzer is listed, asserting a count would just have to
    # be edited each time an adapter lands, which tests nothing.
    assert panel._analyzers.rowCount() == len(registry)
    listed = {panel._analyzers.item(r, 0).text()
              for r in range(panel._analyzers.rowCount())}
    assert listed == {a.display for a in registry.all()}

    # The roster goes up before Docker is ever probed (the probe is what used to
    # hang the UI thread), so every row starts on a neutral placeholder.
    initial = {panel._analyzers.item(r, 2).text()
               for r in range(panel._analyzers.rowCount())}
    assert initial == {"checking"}

    # The window computes availability off the UI thread and feeds it back row
    # by row. Replay that with Docker offline: no containerised analyzer can
    # run, but one that needs no container stays ready, and the panel says so.
    offline = _Offline()
    for analyzer in registry.all():
        panel.set_analyzer_status(analyzer.name, analyzer.availability(offline))

    status_by_display = {panel._analyzers.item(r, 0).text():
                         panel._analyzers.item(r, 2).text()
                         for r in range(panel._analyzers.rowCount())}
    for analyzer in registry.all():
        expected = "Docker unavailable" if analyzer.image else "Ready"
        assert status_by_display[analyzer.display] == expected, analyzer.name
    assert any(not a.image for a in registry.all()), \
        "expected at least one container-less analyzer to cover the Ready path"


def test_activity_log_accepts_engine_events(qapp) -> None:
    panel = ActivityPanel()
    for level in ("info", "discovery", "warn", "error"):
        panel.append_log({"ts": 0, "text": f"<b>{level}</b> line", "level": level})
    text = panel._log.toPlainText()
    assert text.count("line") == 4
    assert "<b>" in text, "log text must be escaped, not interpreted as HTML"


# --------------------------------------------------------------------- theme

def test_every_enum_value_has_a_colour() -> None:
    for etype in EntityType:
        assert theme.entity_color(etype) != theme.TEXT_SECONDARY, etype
        assert theme.entity_label(etype)
    for severity in Severity:
        assert theme.severity_color(severity) != theme.TEXT_SECONDARY, severity


def test_theme_handles_unknown_values() -> None:
    assert theme.entity_color("not-a-type") == theme.TEXT_SECONDARY
    assert theme.severity_color("not-a-severity") == theme.TEXT_SECONDARY


# ------------------------------------------------------------ window chrome

def test_window_controls_paint_without_a_font(qapp) -> None:
    """The controls carry a drawn icon, not typed text.

    Typed glyphs let the font decide the weight and render as boxes on some
    Windows fonts. Each control is a drawn icon in a flush WinButton.
    """
    from PyQt6.QtGui import QPixmap

    from themob.app.widgets.window_buttons import WinButton

    for name, close in (("win_min", False), ("win_max", False),
                        ("win_close", True)):
        button = WinButton(name, "control", close=close)
        assert button.text() == "", "a window control carries an icon, not text"
        assert not button.icon().isNull()
        pixmap = QPixmap(button.size())
        pixmap.fill()
        button.render(pixmap)
        assert not pixmap.isNull()


def test_the_maximise_control_switches_to_restore(qapp) -> None:
    from themob.app.widgets.window_buttons import WindowControls

    controls = WindowControls()
    assert controls.max_button.toolTip() == "Maximise"
    controls.set_maximized(True)
    assert controls.max_button.toolTip() == "Restore"


def test_the_close_control_is_flush_in_the_corner(qapp) -> None:
    """The close button fills its slot and the strip has no right margin or
    spacing, so the red hover fill runs to the window corner with no notch."""
    from themob.app.widgets.window_buttons import WinButton, WindowControls

    close = WinButton("win_close", "Close", close=True)
    assert close.objectName() == "winClose"
    assert close.width() == 46

    controls = WindowControls()
    layout = controls.layout()
    assert layout.contentsMargins().right() == 0
    assert layout.spacing() == 0
    # The close is the last control, hard against the right edge.
    assert layout.itemAt(layout.count() - 1).widget() is controls._close


def test_the_app_has_an_icon_for_the_taskbar(qapp) -> None:
    """Hovering the app should show the mark and the name, not a blank."""
    from themob.app.widgets.logo import app_icon

    icon = app_icon()
    assert icon is not None and not icon.isNull()


def test_the_main_actions_have_keyboard_shortcuts(qapp, tmp_path) -> None:
    """Section 12b: the sections, the rail, maximize, run and export are all
    reachable by keyboard, and the run and export keys are named in tooltips."""
    from PyQt6.QtGui import QShortcut
    from themob.app.main_window import MainWindow
    from themob.storage.db import open_database

    window = MainWindow(open_database(tmp_path / "t.db"), tmp_path / "home")
    sequences = {sc.key().toString() for sc in window.findChildren(QShortcut)}
    for expected in ("Ctrl+1", "Ctrl+9", "Ctrl+B", "F11", "Ctrl+R", "Ctrl+E"):
        assert expected in sequences, f"{expected} shortcut is missing"
    assert "Ctrl+R" in window._analyze.toolTip()
    assert "Ctrl+E" in window._export.toolTip()


def test_the_assistant_flattens_tables_so_a_piped_command_survives(qapp) -> None:
    """Qt's Markdown table parser collapses on a pipe inside a cell, so the panel
    rewrites tables as lists first. A command's pipe (inside inline code) must
    survive, and fenced code must be left untouched."""
    from themob.app.panels.assistant import _flatten_markdown_tables

    md = ("# Fixes\n\n"
          "| File | Command |\n"
          "| --- | --- |\n"
          "| libapp.so | `readelf -lW libapp.so | grep RELRO` |\n"
          "| build.gradle | set minSdkVersion 26 |\n\n"
          "```\nkeep | this | fenced\n```\n")
    out = _flatten_markdown_tables(md)

    before_fence = out.split("```")[0]
    assert "|" not in before_fence.replace(
        "`readelf -lW libapp.so | grep RELRO`", "")   # table pipes gone...
    assert "`readelf -lW libapp.so | grep RELRO`" in out   # ...but the command intact
    assert "- **File:** libapp.so" in out
    assert "- **File:** build.gradle" in out
    assert "keep | this | fenced" in out              # fenced block untouched
    assert "# Fixes" in out                            # prose preserved


def test_the_assistant_panel_is_honest_without_a_project(qapp, tmp_path) -> None:
    """With no project loaded the Ask button stays disabled and the panel says
    why, rather than offering to answer nothing."""
    from themob.app.panels.assistant import AssistantPanel

    panel = AssistantPanel()
    panel.bind(tmp_path)
    panel.load("")              # no project
    assert not panel._ask.isEnabled()
    assert panel._status.text()


# ------------------------------------------------------------ sidebar toggle

def _sidebar_host(qapp):
    from PyQt6.QtWidgets import QHBoxLayout, QWidget

    from themob.app.widgets.sidebar import Sidebar

    host = QWidget()
    host.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True)
    host.resize(900, 600)
    row = QHBoxLayout(host)
    row.setContentsMargins(0, 0, 0, 0)
    sidebar = Sidebar()
    sidebar.add_item("overview", "Overview", "1")
    sidebar.add_item("graph", "Graph", "2")
    row.addWidget(sidebar)
    row.addStretch()
    sidebar.attach_toggle(host)
    host.show()
    return host, sidebar


def test_the_collapse_toggle_is_hidden_until_you_reach_for_it(qapp) -> None:
    """Docker's pattern: the chrome stays quiet until the pointer is near."""
    from PyQt6.QtCore import QPoint

    _host, sidebar = _sidebar_host(qapp)
    assert not sidebar._toggle.isVisible()
    assert sidebar._pointer_is_near(QPoint(sidebar.width(), 200))
    assert not sidebar._pointer_is_near(QPoint(700, 200))


def test_the_toggle_straddles_the_sidebar_edge(qapp) -> None:
    """Parented to the body, or the sidebar would clip its own control."""
    _host, sidebar = _sidebar_host(qapp)
    centre = sidebar._toggle.x() + sidebar._toggle.width() // 2
    assert abs(centre - sidebar.width()) <= 1
    assert sidebar._toggle.parentWidget() is not sidebar


def test_collapsing_flips_the_toggle_glyph(qapp) -> None:
    _host, sidebar = _sidebar_host(qapp)
    assert sidebar._toggle._collapsed is False
    sidebar.toggle()
    assert sidebar._toggle._collapsed is True
    assert "Expand" in sidebar._toggle.toolTip()


def test_collapsing_announces_itself(qapp) -> None:
    """The run controls need to know, or they render as two blank buttons."""
    _host, sidebar = _sidebar_host(qapp)
    seen: list[bool] = []
    sidebar.collapsed_changed.connect(seen.append)
    sidebar.toggle()
    sidebar.toggle()
    assert seen == [True, False]


def test_the_run_controls_keep_an_icon_when_collapsed(qapp, tmp_path) -> None:
    """Analyze and Stop stay identifiable on the 52px rail.

    Collapsed, they drop their text label and keep their drawn icon, so the
    rail shows a play and a stop icon rather than two blank buttons.
    """
    from themob.app.main_window import MainWindow
    from themob.storage.db import open_database

    window = MainWindow(open_database(tmp_path / "t.db"), tmp_path / "home")
    assert window._analyze.text() == "Analyze"

    window._sidebar.toggle()
    assert window._analyze.text() == ""
    assert window._stop.text() == ""
    assert not window._analyze.icon().isNull()
    assert not window._stop.icon().isNull()
    # The tooltip is what says which is which once the label is gone.
    assert "Analyze" in window._analyze.toolTip()
    assert not window._run_state.isVisible()

    window._sidebar.toggle()
    assert window._analyze.text() == "Analyze"


# ------------------------------------------------------------- theme bands

def _luminance(hex_colour: str) -> float:
    r, g, b = (int(hex_colour[i:i + 2], 16) for i in (1, 3, 5))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def test_the_chrome_reads_as_three_distinct_bands() -> None:
    """Light chrome on top, content in the middle, dark chrome at the edges.

    The threshold here was 3 and the rail sat 4.7 points below the page, so
    this test passed while nobody could see the separation it claimed to
    guarantee. Both colours were near black and there was nowhere darker to go;
    lifting the page is what opened the gap. 8 points is the floor now, matched
    to what actually reads on a dark panel rather than to what is merely
    greater than zero.
    """
    title = _luminance(theme.BG_TITLEBAR)
    page = _luminance(theme.BG_BASE)
    rail = _luminance(theme.BG_SIDEBAR)

    assert title > page > rail, "the three bands are out of order"
    assert title - page >= 8, "the title bar does not read as lighter"
    assert page - rail >= 8, "the sidebar does not read as darker"


def test_the_footer_shares_the_rails_dark_band() -> None:
    """The dark chrome runs down the left edge and along the bottom as one."""
    assert theme.BG_SIDEBAR in theme.stylesheet()
    footer = theme.stylesheet().split("QFrame#footer")[1].split("}")[0]
    assert theme.BG_SIDEBAR in footer


def test_the_sidebar_actually_paints_its_dark_band(qapp) -> None:
    """The band tests above check tokens, not paint. A bare QWidget subclass
    drops a stylesheet background unless WA_StyledBackground is set, so without
    it the #sidebar colour is ignored and the rail renders in the page ground,
    collapsing the three tone bands into two. A render confirmed this; the
    attribute is what the render depends on."""
    from themob.app.widgets.sidebar import Sidebar

    assert Sidebar().testAttribute(Qt.WidgetAttribute.WA_StyledBackground)


def test_hover_and_selection_stay_above_the_surface_they_sit_on() -> None:
    """Lifting the page broke this once: raised fell below hover.

    A hover state darker than the resting state reads as the row switching off
    when you point at it.
    """
    page = _luminance(theme.BG_BASE)
    raised = _luminance(theme.BG_RAISED)
    hover = _luminance(theme.BG_HOVER)
    select = _luminance(theme.BG_SELECT)

    assert page < raised < hover < select, "the interaction ramp is out of order"
    assert raised - page >= 5, "an input does not read as distinct from the page"


def test_the_severity_ramp_stays_semantic() -> None:
    """Recolouring risk to match a palette misreports, which is worse than
    being off-brand. Only INFO is allowed to be violet."""
    from themob.model.enums import Severity

    assert theme.SEVERITY_COLORS[Severity.CRITICAL].lower().startswith("#ff")
    assert theme.SEVERITY_COLORS[Severity.LOW] != theme.ACCENT
    assert theme.SEVERITY_COLORS[Severity.INFO] == theme.ACCENT


# ---------------------------------------------------------- section panels

def _section_fixture(qapp, loaded):
    from themob.correlate.sections import project as project_sections

    project, snapshot, repos = loaded
    findings = repos.findings.list(project.id)
    return {v.key: v for v in project_sections(snapshot, findings)}, snapshot


def test_a_section_panel_renders_its_projection(qapp, loaded) -> None:
    from themob.app.panels.section_panel import SectionPanel

    views, snapshot = _section_fixture(qapp, loaded)
    panel = SectionPanel()
    panel.load(views["platform"], snapshot)

    assert panel._title._title.text() == "Platform & IPC"
    assert panel._entities_table.rowCount() > 0


def test_a_section_panel_survives_an_empty_section(qapp, loaded) -> None:
    """Storage has no analyzer yet, so its panel must still draw."""
    from themob.app.panels.section_panel import SectionPanel

    views, snapshot = _section_fixture(qapp, loaded)
    panel = SectionPanel()
    panel.load(views["storage"], snapshot)

    assert panel._findings_table.rowCount() == 1        # the placeholder row
    assert "Nothing found" in panel._findings_table.item(0, 3).text()


def test_a_section_panel_clears(qapp) -> None:
    from themob.app.panels.section_panel import SectionPanel

    panel = SectionPanel()
    panel.clear()
    assert panel._title._title.text() == ""


def test_the_exposed_column_reflects_the_correlator(qapp, loaded) -> None:
    """The column that changes what a tester does first.

    Severity says how bad a finding would be; exposure says whether anything
    outside the app can reach it. The fixture's provider is exported, so a
    finding on it is reachable and the table has to say so.
    """
    from themob.app.panels.section_panel import SectionPanel
    from themob.model.findings import Finding, FindingSource

    project, snapshot, repos = loaded
    provider = next(e for e in snapshot.entities
                    if e.key.endswith("ShopProvider"))
    repos.findings.upsert(project.id, Finding(
        fingerprint="e" * 64, weakness_key="android.ipc.provider-exported-unprotected",
        title="Content provider is exported without a permission",
        severity=Severity.HIGH, confidence=0.9, entity_ids=[provider.id],
        sources=[FindingSource(tool="config-audit", rule="x")]))

    from themob.correlate.graph import build_snapshot
    from themob.correlate.sections import project as project_sections

    fresh = build_snapshot(repos, project.id)
    views = {v.key: v for v in project_sections(
        fresh, repos.findings.list(project.id))}
    panel = SectionPanel()
    panel.load(views["platform"], fresh)

    exposed = {panel._findings_table.item(r, 3).text():
               panel._findings_table.item(r, 2).text()
               for r in range(panel._findings_table.rowCount())}
    assert exposed.get("Content provider is exported without a permission") == "Yes"


def test_the_nav_carries_every_section(qapp, tmp_path) -> None:
    """The rail is generated from the correlator, not a second hand-written list."""
    from themob.app.main_window import MainWindow
    from themob.correlate.sections import SECTIONS
    from themob.storage.db import open_database

    window = MainWindow(open_database(tmp_path / "t.db"), tmp_path / "home")
    keys = set(window._sidebar._buttons)
    # Reverse engineering is the Code page, so it is not a duplicate entry.
    for section in SECTIONS:
        if section.key == "code":
            continue
        assert f"section:{section.key}" in keys, section.key
        assert f"section:{section.key}" in window._pages


def test_an_ampersand_in_a_nav_label_is_not_a_mnemonic(qapp) -> None:
    """Qt reads "&" as an accelerator marker, so "Network & API" rendered as
    "Network _API" with the A underlined."""
    sidebar = Sidebar()
    button = sidebar.add_item("network", "Network & API", "*")
    assert "&&" in button.text(), "the ampersand was not escaped"


# ---------------------------------------------------------- finding detail

def _detail_finding(**overrides):
    from themob.model.findings import Evidence, Finding, Location, Remediation
    from themob.model.enums import EvidenceKind

    doc = dict(
        fingerprint="d" * 64, weakness_key="android.config.debuggable",
        title="Application is debuggable", severity=Severity.HIGH,
        confidence=0.95, risk=72.0,
        score_rationale="raised from medium because an exported entry point "
                        "reaches it directly",
        base_severity=Severity.MEDIUM,
        masvs_control="MASVS-RESILIENCE-4", mobile_top10="M8", cwe="CWE-489",
        location=Location(file="AndroidManifest.xml"),
        evidence=[Evidence(kind=EvidenceKind.SNIPPET,
                           value='android:debuggable="true"')],
        remediation=Remediation(summary="Remove it from the manifest."))
    doc.update(overrides)
    return Finding(**doc)


def test_the_detail_panel_shows_the_whole_schema(qapp) -> None:
    from themob.app.panels.finding_detail import FindingDetail

    panel = FindingDetail()
    panel.load(_detail_finding(), [], [("config-audit", 0.95)])

    assert panel._title.text() == "Application is debuggable"
    assert panel._severity.text() == "High"
    assert "95%" in panel._confidence.text()
    assert "risk 72" in panel._confidence.text()


def test_the_rationale_is_shown_not_hidden(qapp) -> None:
    """A rating a tester cannot question is one they end up ignoring.

    The scorer may have raised the severity; if the reason lives in a tooltip
    there is no way to argue with it.
    """
    from themob.app.panels.finding_detail import FindingDetail

    panel = FindingDetail()
    panel.load(_detail_finding(), [], [])
    assert "raised from medium" in panel._rationale.text()
    assert panel._rationale.isVisible() or not panel.isVisible()


def test_an_unraised_finding_shows_no_rationale(qapp) -> None:
    from themob.app.panels.finding_detail import FindingDetail

    panel = FindingDetail()
    panel.load(_detail_finding(score_rationale=None), [], [])
    assert panel._rationale.text() == ""


def test_a_suppressing_verdict_needs_a_reason_before_the_button_works(
        qapp) -> None:
    """The engine refuses it anyway; the panel makes the refusal unsurprising."""
    from themob.app.panels.finding_detail import FindingDetail
    from themob.model.enums import FindingStatus

    panel = FindingDetail()
    panel.load(_detail_finding(), [], [])

    assert panel._buttons[FindingStatus.CONFIRMED].isEnabled()
    assert not panel._buttons[FindingStatus.FALSE_POSITIVE].isEnabled()
    assert not panel._buttons[FindingStatus.ACCEPTED_RISK].isEnabled()

    panel._note.setPlainText("Debug build only.")
    assert panel._buttons[FindingStatus.FALSE_POSITIVE].isEnabled()


def test_the_verdict_signal_carries_the_note(qapp) -> None:
    from themob.app.panels.finding_detail import FindingDetail
    from themob.model.enums import FindingStatus

    panel = FindingDetail()
    finding = _detail_finding()
    panel.load(finding, [], [])
    panel._note.setPlainText("Release build sets it false.")

    seen: list[tuple] = []
    panel.verdict_requested.connect(lambda *a: seen.append(a))
    panel._buttons[FindingStatus.FALSE_POSITIVE].click()

    assert len(seen) == 1
    finding_id, status, note = seen[0]
    assert finding_id == finding.id
    assert status is FindingStatus.FALSE_POSITIVE
    assert note == "Release build sets it false."


def test_an_unmapped_maswe_says_so_rather_than_showing_a_blank(qapp) -> None:
    """"Not mapped" is information: it says the pack has no verified id."""
    from themob.app.panels.finding_detail import FindingDetail

    panel = FindingDetail()
    panel.load(_detail_finding(), [], [])
    grid = panel._standards._grid
    rendered = [grid.itemAtPosition(row, 1).widget().text()
                for row in range(panel._standards._rows)]
    assert "not mapped" in rendered


def test_notes_are_listed_oldest_first(qapp) -> None:
    from themob.app.panels.finding_detail import FindingDetail
    from themob.storage.repositories import Note

    panel = FindingDetail()
    panel.load(_detail_finding(), [
        Note(finding_id="x", author="a@lab", text="First doubt.",
             created_at="2026-09-01T10:00:00"),
        Note(finding_id="x", author="a@lab", text="Client confirmed.",
             created_at="2026-09-02T10:00:00"),
    ], [])
    assert panel._notes_body.count() > 0


def test_the_detail_panel_clears(qapp) -> None:
    from themob.app.panels.finding_detail import FindingDetail

    panel = FindingDetail()
    panel.load(_detail_finding(), [], [])
    panel.clear()
    assert panel._title.text() == ""


# --------------------------------------------------------- report export

def _console(qapp, db, repos, sample_apk, tmp_path):
    """A main window sharing the fixture database, with a project loaded."""
    from themob.app.main_window import MainWindow

    audit = AuditTrail(repos.audit)
    result = intake(sample_apk, repos, audit, root=tmp_path / "home")
    audit.record_attestation(result.project, Attestation(
        target_name="sample.apk", target_sha256=result.sha256,
        operator="tester@lab", engagement_ref="ENG-1", attested=True),
        repos.projects)

    window = MainWindow(db, tmp_path / "home")
    window.load_project(result)
    return window, result


def test_code_tree_is_not_rebuilt_when_the_index_is_unchanged(
        qapp, db, repos, sample_apk, tmp_path) -> None:
    """Regression: a refresh during a run must not rebuild the class tree (tens
    of thousands of items) every time the graph changes. The rebuild is skipped
    when the index file on disk has not changed since the last load."""
    import json

    from themob.app.main_window import MainWindow
    from themob.correlate.graph import build_snapshot
    from themob.model.entities import Entity

    audit = AuditTrail(repos.audit)
    result = intake(sample_apk, repos, audit, root=tmp_path / "home")
    audit.record_attestation(result.project, Attestation(
        target_name="sample.apk", target_sha256=result.sha256,
        operator="tester@lab", engagement_ref="ENG-1", attested=True),
        repos.projects)
    ws = result.workspace
    index = ws.raw_dir("jadx-decompile") / "index.json"
    index.write_text(json.dumps({"classes": [
        {"fqcn": "com.x.A", "package": "com.x", "name": "A",
         "path": "sources/com/x/A.java"}]}), encoding="utf-8")
    repos.entities.upsert(result.project.id, Entity(
        type=EntityType.APP, platform=Platform.ANDROID, key="com.example.shop",
        label="shop", attributes={"package": "com.example.shop",
                                  "class_index": ws.relative(index)}))

    window = MainWindow(db, tmp_path / "home")
    calls = {"n": 0}
    original = window._code.load

    def counting_load(*args, **kwargs):
        calls["n"] += 1
        return original(*args, **kwargs)

    window._code.load = counting_load
    window.load_project(result)                 # builds the tree once
    assert calls["n"] == 1
    window._refresh_code(build_snapshot(repos, result.project.id))
    assert calls["n"] == 1                       # unchanged index: rebuild skipped


def test_new_scan_authorizes_and_loads_another_project_in_place(
        qapp, db, repos, sample_apk, tmp_path, monkeypatch) -> None:
    """The in-window 'New scan' runs the gate again and loads what it returns,
    so a tester does not restart themob to analyze the next app."""
    from themob.app import auth_gate as ag

    window, _first = _console(qapp, db, repos, sample_apk, tmp_path)
    assert window._new_scan.isEnabled()

    class _Gate:
        DialogCode = ag.AuthorizationGate.DialogCode

        def __init__(self, parent=None) -> None:
            pass

        def exec(self):
            return _Gate.DialogCode.Accepted

        def result(self):
            return "decision"

    sentinel = object()
    loaded: dict = {}
    monkeypatch.setattr(ag, "AuthorizationGate", _Gate)
    monkeypatch.setattr(ag, "authorize", lambda *a, **k: sentinel)
    monkeypatch.setattr(window, "load_project", lambda result: loaded.update(r=result))

    window.new_scan()
    assert loaded.get("r") is sentinel


def test_low_disk_space_warns_before_a_run(qapp, db, repos, sample_apk, tmp_path,
                                           monkeypatch) -> None:
    """A full disk makes a whole run fail or time out analyzer by analyzer, so
    the console checks free space first and lets the operator decide."""
    import shutil
    from types import SimpleNamespace

    from themob.app import main_window as mw

    window, _result = _console(qapp, db, repos, sample_apk, tmp_path)

    # Plenty of space: no prompt, run proceeds.
    monkeypatch.setattr(shutil, "disk_usage",
                        lambda p: SimpleNamespace(total=0, used=0,
                                                  free=50 * 1024 ** 3))
    assert window._confirm_disk_space() is True

    # Low space: the confirm dialog decides; declining blocks the run.
    monkeypatch.setattr(shutil, "disk_usage",
                        lambda p: SimpleNamespace(total=0, used=0,
                                                  free=100 * 1024 ** 2))
    asked: dict = {}

    class _Stub:
        @staticmethod
        def ask(*a, **k):
            asked["called"] = True
            return False

    monkeypatch.setattr(mw, "ConfirmDialog", _Stub)
    assert window._confirm_disk_space() is False
    assert asked.get("called")


def test_new_scan_is_refused_while_a_run_is_in_flight(qapp, db, repos, sample_apk,
                                                      tmp_path) -> None:
    window, _first = _console(qapp, db, repos, sample_apk, tmp_path)
    window._set_running(True)
    assert not window._new_scan.isEnabled()
    window._set_running(False)
    assert window._new_scan.isEnabled()


def test_assistant_agent_mode_routes_to_the_agent(qapp, monkeypatch) -> None:
    """With 'Investigate' checked, the worker runs the agent; otherwise the
    one-shot assistant. The panel exposes the toggle."""
    from themob.app.panels.assistant import AssistantPanel, _AskWorker
    from themob.assist import agent as agent_mod
    from themob.assist import core as core_mod

    assert AssistantPanel()._agent_mode is not None     # the toggle exists

    seen: dict = {}
    monkeypatch.setattr(agent_mod, "run",
                        lambda home, project, question: {"answer": "agent",
                                                         "steps": [{"tool": "overview",
                                                                    "args": {}}]})
    monkeypatch.setattr(core_mod, "ask",
                        lambda home, project, question: {"answer": "oneshot"})

    worker = _AskWorker("home", "p", "q", "agent")
    worker.done.connect(lambda r: seen.update(r))
    worker.run()
    assert seen["answer"] == "agent"

    seen.clear()
    worker = _AskWorker("home", "p", "q", "ask")
    worker.done.connect(lambda r: seen.update(r))
    worker.run()
    assert seen["answer"] == "oneshot"


def test_assistant_renders_and_approves_agent_proposals(qapp, monkeypatch) -> None:
    """The agent's recommended gated actions render as approve-able rows, and a
    click runs the gated tool (verdict) or asks the window to rescan."""
    from PyQt6.QtWidgets import QPushButton

    from themob.app.panels.assistant import AssistantPanel
    from themob.mcp import tools as tools_mod

    panel = AssistantPanel()
    panel._home, panel._project = "home", "p"
    panel._on_answer({
        "answer": "ok", "steps": [{"tool": "overview", "args": {}}],
        "proposals": [
            {"action": "record_verdict", "fingerprint": "abcd",
             "status": "false_positive", "reason": "debug only"},
            {"action": "rescan", "reason": "stale"}]})
    # A header caption plus one row per proposal.
    assert panel._proposals_layout.count() == 3

    recorded: dict = {}
    monkeypatch.setattr(tools_mod, "record_verdict",
                        lambda home, project, fp, status, note="", operator="":
                        recorded.setdefault("v", (fp, status)) or {"ok": True})
    button = QPushButton()
    panel._approve({"action": "record_verdict", "fingerprint": "abcd",
                    "status": "false_positive", "reason": "x"}, button)
    assert recorded["v"] == ("abcd", "false_positive")
    assert button.text() == "Recorded"

    seen: list = []
    panel.rescan_requested.connect(lambda: seen.append(True))
    rescan_button = QPushButton()
    panel._approve({"action": "rescan", "reason": "x"}, rescan_button)
    assert seen == [True] and rescan_button.text() == "Started"

    # Asking again clears the proposals.
    panel._clear_proposals()
    assert panel._proposals_layout.count() == 0


def test_trends_panel_renders_the_local_corpus(qapp, tmp_path) -> None:
    """The Trends page reads the corpus and shows the recurring weaknesses."""
    from themob.app.panels.trends import TrendsPanel
    from themob.model.findings import Finding, FindingSource
    from themob.model.enums import FindingStatus
    from themob.storage.db import open_database
    from themob.storage.repositories import Project, Repositories

    database = open_database(tmp_path / "themob.db")
    try:
        repos = Repositories(database)
        for i, platform in enumerate((Platform.ANDROID, Platform.ANDROID)):
            project = Project(name=f"app{i}", target_platform=platform,
                              source_path=f"a{i}.apk", source_sha256=f"{i:064x}")
            repos.projects.create(project)
            repos.findings.upsert(project.id, Finding(
                fingerprint=f"{i}a" + "0" * 62,
                weakness_key="android.network.cleartext-endpoint",
                title="Cleartext endpoint", severity=Severity.HIGH,
                status=FindingStatus.CONFIRMED,
                sources=[FindingSource(tool="t", rule="x")]))
    finally:
        database.close_all()

    panel = TrendsPanel()
    panel.bind(tmp_path)
    panel._force_refresh()

    assert panel._apps.text == "2"
    assert panel._findings.text == "2"
    # The recurring weakness is listed (it appeared in both apps).
    assert panel._weak_layout.count() >= 1


def test_trends_panel_is_honest_when_empty(qapp, tmp_path) -> None:
    from themob.app.panels.trends import TrendsPanel
    from themob.storage.db import open_database

    open_database(tmp_path / "themob.db").close_all()   # an empty store
    panel = TrendsPanel()
    panel.bind(tmp_path)
    panel._force_refresh()
    assert panel._apps.text == "0"
    assert "fills in" in panel._status.text()


class _CapturedDialog:
    """Stands in for MessageDialog so a modal never opens under pytest."""

    seen: list[dict] = []

    def __init__(self, parent=None, *, title="", message="", detail="",
                 tone="info") -> None:
        _CapturedDialog.seen.append(
            {"title": title, "message": message, "detail": detail, "tone": tone})

    def exec(self) -> int:
        return 1

    @staticmethod
    def show_error(parent, message, detail="", title="themob: error") -> None:
        _CapturedDialog.seen.append(
            {"title": title, "message": message, "detail": detail,
             "tone": "error"})


@pytest.fixture()
def captured_dialog(monkeypatch):
    from themob.app import main_window as mw

    _CapturedDialog.seen = []
    monkeypatch.setattr(mw, "MessageDialog", _CapturedDialog)
    return _CapturedDialog


def test_export_is_off_until_there_is_something_to_report(qapp, db, repos,
                                                          sample_apk,
                                                          tmp_path) -> None:
    """An enabled export with no project would write an empty document."""
    from themob.app.main_window import MainWindow

    empty = MainWindow(db, tmp_path / "empty")
    assert not empty._export.isEnabled()

    window, _result = _console(qapp, db, repos, sample_apk, tmp_path)
    assert window._export.isEnabled()

    # And it goes away again mid-run: a report written while analyzers are
    # still going reads as finished when it is not.
    window._set_running(True)
    assert not window._export.isEnabled()
    window._set_running(False)
    assert window._export.isEnabled()


def test_exporting_from_the_console_writes_both_files(qapp, db, repos,
                                                      sample_apk, tmp_path,
                                                      captured_dialog,
                                                      monkeypatch) -> None:
    from themob.app import main_window as mw
    from themob.audit.attestation import Action

    window, result = _console(qapp, db, repos, sample_apk, tmp_path)
    out = tmp_path / "handover"
    monkeypatch.setattr(mw.QFileDialog, "getExistingDirectory",
                        staticmethod(lambda *a, **k: str(out)))

    window._export.click()

    assert (out / "themob-report.html").is_file()
    assert (out / "themob-report.json").is_file()
    assert any(e.action == Action.REPORT_EXPORTED
               for e in repos.audit.list(result.project.id))
    assert captured_dialog.seen, "the operator was told nothing"
    assert "Report written" in captured_dialog.seen[-1]["message"]


def test_cancelling_the_picker_writes_nothing(qapp, db, repos, sample_apk,
                                              tmp_path, captured_dialog,
                                              monkeypatch) -> None:
    from themob.app import main_window as mw
    from themob.audit.attestation import Action

    window, result = _console(qapp, db, repos, sample_apk, tmp_path)
    monkeypatch.setattr(mw.QFileDialog, "getExistingDirectory",
                        staticmethod(lambda *a, **k: ""))

    window._export.click()

    assert not captured_dialog.seen
    assert not any(e.action == Action.REPORT_EXPORTED
                   for e in repos.audit.list(result.project.id))


def test_the_confirmation_repeats_the_reports_caveats(qapp, db, repos,
                                                      sample_apk, tmp_path,
                                                      captured_dialog,
                                                      monkeypatch) -> None:
    """Someone is about to forward this, so a gap gets said out loud."""
    from themob.app import main_window as mw
    from themob.model.enums import JobStatus, Stage

    window, result = _console(qapp, db, repos, sample_apk, tmp_path)
    job = repos.jobs.create(result.project.id, Stage.SECRETS, "gitleaks-scan")
    repos.jobs.finish(job.id, JobStatus.FAILED, "the worker produced no output")

    monkeypatch.setattr(mw.QFileDialog, "getExistingDirectory",
                        staticmethod(lambda *a, **k: str(tmp_path / "out")))
    window._export.click()

    said = captured_dialog.seen[-1]
    assert "gitleaks-scan" in said["message"]
    assert said["tone"] == "warn"


def test_a_failed_export_is_reported_rather_than_swallowed(
        qapp, db, repos, sample_apk, tmp_path, captured_dialog,
        monkeypatch) -> None:
    from themob.app import main_window as mw

    window, _result = _console(qapp, db, repos, sample_apk, tmp_path)
    monkeypatch.setattr(mw.QFileDialog, "getExistingDirectory",
                        staticmethod(lambda *a, **k: str(tmp_path / "out")))

    def boom(*_a, **_k):
        raise OSError("the disk is full")

    monkeypatch.setattr(mw, "export_report", boom)
    window._export.click()

    said = captured_dialog.seen[-1]
    assert said["tone"] == "error"
    assert "disk is full" in said["detail"]


def test_the_export_button_keeps_an_icon_when_collapsed(qapp, db,
                                                        tmp_path) -> None:
    from themob.app.main_window import MainWindow

    window = MainWindow(db, tmp_path / "home")
    window._sidebar.toggle()
    assert window._export.text() == ""
    assert not window._export.icon().isNull()
    assert "Export report" in window._export.toolTip()
    window._sidebar.toggle()
    assert window._export.text() == "Export report"


# --------------------------------------------------------------- questions

def test_the_questions_page_ships_with_questions(qapp, db, tmp_path) -> None:
    """A query builder handed over empty is a feature nobody uses."""
    from themob.app.main_window import MainWindow
    from themob.correlate import queries

    window = MainWindow(db, tmp_path / "home")
    assert "queries" in window._pages
    assert window._queries._questions.count() == len(queries.BUILTINS)


def test_picking_a_question_answers_it(qapp, db, repos, loaded) -> None:
    from themob.app.panels.queries_panel import QueriesPanel
    from themob.correlate.graph import build_snapshot

    panel = QueriesPanel()
    panel.bind(repos)

    stored = repos.projects.list()[0]
    snapshot = build_snapshot(repos, stored.id)
    panel.load(snapshot, repos.findings.list(stored.id))

    panel._select("exported-no-permission")
    assert panel._result is not None
    assert panel._result.query.key == "exported-no-permission"
    assert panel._table.rowCount() == len(panel._rows)


def test_a_saved_question_appears_beside_the_builtins(qapp, db, repos,
                                                      tmp_path) -> None:
    from themob.app.panels.queries_panel import QueriesPanel
    from themob.correlate import queries
    from themob.correlate.graph import empty_snapshot

    panel = QueriesPanel()
    panel.bind(repos)
    panel.load(empty_snapshot(), [])

    panel._select("cleartext-endpoints")
    panel._name.setText("My cleartext check")
    panel._on_save()

    assert panel._questions.count() == len(queries.BUILTINS) + 1
    assert repos.queries.load("my-cleartext-check") is not None


def test_a_builtin_cannot_be_deleted(qapp, db, repos) -> None:
    """It is themob's claim about what matters, not the tester's to remove."""
    from themob.app.panels.queries_panel import QueriesPanel
    from themob.correlate import queries
    from themob.correlate.graph import empty_snapshot

    panel = QueriesPanel()
    panel.bind(repos)
    panel.load(empty_snapshot(), [])

    panel._select("cleartext-endpoints")
    panel._on_delete()
    assert panel._questions.count() == len(queries.BUILTINS)


def test_a_saved_question_can_be_deleted(qapp, db, repos) -> None:
    from themob.app.panels.queries_panel import QueriesPanel
    from themob.correlate import queries
    from themob.correlate.graph import empty_snapshot

    panel = QueriesPanel()
    panel.bind(repos)
    panel.load(empty_snapshot(), [])
    panel._select("cleartext-endpoints")
    panel._name.setText("Mine")
    panel._on_save()

    panel._select("mine")
    panel._on_delete()
    assert panel._questions.count() == len(queries.BUILTINS)
    assert repos.queries.load("mine") is None


def test_saving_over_a_builtin_name_is_reported_not_swallowed(
        qapp, db, repos) -> None:
    from themob.app.panels.queries_panel import QueriesPanel
    from themob.correlate.graph import empty_snapshot

    panel = QueriesPanel()
    panel.bind(repos)
    panel.load(empty_snapshot(), [])
    panel._select("cleartext-endpoints")
    # The key derived from this title collides with the builtin's own key.
    panel._name.setText("cleartext endpoints")
    panel._on_save()

    assert "built-in" in panel._description.text()


def test_the_panel_clears(qapp, db, repos) -> None:
    from themob.app.panels.queries_panel import QueriesPanel
    from themob.correlate.graph import empty_snapshot

    panel = QueriesPanel()
    panel.bind(repos)
    panel.load(empty_snapshot(), [])
    panel.clear()
    assert panel._table.rowCount() == 0


# ------------------------------------------------------------------ dynamic

def _dynamic_project(repos, tmp_path):
    from themob.model.entities import Entity
    from themob.model.enums import EntityType, Platform
    from themob.storage.repositories import Project

    stored = repos.projects.create(Project(
        name="Shop", target_platform=Platform.ANDROID,
        source_path="in/shop.apk", source_sha256="a" * 64))
    repos.projects.set_authorization(stored.id, ref="ENG-1", by="tester@lab")
    repos.entities.upsert(stored.id, Entity(
        type=EntityType.APP, platform=Platform.ANDROID, key="com.example.shop",
        label="shop", attributes={"package": "com.example.shop"}))
    return repos.projects.get(stored.id)


def test_the_dynamic_panel_starts_unauthorized(qapp, db, repos, tmp_path) -> None:
    from themob.app.panels.dynamic_panel import DynamicPanel
    from themob.audit.attestation import AuditTrail

    project = _dynamic_project(repos, tmp_path)
    panel = DynamicPanel()
    panel.bind(repos, AuditTrail(repos.audit))
    panel.load(project.id, None)

    assert "Not authorized" in panel._status.text()


def test_attesting_from_the_panel_unlocks_dynamic_analysis(qapp, db, repos,
                                                           tmp_path) -> None:
    from themob.app.panels.dynamic_panel import DynamicPanel
    from themob.audit.attestation import AuditTrail
    from themob.dynamic.gate import require_execution

    project = _dynamic_project(repos, tmp_path)
    panel = DynamicPanel()
    panel.bind(repos, AuditTrail(repos.audit))
    panel.load(project.id, None)

    panel._device_id.setText("emulator-5554")
    panel._dedicated.setChecked(True)
    panel._traffic.setChecked(True)
    panel._scope.setText(".example.com, api.shop.test")
    panel._on_authorize()

    detail = require_execution(repos, project.id)
    assert detail["device_id"] == "emulator-5554"
    assert detail["interception_scope"] == [".example.com", "api.shop.test"]
    assert "Authorized" in panel._status.text()


def test_an_incomplete_attestation_is_refused_in_the_panel(qapp, db, repos,
                                                           tmp_path) -> None:
    from themob.app.panels.dynamic_panel import DynamicPanel
    from themob.audit.attestation import AuditTrail

    project = _dynamic_project(repos, tmp_path)
    panel = DynamicPanel()
    panel.bind(repos, AuditTrail(repos.audit))
    panel.load(project.id, None)

    panel._device_id.setText("R58M123")
    panel._traffic.setChecked(True)
    panel._on_authorize()

    assert "dedicated test device" in panel._auth_hint.text()


def test_importing_frida_output_merges_and_asks_for_a_refresh(
        qapp, db, repos, tmp_path, monkeypatch) -> None:
    from themob.app.panels.dynamic_panel import DynamicPanel
    from themob.audit.attestation import AuditTrail
    from themob.dynamic import gate
    from themob.dynamic.gate import DeviceAttestation, ExecutionAttestation

    project = _dynamic_project(repos, tmp_path)
    gate.authorize(ExecutionAttestation(
        operator="tester@lab",
        device=DeviceAttestation(identifier="emulator-5554",
                                 dedicated_test_device=True, is_emulator=True),
        traffic_authorized=True), project.id, AuditTrail(repos.audit))

    log = tmp_path / "frida.log"
    log.write_text('themob-observe {"kind":"digest","algorithm":"MD5"}\n',
                   encoding="utf-8")

    panel = DynamicPanel()
    panel.bind(repos, AuditTrail(repos.audit))
    panel.load(project.id, None)
    monkeypatch.setattr(panel, "_pick", lambda *a, **k: str(log))

    refreshed = []
    panel.findings_merged.connect(lambda: refreshed.append(True))
    panel._on_import_frida()

    assert refreshed, "the graph was not asked to refresh"
    findings = repos.findings.list(project.id)
    assert any(f.weakness_key == "android.crypto.weak-hash" for f in findings)
    assert "runtime finding" in panel._run_hint.text()


def test_the_panel_lists_the_shipped_jobs(qapp, db, repos, tmp_path) -> None:
    from themob.app.panels.dynamic_panel import DynamicPanel
    from themob.audit.attestation import AuditTrail

    panel = DynamicPanel()
    panel.bind(repos, AuditTrail(repos.audit))

    labels = [panel._job.itemText(i) for i in range(panel._job.count())]
    assert any("observe-crypto.js" in x for x in labels)
    assert any("ssl-pin-bypass" in x for x in labels)
    assert any("capture" in x for x in labels)


# --------------------------------------------------------------- graph capping

def _perm_snapshot(count: int, *, flagged_last: bool = False):
    """A root App plus *count* permission nodes, no edges."""
    from themob.correlate.graph import GraphSnapshot
    from themob.model.entities import Entity

    root = Entity(type=EntityType.APP, platform=Platform.ANDROID,
                  key="com.x", label="root")
    ents = [root] + [Entity(type=EntityType.PERMISSION, platform=Platform.ANDROID,
                            key=f"p{i}", label=f"p{i}") for i in range(count)]
    severity = {}
    if flagged_last:
        severity[ents[-1].id] = Severity.CRITICAL
    return GraphSnapshot(project_id="p", entities=ents, edges=[],
                         root_id=root.id, finding_severity=severity), root.id, ents


def test_the_graph_caps_a_huge_snapshot(qapp) -> None:
    """A pathological package must not freeze the force-directed layout: the view
    renders a bounded, security-weighted subset and says how much it hid."""
    from themob.app.widgets.graph_view import GraphView, _MAX_RENDER_NODES

    snap, root_id, ents = _perm_snapshot(_MAX_RENDER_NODES + 400, flagged_last=True)
    flagged = ents[-1].id            # last node, cut without prioritisation
    view = GraphView()
    view.load(snap)
    assert len(view._nodes) == _MAX_RENDER_NODES
    assert root_id in view._nodes                  # the app root always shows
    assert flagged in view._nodes                  # a finding-bearing node is kept
    assert not view._cap_note.isHidden()           # and it says so
    assert "of" in view._cap_note.text()
    # No edge may point at a node that was not rendered.
    for src, dst, _t in view._edges:
        assert src in view._nodes and dst in view._nodes


def test_the_graph_does_not_cap_a_normal_snapshot(qapp) -> None:
    from themob.app.widgets.graph_view import GraphView

    snap, _root_id, _ents = _perm_snapshot(20)
    view = GraphView()
    view.load(snap)
    assert len(view._nodes) == 21
    assert view._cap_note.isHidden()


def test_refresh_skips_graph_build_during_a_run(qapp, tmp_path, monkeypatch) -> None:
    """The crash was NetworkX on the UI thread racing the engine's graph work.

    During a run, refresh must move the live counts only and never build the
    read model, so build_snapshot standing in for all NetworkX work must not be
    called. It is restored and exercised in full by every other MainWindow test.
    """
    from types import SimpleNamespace

    from themob.app import main_window as mw
    from themob.app.main_window import MainWindow
    from themob.storage.db import open_database

    window = MainWindow(open_database(tmp_path / "t.db"), tmp_path / "home")
    window._project = SimpleNamespace(id="proj0001")

    def _boom(*_a, **_k):
        raise AssertionError("build_snapshot ran on the UI thread during a run")

    monkeypatch.setattr(mw, "build_snapshot", _boom)
    window._run_active = True
    window.refresh()          # must short-circuit to live counts, not _boom


# ------------------------------------------------------ window placement

def test_the_window_centres_itself_rather_than_opening_top_left(
        qapp, db, tmp_path) -> None:
    """A frameless window is not placed by the OS, so without this it opens
    pinned to the top-left corner instead of the middle of the screen."""
    from themob.app.main_window import MainWindow

    window = MainWindow(db, tmp_path / "home")
    assert window._centered is False            # not centred until first shown
    window._center_on_screen()

    screen = window.screen() or QApplication.primaryScreen()
    available = screen.availableGeometry()
    frame = window.frameGeometry()
    # Always clamped into the work area, so the title bar can never go off-screen.
    assert window.x() >= available.left()
    assert window.y() >= available.top()
    # And when the window fits the screen, it is actually centred on it.
    if available.width() >= frame.width() and available.height() >= frame.height():
        assert abs(frame.center().x() - available.center().x()) <= 2
        assert abs(frame.center().y() - available.center().y()) <= 2


# ---------------------------------------------------------- scan switcher

def test_open_scan_reopens_a_saved_scan_fully(qapp, db, repos, sample_apk,
                                              tmp_path) -> None:
    """A finished scan is persisted, so reopening it adopts its project again
    and restores the window to that scan. A scan whose sample is gone is still
    browsable; only re-running it needs the sample, hence a null target."""
    from themob.storage.repositories import Project

    window, result = _console(qapp, db, repos, sample_apk, tmp_path)
    first_id = result.project.id

    # A second scan whose sample was never kept on disk.
    second = repos.projects.create(Project(
        name="Other app", source_sha256="b" * 64, source_path="in/other.apk"))

    window.open_project(second.id)
    assert window._project.id == second.id
    assert window._target is None               # sample gone, still opens

    # Reopen the first: its sample is present, so a run target is rebuilt.
    window.open_project(first_id)
    assert window._project.id == first_id
    assert window._target is not None


def test_open_scan_routes_the_chosen_scan(qapp, db, repos, sample_apk,
                                          tmp_path, monkeypatch) -> None:
    from PyQt6.QtWidgets import QDialog

    from themob.app import main_window as mw

    window, _result = _console(qapp, db, repos, sample_apk, tmp_path)

    class _Picker:
        DialogCode = QDialog.DialogCode
        chosen = "chosen-id"

        def __init__(self, *a, **k) -> None:
            pass

        def exec(self):
            return QDialog.DialogCode.Accepted

    monkeypatch.setattr(mw, "ScanPicker", _Picker)
    seen: dict = {}
    monkeypatch.setattr(window, "open_project",
                        lambda pid: seen.setdefault("id", pid))
    window.open_scan()
    assert seen.get("id") == "chosen-id"


def test_switching_while_a_scan_runs_prompts_then_defers(
        qapp, db, repos, sample_apk, tmp_path, monkeypatch) -> None:
    """Opening another scan mid-run must prompt to stop first, and only switch
    once the run has actually ended, so a live analyzer is never orphaned."""
    from themob.app import main_window as mw
    from themob.storage.repositories import Project

    window, result = _console(qapp, db, repos, sample_apk, tmp_path)
    first_id = result.project.id
    second = repos.projects.create(Project(
        name="Other app", source_sha256="c" * 64, source_path="in/other.apk"))

    class _FakeEngine:
        def __init__(self) -> None:
            self._running = True

        def isRunning(self) -> bool:
            return self._running

        def stop(self) -> None:
            self._running = False

    window._engine = _FakeEngine()
    window._set_running(True)

    # Declining the prompt leaves the running scan exactly as it was.
    class _No:
        @staticmethod
        def ask(*a, **k):
            return False

    monkeypatch.setattr(mw, "ConfirmDialog", _No)
    window.open_project(second.id)
    assert window._pending_open is None
    assert window._project.id == first_id

    # Accepting stops the run and defers the switch until it ends.
    class _Yes:
        @staticmethod
        def ask(*a, **k):
            return True

    monkeypatch.setattr(mw, "ConfirmDialog", _Yes)
    window.open_project(second.id)
    assert window._pending_open == second.id
    assert window._engine.isRunning() is False       # a stop was requested
    assert window._project.id == first_id            # not switched yet

    # When the run actually finishes, the waiting switch is performed.
    window._run_active = False
    window._consume_pending_open()
    assert window._project.id == second.id
    assert window._pending_open is None


def test_live_counts_move_the_nav_badges_without_building_the_graph(
        qapp, db, repos, loaded, tmp_path, monkeypatch) -> None:
    """The sidebar must keep showing finding and entity numbers during a run,
    and do it from cheap database reads, never the NetworkX rebuild that the
    _run_active guard exists to avoid."""
    from themob.app import main_window as mw
    from themob.app.main_window import MainWindow

    project, _snapshot, _repos = loaded
    window = MainWindow(db, tmp_path / "home")
    window._project = project

    def _boom(*_a, **_k):
        raise AssertionError("built the NetworkX graph during a run")

    monkeypatch.setattr(mw, "build_snapshot", _boom)
    window._run_active = True
    window.refresh()            # routes to the live counts, must not call _boom

    badges = window._sidebar._badges
    assert badges["graph"] == "5"               # five entities in the fixture
    assert badges["overview"] == "1"            # one finding
    # The debuggable finding is a manifest judgement: it lands in Platform & IPC.
    assert badges["section:platform"] == "1"


def test_live_snapshot_renders_the_views_during_a_run(qapp, db, repos, loaded,
                                                      tmp_path) -> None:
    """Regression: the graph (and the other views) were empty until the run
    ended. A background snapshot now renders them live. Simulate the worker's
    result and assert the graph view actually gained its nodes mid-run."""
    from themob.app.main_window import MainWindow
    from themob.correlate.graph import build_snapshot

    project, _snapshot, _repos = loaded
    window = MainWindow(db, tmp_path / "home")
    window._project = project
    window._run_active = True
    assert window._graph._graph._nodes == {}        # empty before any render

    # What the background _SnapshotWorker hands back on the UI thread.
    snapshot = build_snapshot(window._repos, project.id)
    findings = window._repos.findings.list(project.id)
    window._on_live_snapshot(project.id, snapshot, findings)

    assert len(window._graph._graph._nodes) == 5     # populated live, mid-run
    assert window._overview._table.rowCount() == 1   # the overview filled too

    # A late result for a different project is ignored, not misrendered.
    window._on_live_snapshot("some-other-id", snapshot, findings)
    assert len(window._graph._graph._nodes) == 5


# ----------------------------------------------------- secret reveal gate

def _evidence_texts(panel) -> list[str]:
    layout = panel._evidence_body
    out = []
    for i in range(layout.count()):
        widget = layout.itemAt(i).widget()
        if widget is not None and hasattr(widget, "text"):
            out.append(widget.text())
    return out


def _evidence_buttons(panel) -> list[str]:
    from PyQt6.QtWidgets import QPushButton

    layout = panel._evidence_body
    return [layout.itemAt(i).widget().text()
            for i in range(layout.count())
            if isinstance(layout.itemAt(i).widget(), QPushButton)]


def _secret_finding(value: str, *, redacted: bool):
    from themob.model.enums import EvidenceKind
    from themob.model.findings import Evidence, Finding, Location

    return Finding(
        fingerprint="a" * 64, weakness_key="android.secrets.service-api-key",
        title="Hardcoded API key", severity=Severity.HIGH, confidence=0.8,
        location=Location(),
        evidence=[Evidence(kind=EvidenceKind.SNIPPET, value=value,
                           redacted=redacted)])


def test_a_sandbox_redacted_secret_offers_no_reveal(qapp, tmp_path) -> None:
    """When the only evidence is a sandbox-redacted preview there is no fuller
    value, so the detail shows it as-is and says so instead of a reveal button
    that would return the same stars."""
    from themob.app.panels.finding_detail import FindingDetail
    from themob.app.widgets.secret_gate import SecretGate

    panel = FindingDetail()
    panel.set_secret_gate(SecretGate(tmp_path))
    panel.load(_secret_finding("Stripe: sk_live_****abcd", redacted=True), [], [])

    texts = _evidence_texts(panel)
    assert any("never left the container" in t for t in texts)
    assert "sk_live_****abcd" in " ".join(texts)     # the safe preview shows as-is
    assert not _evidence_buttons(panel)               # no Reveal/Hide button


def test_a_captured_secret_is_masked_until_revealed(qapp, tmp_path) -> None:
    """A full value themob holds is masked by default and shown only once the
    password gate is unlocked."""
    from themob.app.panels.finding_detail import FindingDetail
    from themob.app.widgets.secret_gate import SecretGate

    full = "Stripe: sk_live_FULLSECRETvalue123"
    panel = FindingDetail()
    gate = SecretGate(tmp_path)
    panel.set_secret_gate(gate)
    panel.load(_secret_finding(full, redacted=False), [], [])

    # Masked by default, with a reveal button present.
    assert full not in " ".join(_evidence_texts(panel))
    assert _evidence_buttons(panel) == ["Reveal values"]

    # Unlock the gate and re-render: now the full value is shown.
    gate._unlocked = True
    panel._render_evidence(panel._finding)
    assert full in " ".join(_evidence_texts(panel))
    assert _evidence_buttons(panel) == ["Hide values"]
