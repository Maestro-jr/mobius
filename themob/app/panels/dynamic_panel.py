"""Dynamic analysis: the console's door into Phase 3.

Everything the dynamic engine can do exists in :mod:`themob.dynamic`, but until
this panel it was reachable only from Python. This is the seat an operator uses.

It is built around the fact that themob does not, and should not, run a device
for you. So the panel does the three things it can do safely from the desktop:

* **attest**, recording the execution authorization the whole phase gates on,
  the device, the traffic, and the hosts that may be intercepted;
* **prepare**, turning a chosen job into the exact command to run against that
  device, so nothing is guessed and the interception scope travels as data;
* **import**, taking the output a run produced back in and merging it onto the
  graph, which is where a runtime observation becomes a finding beside the
  static ones.

The running itself, spawning Frida, driving mitmproxy, happens on the operator's
device with the prepared command, not inside this process. That boundary is the
same one the whole phase draws: themob prepares and records, the device runs.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QFrame,
                             QGridLayout, QHBoxLayout, QLineEdit, QPushButton,
                             QScrollArea, QWidget)

from ...audit.attestation import AuditTrail, current_operator
from ...dynamic import (Adb, AdbError, ExecutionAttestation, DeviceAttestation,
                        ExecutionNotAuthorized, Instrumentation, capture)
from ...dynamic.gate import require_execution
from ...dynamic.instrument import OBJECTION_JOBS, available_agents
from ...dynamic.session import DynamicSession
from ...storage.repositories import Repositories
from ...storage.workspace import Workspace
from .. import theme
from ..widgets.common import Rule, Section, caption, label, page_layout
from ..widgets.dialog import MessageDialog


class DynamicPanel(QScrollArea):
    """Attest, prepare a run, and import what it observed."""

    findings_merged = pyqtSignal()          # ask the window to refresh the graph

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)

        host = QWidget()
        self.setWidget(host)
        self._root = page_layout(host)

        self._repos: Repositories | None = None
        self._audit: AuditTrail | None = None
        self._workspace: Workspace | None = None
        self._project_id: str = ""
        self._adb = Adb()

        self._build()

    # ------------------------------------------------------------------ build

    def _build(self) -> None:
        self._status = label("No project loaded.", "", f"color:{theme.TEXT_MUTED};")
        self._root.addWidget(self._status)
        self._root.addWidget(Rule())

        self._build_authorization()
        self._build_device()
        self._build_run()
        self._root.addStretch()

    def _build_authorization(self) -> None:
        section = Section("Execution authorization")
        section.body.addWidget(caption(
            "Running an app is a different act from reading it. Attest the "
            "device, the traffic, and the hosts that may be intercepted."))

        grid = QGridLayout()
        grid.setContentsMargins(0, 6, 0, 0)
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(8)

        self._device_id = QLineEdit()
        self._device_id.setPlaceholderText("adb serial, e.g. emulator-5554")
        grid.addWidget(caption("Device"), 0, 0)
        grid.addWidget(self._device_id, 0, 1)

        self._scope = QLineEdit()
        self._scope.setPlaceholderText(
            "hosts to intercept, comma separated; .example.com covers subdomains")
        grid.addWidget(caption("Interception scope"), 1, 0)
        grid.addWidget(self._scope, 1, 1)

        section.body.addLayout(grid)

        self._dedicated = QCheckBox(
            "This is a dedicated test device or emulator, not a personal phone")
        self._traffic = QCheckBox(
            "Generating live traffic to the app's backends is authorized")
        section.body.addWidget(self._dedicated)
        section.body.addWidget(self._traffic)

        self._auth_hint = label("", "danger")
        self._auth_hint.setWordWrap(True)
        section.body.addWidget(self._auth_hint)

        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        self._authorize = QPushButton("Authorize dynamic analysis")
        self._authorize.setObjectName("primary")
        self._authorize.clicked.connect(self._on_authorize)
        row.addWidget(self._authorize)
        row.addStretch()
        section.body.addLayout(row)

        self._root.addWidget(section)

    def _build_device(self) -> None:
        section = Section("Device")
        self._devices = label("Not checked. Refresh to list connected devices.",
                              "", f"color:{theme.TEXT_MUTED};")
        self._devices.setWordWrap(True)
        section.body.addWidget(self._devices)

        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        refresh = QPushButton("Refresh devices")
        refresh.clicked.connect(self._on_refresh_devices)
        row.addWidget(refresh)
        row.addStretch()
        section.body.addLayout(row)
        self._root.addWidget(section)

    def _build_run(self) -> None:
        section = Section("Prepare a run, then import what it saw")
        section.body.addWidget(caption(
            "themob prepares the command; you run it against the device, then "
            "import the result here to merge it onto the graph."))

        row = QHBoxLayout()
        row.setContentsMargins(0, 6, 0, 0)
        row.setSpacing(8)

        self._job = QComboBox()
        for agent in available_agents():
            self._job.addItem(f"frida agent: {agent}", ("frida", agent))
        for job in sorted(OBJECTION_JOBS):
            self._job.addItem(f"objection: {job}", ("objection", job))
        self._job.addItem("mitmproxy capture", ("capture", ""))
        row.addWidget(self._job)

        prepare = QPushButton("Show command")
        prepare.clicked.connect(self._on_prepare)
        row.addWidget(prepare)
        row.addStretch()
        section.body.addLayout(row)

        section.body.addWidget(Rule())

        imports = QHBoxLayout()
        imports.setContentsMargins(0, 6, 0, 0)
        imports.setSpacing(8)
        frida = QPushButton("Import Frida output...")
        frida.clicked.connect(self._on_import_frida)
        cap = QPushButton("Import capture log...")
        cap.clicked.connect(self._on_import_capture)
        imports.addWidget(frida)
        imports.addWidget(cap)
        imports.addStretch()
        section.body.addLayout(imports)

        self._run_hint = label("", "")
        self._run_hint.setWordWrap(True)
        section.body.addWidget(self._run_hint)
        self._root.addWidget(section)

    # ------------------------------------------------------------------- data

    def bind(self, repos: Repositories, audit: AuditTrail) -> None:
        self._repos = repos
        self._audit = audit

    def load(self, project_id: str, workspace: Workspace | None) -> None:
        self._project_id = project_id
        self._workspace = workspace
        self._refresh_status()

    def clear(self) -> None:
        self._project_id = ""
        self._workspace = None
        self._status.setText("No project loaded.")

    def _refresh_status(self) -> None:
        if not (self._repos and self._project_id):
            self._status.setText("No project loaded.")
            return
        try:
            detail = require_execution(self._repos, self._project_id)
        except ExecutionNotAuthorized:
            self._status.setText(
                "Not authorized for dynamic analysis. Attest below before "
                "running anything against a device.")
            self._status.setStyleSheet(f"color:{theme.WARN};")
            return
        scope = ", ".join(detail.get("interception_scope") or []) or "nothing"
        self._status.setText(
            f"Authorized on {detail.get('device_id')}. Intercepting: {scope}.")
        self._status.setStyleSheet(f"color:{theme.OK};")

    # ---------------------------------------------------------------- actions

    def _on_authorize(self) -> None:
        if not (self._repos and self._audit and self._project_id):
            return
        scope = [h.strip() for h in self._scope.text().split(",") if h.strip()]
        attestation = ExecutionAttestation(
            operator=current_operator(),
            device=DeviceAttestation(
                identifier=self._device_id.text().strip(),
                dedicated_test_device=self._dedicated.isChecked(),
                is_emulator=self._device_id.text().strip().startswith("emulator-")),
            traffic_authorized=self._traffic.isChecked(),
            interception_scope=scope)
        try:
            from ...dynamic import gate
            gate.authorize(attestation, self._project_id, self._audit)
        except ExecutionNotAuthorized as exc:
            self._auth_hint.setText(str(exc))
            return
        self._auth_hint.setText("")
        self._refresh_status()

    def _on_refresh_devices(self) -> None:
        if not self._adb.is_available():
            self._devices.setText(
                "adb is not on PATH. Install the Android platform tools to "
                "discover devices.")
            return
        try:
            devices = self._adb.devices(with_properties=True)
        except AdbError as exc:
            self._devices.setText(str(exc))
            return
        if not devices:
            self._devices.setText("No devices connected.")
            return
        lines = [f"{d.label}  {d.state}"
                 + ("  (looks like a personal phone)"
                    if d.looks_like_a_daily_driver else "")
                 for d in devices]
        self._devices.setText("\n".join(lines))

    def _on_prepare(self) -> None:
        if not (self._repos and self._project_id):
            return
        kind, name = self._job.currentData()
        try:
            plan = self._plan(kind, name)
        except (ExecutionNotAuthorized, Exception) as exc:  # noqa: BLE001
            MessageDialog.show_error(self, "That run could not be prepared.",
                                     str(exc))
            return
        command = " ".join(plan["command"]) if plan["command"] else "(none)"
        detail = command
        if plan.get("instructions"):
            detail += "\n\n" + "\n".join(plan["instructions"])
        MessageDialog(self, title="Run this against the device",
                      message=plan["description"], detail=detail).exec()

    def _plan(self, kind: str, name: str) -> dict:
        if kind == "capture":
            work = (self._workspace.reports_dir / "capture"
                    if self._workspace else Path.cwd())
            plan = capture.mitmproxy_capture(self._repos, self._project_id, work)
            return {"description": "mitmproxy capture, scoped to the attestation",
                    "command": plan.command, "instructions": plan.instructions}
        instr = Instrumentation(adb=self._adb)
        package = self._package()
        if kind == "frida":
            plan = instr.frida_script(self._repos, self._project_id, package, name)
        else:
            plan = instr.objection_job(self._repos, self._project_id, package, name)
        return {"description": plan.description, "command": plan.command,
                "instructions": []}

    def _package(self) -> str:
        from ...model.enums import EntityType

        apps = self._repos.entities.list(self._project_id, EntityType.APP)
        for app in apps:
            package = app.attributes.get("package")
            if isinstance(package, str) and package:
                return package
        return ""

    def _on_import_frida(self) -> None:
        path = self._pick("Import Frida output", "Text (*.txt *.log);;All (*)")
        if not path:
            return
        text = Path(path).read_text(encoding="utf-8", errors="replace")
        self._merge(lambda s: s.record_frida(self._project_id, text, raw_ref=path))

    def _on_import_capture(self) -> None:
        path = self._pick("Import capture log", "JSON lines (*.jsonl);;All (*)")
        if not path:
            return
        result = capture.read_capture(path)
        self._merge(lambda s: s.record_capture(self._project_id, result,
                                               raw_ref=path))

    def _merge(self, ingest) -> None:
        if not (self._repos and self._audit and self._project_id):
            return
        session = DynamicSession(self._repos, self._audit)
        try:
            outcome = ingest(session)
            session.finalize(self._project_id)
        except ExecutionNotAuthorized as exc:
            self._run_hint.setText(str(exc))
            self._run_hint.setStyleSheet(f"color:{theme.WARN};")
            return
        if not outcome.ok:
            self._run_hint.setText(f"Import failed: {outcome.error}")
            self._run_hint.setStyleSheet(f"color:{theme.ERROR};")
            return
        self._run_hint.setText(
            f"{outcome.findings} runtime finding(s), {outcome.merged} merged "
            "with a static finding.")
        self._run_hint.setStyleSheet(f"color:{theme.TEXT_MUTED};")
        self.findings_merged.emit()

    def _pick(self, title: str, filt: str) -> str:
        path, _ = QFileDialog.getOpenFileName(self, title, "", filt)
        return path
