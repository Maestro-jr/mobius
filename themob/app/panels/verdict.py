"""Verdict: the mobius release review, run live from the console.

The window's face for :mod:`themob.mobius`. One button runs the Planner /
Executor / Critic loop over Zetaris, H-MEM and the Nemotron lanes on
Nightshift; every step the agents take streams into "Agents at work" as it
happens, tagged with the sponsor that did it. When the run ends the page shows
the verdict, the reasons with the claims they rest on, the sponsor ledger, and
a link to the explain-why report.

Two switches turn H-MEM and the advisory feeds off for a run, so the effect of
each on the verdict can be shown rather than asserted.

The engine is the same one ``python -m themob.mobius run`` drives; this page
adds nothing to its decisions. It runs on a ``QThread`` and reports through
queued signals, so the window never blocks on a model or a query.

House style: labelled sections, hairlines, figures on the ground. No cards.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from PyQt6.QtCore import QThread, QUrl, pyqtSignal
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (QCheckBox, QComboBox, QFrame, QHBoxLayout, QLineEdit,
                             QPlainTextEdit, QPushButton, QScrollArea, QVBoxLayout,
                             QWidget)

from ...model.enums import Severity
from .. import theme
from ..widgets.common import (KeyValues, Metric, MetricRow, Section, caption,
                              page_layout, value)

_REPO_ENV = Path(__file__).resolve().parents[3] / ".env"
_LABEL = {"ship": "Ship", "ship_with_fixes": "Ship with fixes", "block": "Block"}
# The verdict is a risk statement, so it borrows the semantic severity ramp.
_TONE = {"block": Severity.CRITICAL, "ship_with_fixes": Severity.HIGH,
         "ship": Severity.LOW}
_MAX_LOG_LINES = 2000


class MobiusThread(QThread):
    """One mobius run off the GUI thread. Events arrive through a queued signal."""

    event = pyqtSignal(object)            # trace Event
    finished_ok = pyqtSignal(object, str)  # RunResult, output directory
    failed = pyqtSignal(str)

    def __init__(self, package: str, sector: str, use_memory: bool,
                 use_advisories: bool, kind: str = "app", parent=None) -> None:
        super().__init__(parent)
        self._package = package
        self._sector = sector
        self._memory = use_memory
        self._advisories = use_advisories
        self._kind = kind

    def run(self) -> None:                                     # noqa: D102, QThread
        try:
            from ...assist.meterless import MeterlessClient
            from ...hmem.scan_memory import ScanMemory
            from ...mobius.__main__ import load_env
            from ...mobius.agents import Lanes, RoleModels
            from ...mobius.datalayer import ZetarisClient, ZetarisDataLayer
            from ...mobius.loop import Orchestrator, RunOptions, new_run_id, write_run
            from ...mobius.trace import RunTrace
            from ...storage.workspace import default_root

            load_env(_REPO_ENV)
            run_id = new_run_id()
            trace = RunTrace(run_id)
            trace.subscribe(self.event.emit)
            client = MeterlessClient.from_env()
            if client.state() != "online":
                self.failed.emit(f"Nightshift is not online at {client.base_url}. "
                                 "Open the Nightshift app and try again.")
                return
            models = RoleModels(client, Lanes.from_env(client.model), trace)
            data = ZetarisDataLayer(ZetarisClient.from_env())
            memory = ScanMemory() if self._memory else None
            subject = self._package.strip().lower() if self._kind == "web" else self._package
            options = RunOptions(use_memory=self._memory,
                                 use_advisories=self._advisories,
                                 sector=self._sector or None, kind=self._kind,
                                 target=subject if self._kind == "web" else "")
            result = Orchestrator(data, models, memory, trace, options).run(
                subject or None)
            out = default_root() / "runs" / run_id
            write_run(result, out)
        except Exception as exc:                               # noqa: BLE001
            self.failed.emit(f"{type(exc).__name__}: {exc}")
        else:
            self.finished_ok.emit(result, str(out))


class VerdictPanel(QScrollArea):
    """Run mobius and watch it reason, then read the verdict and its receipts."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        host = QWidget()
        self.setWidget(host)
        self._root = page_layout(host)
        self._thread: MobiusThread | None = None
        self._report = ""
        self._counts = {"sql": 0, "model_call": 0, "retry": 0, "memory": 0}
        self._build()

    # ------------------------------------------------------------------ build

    def _build(self) -> None:
        run = Section("Release verdict", "Planner, Executor and Critic over Zetaris, "
                      "H-MEM and Nemotron")
        about = caption("Asks one question of the scanned app: can it ship, and if not, "
                        "why not. Every reason cites the query that proved it.")
        about.setWordWrap(True)
        run.body.addWidget(about)

        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        self._subject_kind = QComboBox()
        self._subject_kind.addItem("App", "app")
        self._subject_kind.addItem("Website", "web")
        self._subject_kind.setToolTip("Review a mobile app (publish a scan first) or a "
                                     "website (run webscan on the command line first).")
        self._subject_kind.currentIndexChanged.connect(self._on_kind_changed)
        row.addWidget(self._subject_kind)
        self._package = QLineEdit("com.smartway.gceapp")
        self._package.setPlaceholderText("package id, e.g. com.bank.app")
        self._package.setMinimumWidth(240)
        row.addWidget(self._package, 2)
        self._sector = QComboBox()
        self._sector.addItem("Sector from memory", "")
        for name in ("education", "fintech", "health", "kids", "ecommerce",
                     "government", "social", "general"):
            self._sector.addItem(f"Confirm: {name}", name)
        self._sector.setToolTip("Confirming a sector stores it in H-MEM as the "
                                "owner's word; later runs start from it.")
        row.addWidget(self._sector, 1)
        self._use_memory = QCheckBox("Memory (H-MEM)")
        self._use_memory.setChecked(True)
        row.addWidget(self._use_memory)
        self._use_advisories = QCheckBox("Advisories (KEV, EPSS)")
        self._use_advisories.setChecked(True)
        row.addWidget(self._use_advisories)
        self._run = QPushButton("Run review")
        self._run.setObjectName("primary")
        self._run.clicked.connect(self._start)
        row.addWidget(self._run)
        run.body.addLayout(row)

        self._metrics = MetricRow()
        self._verdict = self._metrics.add(Metric("verdict", "-"))
        self._sector_m = self._metrics.add(Metric("sector", "-"))
        self._zetaris = self._metrics.add(Metric("Zetaris queries", "0"))
        self._nemotron = self._metrics.add(Metric("Nemotron calls", "0"))
        self._critic = self._metrics.add(Metric("Critic", "0", "retries"))
        self._memory_m = self._metrics.add(Metric("H-MEM", "0", "memories used"))
        run.body.addWidget(self._metrics)
        self._status = caption("Idle.")
        self._status.setWordWrap(True)
        run.body.addWidget(self._status)
        self._root.addWidget(run)

        split = QHBoxLayout()
        split.setContentsMargins(0, 0, 0, 0)
        split.setSpacing(28)
        work = Section("Agents at work", "live trace")
        self._log = QPlainTextEdit()
        self._log.setReadOnly(True)
        self._log.setMaximumBlockCount(_MAX_LOG_LINES)
        self._log.setMinimumHeight(360)
        self._log.setStyleSheet(
            f"background:transparent; border:none;"
            f"font-family:{theme.FONT_MONO}; font-size:11.5px;"
            f"color:{theme.TEXT_SECONDARY};")
        work.body.addWidget(self._log)
        split.addWidget(work, 3)

        side = QVBoxLayout()
        side.setContentsMargins(0, 0, 0, 0)
        side.setSpacing(20)
        why = Section("Why")
        self._why_box = QVBoxLayout()
        self._why_box.setContentsMargins(0, 0, 0, 0)
        self._why_box.setSpacing(6)
        why.body.addLayout(self._why_box)
        self._why_box.addWidget(caption("The reasons appear when the run ends."))
        side.addWidget(why)
        ledger = Section("Sponsor ledger", "what each one did this run")
        self._ledger = KeyValues()
        ledger.body.addWidget(self._ledger)
        side.addWidget(ledger)
        report = Section("Report")
        self._report_label = caption("Written to disk when the run ends.")
        self._report_label.setWordWrap(True)
        report.body.addWidget(self._report_label)
        self._open = report.add_action("Open report", self._open_report)
        self._open.setEnabled(False)
        side.addWidget(report)
        side.addStretch(1)
        holder = QWidget()
        holder.setLayout(side)
        split.addWidget(holder, 2)
        self._root.addLayout(split, 1)

    # ------------------------------------------------------------------- run

    def _start(self) -> None:
        if self._thread is not None and self._thread.isRunning():
            return
        self._log.clear()
        self._clear_why()
        self._ledger.clear()
        self._open.setEnabled(False)
        self._report = ""
        for metric in (self._zetaris, self._nemotron, self._critic, self._memory_m):
            metric.set("0")
        self._verdict.set("-", emphasis="")
        self._sector_m.set("-", note="")
        self._counts = {"sql": 0, "model_call": 0, "retry": 0, "memory": 0}
        flags = []
        if not self._use_memory.isChecked():
            flags.append("memory off")
        if not self._use_advisories.isChecked():
            flags.append("advisories off")
        self._status.setText("Running" + (f" ({', '.join(flags)})" if flags else "")
                             + ". The agents' steps stream below.")
        self._run.setEnabled(False)
        self._thread = MobiusThread(self._package.text().strip(),
                                    self._sector.currentData() or "",
                                    self._use_memory.isChecked(),
                                    self._use_advisories.isChecked(),
                                    self._subject_kind.currentData() or "app", self)
        self._thread.event.connect(self._on_event)
        self._thread.finished_ok.connect(self._on_done)
        self._thread.failed.connect(self._on_failed)
        self._thread.start()

    def _on_kind_changed(self) -> None:
        if (self._subject_kind.currentData() or "app") == "web":
            self._package.setPlaceholderText("domain, e.g. example.com")
            if self._package.text().strip() == "com.smartway.gceapp":
                self._package.clear()
            self._status.setText("Website review. Run `python -m themob.mobius webscan "
                                "<domain>` first so Zetaris holds the surface.")
        else:
            self._package.setPlaceholderText("package id, e.g. com.bank.app")
            self._status.setText("Idle.")

    def _on_event(self, event) -> None:
        from ...mobius.trace import format_event
        self._log.appendPlainText(format_event(event))
        if event.kind in self._counts:
            self._counts[event.kind] += 1
        if event.kind == "recall":
            self._counts["memory"] = len(event.data.get("ids", []))
        self._zetaris.set(self._counts["sql"])
        self._nemotron.set(self._counts["model_call"])
        self._critic.set(self._counts["retry"])
        self._memory_m.set(self._counts["memory"])
        if event.kind == "plan":
            self._sector_m.set(event.summary.split(" ")[1] if event.summary.startswith(
                "sector ") else "-")

    def _on_done(self, result, out: str) -> None:
        self._run.setEnabled(True)
        verdict = result.verdict.get("verdict", "")
        tone = _TONE.get(verdict)
        self._verdict.set(_LABEL.get(verdict, verdict),
                          emphasis=theme.severity_color(tone) if tone else "")
        self._sector_m.set(result.sector, note=f"from {result.sector_source}")
        self._status.setText(result.verdict.get("headline", ""))
        self._fill_why(result)
        self._fill_ledger(result.trace.ledger())
        self._report = str(Path(out) / "report.md")
        self._report_label.setText(self._report)
        self._open.setEnabled(True)

    def _on_failed(self, message: str) -> None:
        self._run.setEnabled(True)
        self._status.setText(f"The run stopped: {message}")
        self._log.appendPlainText(f"stopped: {message}")

    # ---------------------------------------------------------------- render

    def _clear_why(self) -> None:
        while self._why_box.count():
            item = self._why_box.takeAt(0)
            if item.widget() is not None:
                item.widget().setParent(None)

    def _fill_why(self, result) -> None:
        self._clear_why()
        reasons = [r for r in result.verdict.get("reasons") or [] if isinstance(r, dict)]
        if not reasons:
            self._why_box.addWidget(caption("No reasons were given."))
        for reason in reasons:
            cites = ", ".join(reason.get("claims") or [])
            line = value(f"{reason.get('text', '')}" + (f"  ({cites})" if cites else ""))
            line.setWordWrap(True)
            self._why_box.addWidget(line)
        human = result.verdict.get("needs_human") or []
        if human:
            note = caption("Needs a human decision: " + ", ".join(human))
            note.setWordWrap(True)
            self._why_box.addWidget(note)

    def _fill_ledger(self, ledger: dict) -> None:
        z, h, n = ledger["zetaris"], ledger["hmem"], ledger["nightshift"]
        loop = ledger.get("loop", {})
        self._ledger.clear()
        self._ledger.add("Zetaris", f"{z['queries']} SQL queries, {z['rows']} rows, "
                         f"{len(z['tables'])} tables", monospace=False)
        self._ledger.add("H-MEM", f"{h['memories_recalled']} recalled, "
                         f"{h['decisions_informed']} decisions informed, {h['writes']} written",
                         monospace=False)
        self._ledger.add("Nightshift", f"{n['requests']} requests, {n['tokens']:,} "
                         "tokens", monospace=False)
        self._ledger.add("Nemotron", f"{round(n['nemotron_share'] * 100)}% of answered "
                         "requests", monospace=False)
        if loop:
            self._ledger.add("Loop", ", ".join(f"{v} {k.replace('_', ' ')}" for k, v in loop.items()),
                             monospace=False)

    def _open_report(self) -> None:
        if self._report:
            QDesktopServices.openUrl(QUrl.fromLocalFile(self._report))

    # ------------------------------------------------------- window contract

    def bind(self, *_args) -> None:
        pass

    def load(self, *_args) -> None:
        pass

    def clear(self) -> None:
        pass

    def shutdown(self) -> None:
        if self._thread is not None and self._thread.isRunning():
            self._thread.wait(5000)
