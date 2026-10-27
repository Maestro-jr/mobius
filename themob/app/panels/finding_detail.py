"""One finding, in full, and the verdict a tester records against it.

The build plan calls this loop the difference between a console and a report
generator. A scanner produces candidates; an assessment is what a person
concluded about them. So this panel is two halves: everything themob knows,
then the place to disagree with it.

Two decisions shape the layout.

**The rationale sits next to the severity, not in a tooltip.** The scorer may
have raised a rating because an exported component reaches the finding, and a
tester who cannot see why a MEDIUM became HIGH has no way to argue with it. A
rating you cannot question is one you end up ignoring.

**Suppressing verdicts demand a reason before the button works.** Marking
something a false positive removes it from the report, and an unexplained
removal cannot be told apart from an oversight. The engine refuses it anyway;
the panel disables the button so the refusal is not a surprise.
"""
from __future__ import annotations

from typing import Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QPlainTextEdit,
                             QPushButton, QScrollArea, QVBoxLayout, QWidget)

from ...model.enums import FindingStatus, Severity
from ...model.findings import Finding
from ...orchestrator.validation import VERDICT_LABELS, VERDICTS
from ...storage.repositories import Note
from .. import icons, theme
from ..widgets.common import (KeyValues, Rule, Section, caption, heading,
                              label, mono, page_layout, value)
from ..widgets.secret_gate import SecretGate, is_secret_finding, mask_secret

# Verdicts that take a finding out of the report, and so need a reason typed
# before they can be recorded.
_NEEDS_REASON = (FindingStatus.FALSE_POSITIVE, FindingStatus.ACCEPTED_RISK)


class FindingDetail(QScrollArea):
    """The full schema for one finding, plus the validation controls."""

    verdict_requested = pyqtSignal(str, object, str)   # finding id, status, note
    location_requested = pyqtSignal(str)               # fully qualified class
    back_requested = pyqtSignal()

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)

        host = QWidget()
        self.setWidget(host)
        self._root = page_layout(host)
        self._finding: Finding | None = None
        # Set by the window; None in isolation (tests, previews), where secrets
        # simply render masked with no way to reveal.
        self._secret_gate: SecretGate | None = None

        self._build_header()
        self._build_facts()
        self._build_evidence()
        self._build_verdict()
        self._root.addStretch()

    # ------------------------------------------------------------------ build

    def _build_header(self) -> None:
        row = QHBoxLayout()
        row.setSpacing(10)
        # A left chevron and the word, as one target. The icon is drawn (icons
        # module), not a glyph, so it renders the same on every Windows font.
        back = QWidget()
        back.setCursor(Qt.CursorShape.PointingHandCursor)
        back.mousePressEvent = lambda _e: self.back_requested.emit()
        back_row = QHBoxLayout(back)
        back_row.setContentsMargins(0, 0, 0, 0)
        back_row.setSpacing(4)
        arrow = QLabel()
        arrow.setPixmap(icons.pixmap("chevron_left", 13, theme.ACCENT))
        back_text = label("Back", "link")
        # The children ignore the mouse so the whole row is one hit target with
        # one pointer cursor, rather than three.
        for child in (arrow, back_text):
            child.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
            back_row.addWidget(child)
        row.addWidget(back)
        row.addStretch()
        self._root.addLayout(row)

        self._title = heading("")
        self._title.setWordWrap(True)
        self._root.addWidget(self._title)

        severity_row = QHBoxLayout()
        severity_row.setSpacing(14)
        self._severity = label("", "severityValue")
        severity_row.addWidget(self._severity)
        self._confidence = caption("")
        severity_row.addWidget(self._confidence)
        self._status = caption("")
        severity_row.addWidget(self._status)
        severity_row.addStretch()
        self._root.addLayout(severity_row)

        # Why the severity is what it is. Next to the number, not hidden in a
        # tooltip: a rating a tester cannot question is one they ignore.
        self._rationale = caption("")
        self._rationale.setWordWrap(True)
        self._root.addWidget(self._rationale)

        self._description = value("")
        self._description.setWordWrap(True)
        self._root.addWidget(self._description)
        self._root.addWidget(Rule())

    def _build_facts(self) -> None:
        row = QHBoxLayout()
        row.setSpacing(14)

        self._standards_panel = Section("Standards")
        self._standards = KeyValues()
        self._standards_panel.body.addWidget(self._standards)
        # Without this the grid stretches to fill the column, and a panel with
        # one row renders its label top-aligned against a vertically centred
        # value. Standards happens to have six rows and hid the problem.
        self._standards_panel.body.addStretch()
        row.addWidget(self._standards_panel, 1)

        self._where_panel = Section("Where")
        self._where = KeyValues()
        self._where_panel.body.addWidget(self._where)
        self._open_code = label("Open in the code browser", "link")
        self._open_code.setCursor(Qt.CursorShape.PointingHandCursor)
        self._open_code.mousePressEvent = self._on_open_code
        self._open_code.hide()
        self._where_panel.body.addWidget(self._open_code)
        self._where_panel.body.addStretch()
        row.addWidget(self._where_panel, 1)

        self._root.addLayout(row)

    def _build_evidence(self) -> None:
        self._evidence_panel = Section("Evidence")
        self._evidence_body = QVBoxLayout()
        self._evidence_body.setSpacing(4)
        self._evidence_panel.body.addLayout(self._evidence_body)
        self._root.addWidget(self._evidence_panel)

        self._remediation_panel = Section("Remediation")
        self._remediation = value("")
        self._remediation.setWordWrap(True)
        self._remediation_panel.body.addWidget(self._remediation)
        self._root.addWidget(self._remediation_panel)

    def _build_verdict(self) -> None:
        self._verdict_panel = Section("Your verdict")
        self._verdict_panel.body.addWidget(caption(
            "A scanner produces candidates. What you concluded is the "
            "assessment, and it is recorded in the audit trail."))

        self._note = QPlainTextEdit()
        self._note.setPlaceholderText(
            "Why? Required to mark a finding false positive or accepted risk.")
        self._note.setFixedHeight(64)
        self._note.textChanged.connect(self._sync_buttons)
        self._verdict_panel.body.addWidget(self._note)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        self._buttons: dict[FindingStatus, QPushButton] = {}
        for status in VERDICTS:
            button = QPushButton(VERDICT_LABELS[status])
            if status is FindingStatus.CONFIRMED:
                button.setObjectName("primary")
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.clicked.connect(
                lambda _checked, s=status: self._emit_verdict(s))
            self._buttons[status] = button
            buttons.addWidget(button)
        buttons.addStretch()
        self._verdict_panel.body.addLayout(buttons)

        self._notes_panel = Section("Notes")
        self._notes_body = QVBoxLayout()
        self._notes_body.setSpacing(4)
        self._notes_panel.body.addLayout(self._notes_body)

        self._root.addWidget(self._verdict_panel)
        self._root.addWidget(self._notes_panel)

    # ------------------------------------------------------------------- data

    def load(self, finding: Finding, notes: list[Note],
             sources: list[tuple[str, float | None]] | None = None) -> None:
        self._finding = finding

        self._title.setText(finding.title)
        self._severity.setText(finding.severity.value.title())
        self._severity.setStyleSheet(
            f"color:{theme.severity_color(finding.severity)};")
        self._confidence.setText(
            f"{int(round(finding.confidence * 100))}% confidence"
            + (f"  ·  risk {finding.risk:.0f}" if finding.risk is not None else ""))
        self._status.setText(VERDICT_LABELS.get(finding.status, ""))
        self._rationale.setText(finding.score_rationale or "")
        self._rationale.setVisible(bool(finding.score_rationale))
        self._description.setText(finding.description or "")

        self._render_standards(finding, sources or [])
        self._render_where(finding)
        self._render_evidence(finding)
        self._remediation.setText(
            finding.remediation.summary if finding.remediation else "None recorded.")
        self._render_notes(notes)
        self._note.setPlainText("")
        self._sync_buttons()

    def clear(self) -> None:
        self._finding = None
        self._title.setText("")
        self._severity.setText("")
        self._description.setText("")
        self._standards.clear()
        self._where.clear()
        self._sync_buttons()

    def set_secret_gate(self, gate: SecretGate) -> None:
        """Give the panel the shared reveal gate (the window owns it)."""
        self._secret_gate = gate

    # -------------------------------------------------------------- rendering

    def _render_standards(self, finding: Finding,
                          sources: list[tuple[str, float | None]]) -> None:
        self._standards.clear()
        self._standards.add("Weakness", finding.weakness_key or "-")
        self._standards.add("MASVS", finding.masvs_control
                            or (finding.masvs_category.value
                                if finding.masvs_category else "-"))
        # Shown even when absent, because "not mapped yet" is information: it
        # says the pack has no verified id rather than that none exists.
        self._standards.add("MASWE", finding.maswe_id or "not mapped")
        self._standards.add("Mobile Top 10", finding.mobile_top10 or "-")
        self._standards.add("CWE", finding.cwe or "-")
        if sources:
            self._standards.add(
                "Reported by",
                ", ".join(sorted({tool for tool, _c in sources})))

    def _render_where(self, finding: Finding) -> None:
        self._where.clear()
        location = finding.location
        if location is None:
            self._where.add("", "No location recorded.", monospace=False)
            self._open_code.hide()
            return
        for name, text in (("File", location.file), ("Class", location.clazz),
                           ("Method", location.method),
                           ("Component", location.component)):
            if text:
                self._where.add(name, str(text))
        if location.line:
            self._where.add("Line", str(location.line))
        # Only offer the jump when there is a class to jump to.
        self._open_code.setVisible(bool(location.clazz))

    def _render_evidence(self, finding: Finding) -> None:
        _clear_layout(self._evidence_body)
        if not finding.evidence:
            self._evidence_body.addWidget(caption("None recorded."))
            return
        secret = is_secret_finding(finding)
        items = finding.evidence[:20]
        # Split secret evidence by whether themob holds the real value. A value
        # it holds is maskable and worth gating behind the password; one the
        # sandbox already redacted is safe to show and has no fuller form to
        # reveal, so offering a reveal for it would only mislead.
        maskable = secret and any(not e.redacted for e in items)
        has_redacted = secret and any(e.redacted for e in items)
        revealed = (maskable and self._secret_gate is not None
                    and self._secret_gate.unlocked)
        if maskable:
            toggle = QPushButton("Hide values" if revealed else "Reveal values")
            toggle.setCursor(Qt.CursorShape.PointingHandCursor)
            toggle.clicked.connect(self._toggle_secrets)
            self._evidence_body.addWidget(toggle, 0, Qt.AlignmentFlag.AlignLeft)
            self._evidence_body.addWidget(caption(
                "Revealed. Hide them again before you share this screen."
                if revealed else
                "Masked so a credential does not leak onto a shared screen."))
        if has_redacted:
            self._evidence_body.addWidget(caption(
                "Redacted inside the sandbox: the full value never left the "
                "container, so it cannot be shown here."))
        for item in items:
            if secret and not item.redacted and not revealed:
                shown = mask_secret(item.value)
            else:
                shown = item.value
            self._evidence_body.addWidget(mono(shown))
            if item.artifact_path:
                self._evidence_body.addWidget(caption(item.artifact_path))

    def _toggle_secrets(self) -> None:
        """Flip the reveal state (asking for the password) and re-render."""
        if self._secret_gate is not None:
            self._secret_gate.toggle(self)
        if self._finding is not None:
            self._render_evidence(self._finding)

    def _render_notes(self, notes: list[Note]) -> None:
        _clear_layout(self._notes_body)
        self._notes_panel.set_meta(str(len(notes)) if notes else "")
        if not notes:
            self._notes_body.addWidget(caption("No notes yet."))
            return
        for note in notes:
            line = value(note.text)
            line.setWordWrap(True)
            self._notes_body.addWidget(line)
            self._notes_body.addWidget(
                caption(f"{note.author or 'unknown'} · {note.created_at}"))

    # ------------------------------------------------------------ interaction

    def _sync_buttons(self) -> None:
        """A verdict that suppresses a finding needs its reason typed first.

        The engine refuses it regardless; disabling the button means the
        refusal is not a surprise after the fact.
        """
        has_finding = self._finding is not None
        has_reason = bool(self._note.toPlainText().strip())
        for status, button in self._buttons.items():
            needs = status in _NEEDS_REASON
            button.setEnabled(has_finding and (has_reason or not needs))
            button.setToolTip(
                "Type a reason above first." if needs and not has_reason else "")

    def _emit_verdict(self, status: FindingStatus) -> None:
        if self._finding is None:
            return
        self.verdict_requested.emit(self._finding.id, status,
                                    self._note.toPlainText().strip())

    def _on_open_code(self, _event) -> None:
        if self._finding is not None and self._finding.location \
                and self._finding.location.clazz:
            self.location_requested.emit(self._finding.location.clazz)


def _clear_layout(layout) -> None:
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.setParent(None)
