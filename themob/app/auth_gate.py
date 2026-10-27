"""The authorization gate: mandatory, and in front of everything.

No sample is ingested and no analyzer runs until the operator names the target
and attests that they are authorized to assess it. themob decompiles software,
which can implicate ToS and DMCA depending on jurisdiction (build plan Sec 9),
so this is the legal record, not ceremony.

Same shape as TOPRECON's ``AuthorizationGate``: a blocking dialog that writes
the attestation to the audit log *before* the main window can do anything.
:func:`authorize` is the single entry point, so intake and attestation always
happen together: a project can never exist in an unattested state on disk.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (QCheckBox, QFileDialog, QGridLayout, QHBoxLayout,
                             QLineEdit, QPushButton, QVBoxLayout, QWidget)

from ..audit.attestation import AuditTrail, current_operator
from ..orchestrator.intake import (IntakeError, IntakeResult, detect_platform,
                                   validate_sample)
from ..storage.repositories import Repositories
from .widgets.common import Rule, caption, label, mono
from .widgets.dialog import FramelessDialog
from .widgets.logo import MobLogo

logger = logging.getLogger(__name__)

_FILE_FILTER = "Mobile apps (*.apk *.xapk *.apkm *.ipa);;All files (*)"


@dataclass
class GateResult:
    """What the operator attested to."""
    sample_path: Path
    project_name: str
    engagement_ref: str
    scope_note: str
    attested: bool


class AuthorizationGate(FramelessDialog):
    """Blocking dialog: pick a target, attest authorization, or exit."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent, title="themob: Authorization Gate", width=620)
        self._result: Optional[GateResult] = None
        self._build()
        self._validate()

    # ------------------------------------------------------------------ layout

    def _build(self) -> None:
        """Typography and one hairline. No banner card, no boxed checkbox.

        The legal warning carries its weight through wording and placement,
        directly under the thing you are attesting to, rather than through a
        coloured box around it.
        """
        root = self.body
        root.setContentsMargins(26, 4, 26, 22)
        root.setSpacing(16)

        header = QHBoxLayout()
        header.setSpacing(18)
        header.addWidget(MobLogo(height=104))
        titles = QVBoxLayout()
        titles.setSpacing(2)
        titles.addStretch()
        titles.addWidget(label("Authorize a target", "titleLabel"))
        intent = label(
            "themob unpacks and decompiles the app you provide to map its attack "
            "surface. Decompiling software you do not own may breach its licence "
            "and, in some jurisdictions, the law.")
        intent.setWordWrap(True)
        intent.setObjectName("value")
        titles.addWidget(intent)
        titles.addStretch()
        header.addLayout(titles, 1)
        root.addLayout(header)

        root.addWidget(Rule())

        form = QGridLayout()
        form.setHorizontalSpacing(14)
        form.setVerticalSpacing(9)
        form.setColumnMinimumWidth(0, 132)
        form.setColumnStretch(1, 1)

        def field(row: int, name: str, widget, hint: str = "") -> None:
            key = caption(name)
            key.setAlignment(Qt.AlignmentFlag.AlignRight
                             | Qt.AlignmentFlag.AlignVCenter)
            form.addWidget(key, row, 0)
            form.addWidget(widget, row, 1)
            if hint:
                widget.setPlaceholderText(hint)

        self._path = QLineEdit()
        self._path.textChanged.connect(self._validate)
        browse = QPushButton("Browse")
        browse.clicked.connect(self._on_browse)
        file_row = QHBoxLayout()
        file_row.setSpacing(8)
        file_row.addWidget(self._path, 1)
        file_row.addWidget(browse)
        holder = QWidget()
        holder.setLayout(file_row)
        file_row.setContentsMargins(0, 0, 0, 0)
        field(0, "Application", holder)
        self._path.setPlaceholderText("APK, XAPK or IPA")

        self._detail = mono()
        self._detail.setWordWrap(True)
        form.addWidget(self._detail, 1, 1)

        self._name = QLineEdit()
        field(2, "Project", self._name, "defaults to the file name")
        self._ref = QLineEdit()
        field(3, "Engagement", self._ref, "ticket or SOW reference (optional)")
        self._scope = QLineEdit()
        field(4, "Scope", self._scope, "e.g. static analysis only (optional)")
        root.addLayout(form)

        root.addWidget(Rule())

        self._attest = QCheckBox(
            "I own this application, or I hold written authorization to assess it.")
        self._attest.stateChanged.connect(self._validate)
        root.addWidget(self._attest)

        warning = label(
            "Unauthorized use is illegal. Every run is recorded in a "
            "tamper-evident audit log against your operator identity.")
        warning.setWordWrap(True)
        warning.setObjectName("caption")
        root.addWidget(warning)

        self._hint = label("", "danger")
        self._hint.setWordWrap(True)
        root.addWidget(self._hint)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        buttons.addWidget(caption(current_operator()))
        buttons.addStretch()
        cancel = QPushButton("Exit")
        cancel.clicked.connect(self.reject)
        self._go = QPushButton("Authorize and analyze")
        self._go.setObjectName("primary")
        self._go.setEnabled(False)
        self._go.clicked.connect(self._on_authorize)
        buttons.addWidget(cancel)
        buttons.addWidget(self._go)
        root.addLayout(buttons)

    # -------------------------------------------------------------- validation

    def _on_browse(self) -> None:
        path, _filter = QFileDialog.getOpenFileName(
            self, "Select the application package", "", _FILE_FILTER)
        if path:
            self._path.setText(path)

    def _validate(self) -> None:
        """Cheap structural checks only: nothing here parses the package."""
        raw = self._path.text().strip().strip('"')
        problem = ""
        detail = ""

        if raw:
            try:
                sample = validate_sample(Path(raw))
                platform = detect_platform(sample)
                size_mb = sample.stat().st_size / 1024 / 1024
                detail = (f"{platform.value.upper()}  ·  {sample.name}  ·  "
                          f"{size_mb:,.1f} MB")
            except IntakeError as exc:
                problem = str(exc)

        self._detail.setText(detail)
        if problem:
            self._hint.setText(problem)
        elif not raw:
            self._hint.setText("")
        elif not self._attest.isChecked():
            self._hint.setText("You must attest authorization to proceed.")
        else:
            self._hint.setText("")

        self._go.setEnabled(bool(raw) and not problem and self._attest.isChecked())

    def _on_authorize(self) -> None:
        self._validate()
        if not self._go.isEnabled():
            return
        self._result = GateResult(
            sample_path=Path(self._path.text().strip().strip('"')),
            project_name=self._name.text().strip(),
            engagement_ref=self._ref.text().strip(),
            scope_note=self._scope.text().strip(),
            attested=self._attest.isChecked(),
        )
        self.accept()

    def result(self) -> Optional[GateResult]:
        return self._result


def authorize(gate: GateResult, repos: Repositories, audit: AuditTrail, *,
              root: Path | None = None) -> IntakeResult:
    """Ingest the sample and record the attestation, atomically.

    A thin adapter over :func:`themob.orchestrator.authorize.authorize_target`,
    the Qt-free core the headless CLI shares: the dialog collects the operator's
    statement, this hands it over as the OS user, and the core does intake, the
    attestation, and the rollback that keeps an unauthorized sample from ever
    lingering on disk. Raises :class:`IntakeError` or :class:`AuthorizationError`.
    """
    from ..orchestrator.authorize import GateDecision, authorize_target

    return authorize_target(
        GateDecision(
            sample_path=gate.sample_path, project_name=gate.project_name,
            engagement_ref=gate.engagement_ref, scope_note=gate.scope_note,
            attested=gate.attested, operator=current_operator()),
        repos, audit, root=root)
