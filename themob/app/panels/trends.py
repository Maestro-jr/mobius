"""Trends: what the operator's own scans add up to, over time.

The read-only face of the local intelligence layer (themob.intel). It shows the
corpus built from every project in this store: how many apps and findings, the
severity mix, the weaknesses that recur most (and how often they are confirmed
versus dismissed), the platform split, and which weaknesses travel together.

Local to this machine, and advisory: it reports what the deterministic engine
already found, and changes none of it. The corpus is a full read of the store,
so it is computed when this page is shown, not on every refresh during a run.

House style: labelled sections, hairlines, and figures on the ground. No cards.
"""
from __future__ import annotations

from typing import Optional

from PyQt6.QtWidgets import (QFrame, QHBoxLayout, QPushButton, QScrollArea,
                             QVBoxLayout, QWidget)

from ...model.enums import Severity
from .. import theme
from ..widgets.common import (CountRow, Metric, MetricRow, Rule, Section,
                              caption, page_layout, value)

_PLATFORM_COLORS = {"android": theme.ACCENT, "ios": theme.ACCENT_SOFT}


def _clear(layout) -> None:
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.setParent(None)


class TrendsPanel(QScrollArea):
    """The local corpus, rendered. Computed on show, never on the run's path."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        host = QWidget()
        self.setWidget(host)
        self._root = page_layout(host)

        self._home = None
        self._dirty = True
        self._build()

    # ------------------------------------------------------------------ build

    def _build(self) -> None:
        summary = Section("Across your scans")
        self._status = caption("")
        self._status.setWordWrap(True)
        summary.body.addWidget(self._status)
        self._metrics = MetricRow()
        self._apps = self._metrics.add(Metric("apps scanned", "0"))
        self._findings = self._metrics.add(Metric("findings", "0"))
        self._metrics.add_stretch()
        summary.body.addWidget(self._metrics)
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self._force_refresh)
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.addWidget(refresh)
        row.addStretch()
        summary.body.addLayout(row)
        self._root.addWidget(summary)

        severity = Section("By severity")
        from ..widgets.common import SeverityCounts
        self._severity = SeverityCounts()
        severity.body.addWidget(self._severity)
        self._root.addWidget(severity)

        weak = Section("Most common weaknesses")
        caption_hint = caption("Across how many of your apps each one appeared. "
                               "Hover a row for the confirmed/dismissed split.")
        caption_hint.setWordWrap(True)
        weak.body.addWidget(caption_hint)
        self._weak_box = QWidget()
        self._weak_layout = QVBoxLayout(self._weak_box)
        self._weak_layout.setContentsMargins(0, 4, 0, 0)
        self._weak_layout.setSpacing(0)
        weak.body.addWidget(self._weak_box)
        self._root.addWidget(weak)

        platform = Section("By platform")
        self._platform_box = QWidget()
        self._platform_layout = QVBoxLayout(self._platform_box)
        self._platform_layout.setContentsMargins(0, 0, 0, 0)
        self._platform_layout.setSpacing(0)
        platform.body.addWidget(self._platform_box)
        self._root.addWidget(platform)

        cooc = Section("Often found together")
        self._cooc_box = QWidget()
        self._cooc_layout = QVBoxLayout(self._cooc_box)
        self._cooc_layout.setContentsMargins(0, 0, 0, 0)
        self._cooc_layout.setSpacing(0)
        cooc.body.addWidget(self._cooc_box)
        self._root.addWidget(cooc)

        self._root.addStretch(1)

    # ------------------------------------------------------------------- data

    def bind(self, home) -> None:
        self._home = home
        self._dirty = True

    def load(self, home=None) -> None:
        """Called on the main refresh: cheap, it only marks the corpus stale."""
        if home is not None:
            self._home = home
        self._dirty = True

    def clear(self) -> None:
        self._dirty = True

    def showEvent(self, event) -> None:                        # noqa: N802
        super().showEvent(event)
        if self._dirty:
            self._rebuild()

    def _force_refresh(self) -> None:
        self._dirty = True
        self._rebuild()

    def _rebuild(self) -> None:
        from ...intel import corpus as corpus_mod

        try:
            corpus = corpus_mod.summarize(self._home)
        except Exception as exc:                               # noqa: BLE001
            self._status.setText(f"The corpus could not be read: {exc}")
            self._dirty = True
            return
        self._dirty = False

        self._apps.set(corpus.projects)
        self._findings.set(corpus.findings)
        if corpus.is_empty:
            self._status.setText(
                "Local to this machine, nothing leaves it. Scan a few apps and "
                "this fills in: the weaknesses that recur, and how often you "
                "confirm them.")
        else:
            self._status.setText(
                "Local to this machine, nothing leaves it. Built from every "
                f"project in this store, as of {corpus.generated_at}.")

        self._severity.set_counts(
            {s: corpus.by_severity.get(s.value, 0) for s in Severity})
        self._fill_weaknesses(corpus)
        self._fill_platforms(corpus)
        self._fill_cooccurrence(corpus)

    def _fill_weaknesses(self, corpus) -> None:
        _clear(self._weak_layout)
        if not corpus.weaknesses:
            self._weak_layout.addWidget(caption("Nothing yet."))
            return
        for stat in corpus.weaknesses[:15]:
            try:
                color = theme.severity_color(Severity(stat.severity))
            except ValueError:
                color = theme.TEXT_MUTED
            row = CountRow(color, stat.title or stat.key, stat.apps)
            verdict = (f"{stat.occurrences} found · {stat.confirmed} confirmed · "
                       f"{stat.false_positive} dismissed")
            rate = stat.false_positive_rate
            if rate is not None:
                verdict += f" · {round(rate * 100)}% dismissed"
            row.setToolTip(f"{stat.key}\n{verdict}")
            self._weak_layout.addWidget(row)

    def _fill_platforms(self, corpus) -> None:
        _clear(self._platform_layout)
        if not corpus.by_platform:
            self._platform_layout.addWidget(caption("Nothing yet."))
            return
        for name, count in sorted(corpus.by_platform.items(),
                                  key=lambda kv: kv[1], reverse=True):
            color = _PLATFORM_COLORS.get(name, theme.TEXT_MUTED)
            self._platform_layout.addWidget(CountRow(color, name, count))

    def _fill_cooccurrence(self, corpus) -> None:
        _clear(self._cooc_layout)
        if not corpus.co_occurrence:
            self._cooc_layout.addWidget(
                caption("Not enough shared patterns across apps yet."))
            return
        for key_a, key_b, shared in corpus.co_occurrence[:12]:
            line = value(f"{key_a}  +  {key_b}")
            line.setToolTip(f"in {shared} of your apps")
            row = QHBoxLayout()
            row.setContentsMargins(0, 1, 0, 1)
            row.addWidget(line)
            row.addStretch()
            from ..widgets.common import mono
            row.addWidget(mono(f"{shared} apps"))
            holder = QWidget()
            holder.setLayout(row)
            self._cooc_layout.addWidget(holder)
