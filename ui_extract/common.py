"""The shared visual vocabulary.

**No cards.** Structure comes from typography and hairline rules, not from
nesting bordered boxes. A console that wraps every element in a rounded panel
turns into a grid of containers where nothing is more important than anything
else, and a bordered box inside another bordered box is always a mistake.

The rules this file exists to enforce:

* one ground colour: sections sit on the page, they do not float above it;
* a section is a label, a hairline, and its content;
* headings are sentence case at a readable weight, never letter-spaced caps;
* the accent is for the one thing that matters on a screen, not for every
  heading on it;
* vertical rhythm is tight: data first, air second.
"""
from __future__ import annotations

from typing import Callable, Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (QFrame, QGridLayout, QHBoxLayout, QLabel,
                             QScrollArea, QSizePolicy, QVBoxLayout, QWidget)

from ...model.enums import Severity
from .. import theme

# Vertical rhythm. Tight on purpose: this is a console, not a marketing page.
GAP_SECTION = 20
GAP_INNER = 8
MARGIN = 22


# ----------------------------------------------------------------------- text

def label(text: str, object_name: str = "", css: str = "") -> QLabel:
    widget = QLabel(text)
    if object_name:
        widget.setObjectName(object_name)
    if css:
        widget.setStyleSheet(css)
    return widget


def heading(text: str) -> QLabel:
    """A section title. Sentence case, medium weight, primary colour."""
    return label(text, "heading")


def caption(text: str) -> QLabel:
    """Small muted text: units, hints, counts."""
    return label(text, "caption")


def mono(text: str = "") -> QLabel:
    """Monospace for anything machine-generated: hashes, paths, keys."""
    return label(text, "mono")


def value(text: str) -> QLabel:
    """A readable data value in the body face."""
    return label(text, "value")


# ----------------------------------------------------------------- structure

class Rule(QFrame):
    """A hairline. The only divider in the interface."""

    def __init__(self, vertical: bool = False,
                 parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("ruleV" if vertical else "ruleH")
        if vertical:
            self.setFixedWidth(1)
            self.setSizePolicy(QSizePolicy.Policy.Fixed,
                               QSizePolicy.Policy.Expanding)
        else:
            self.setFixedHeight(1)
            self.setSizePolicy(QSizePolicy.Policy.Expanding,
                               QSizePolicy.Policy.Fixed)


class LinkLabel(QLabel):
    """An inline action. Text, not a button, buttons are for commitments."""
    clicked = pyqtSignal()

    def __init__(self, text: str, parent: Optional[QWidget] = None) -> None:
        super().__init__(text, parent)
        self.setObjectName("link")
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def mousePressEvent(self, event) -> None:      # noqa: N802, Qt override
        self.clicked.emit()
        super().mousePressEvent(event)


class Section(QWidget):
    """A titled region: label, hairline, content. No border, no fill.

    Replaces the old bordered ``Panel``. Sections do not nest, if content
    needs its own heading, it is a sibling section, not a box inside a box.
    """

    def __init__(self, title: str = "", meta: str = "",
                 parent: Optional[QWidget] = None, *,
                 scrollable: bool = False) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(GAP_INNER)

        self._head = QHBoxLayout()
        self._head.setContentsMargins(0, 0, 0, 0)
        self._head.setSpacing(10)
        self._title = heading(title)
        self._meta = caption(meta)
        self._head.addWidget(self._title)
        self._head.addWidget(self._meta)
        self._head.addStretch()
        root.addLayout(self._head)
        root.addWidget(Rule())

        if scrollable:
            area = QScrollArea()
            area.setWidgetResizable(True)
            area.setFrameShape(QFrame.Shape.NoFrame)
            area.setHorizontalScrollBarPolicy(
                Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
            host = QWidget()
            self.body = QVBoxLayout(host)
            self.body.setContentsMargins(0, 2, 6, 0)
            self.body.setSpacing(4)
            area.setWidget(host)
            root.addWidget(area, 1)
        else:
            self.body = QVBoxLayout()
            self.body.setContentsMargins(0, 2, 0, 0)
            self.body.setSpacing(GAP_INNER)
            root.addLayout(self.body, 1)

    # -- header ---------------------------------------------------------------

    def set_title(self, text: str) -> None:
        self._title.setText(text)

    def set_meta(self, text: str) -> None:
        self._meta.setText(text)

    def add_header_widget(self, widget: QWidget) -> None:
        self._head.addWidget(widget)

    def add_action(self, text: str, on_click: Callable[[], None]) -> LinkLabel:
        link = LinkLabel(text)
        link.clicked.connect(on_click)
        self._head.addWidget(link)
        return link

    # -- body -----------------------------------------------------------------

    def clear_body(self) -> None:
        while self.body.count():
            item = self.body.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
                widget.deleteLater()

    def show_empty(self, message: str) -> None:
        self.clear_body()
        empty = caption(message)
        empty.setWordWrap(True)
        self.body.addWidget(empty)


class KeyValues(QWidget):
    """A spec-sheet block: muted keys in a left gutter, values beside them.

    The gutter is what makes this readable at a glance, the eye runs down one
    column of labels instead of hunting through a paragraph of pairs.
    """

    GUTTER = 132

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._grid = QGridLayout(self)
        self._grid.setContentsMargins(0, 0, 0, 0)
        self._grid.setHorizontalSpacing(16)
        self._grid.setVerticalSpacing(5)
        self._grid.setColumnMinimumWidth(0, self.GUTTER)
        self._grid.setColumnStretch(1, 1)
        self._rows = 0

    def add(self, key: str, text: str, *, tone: str = "",
            monospace: bool = True) -> QLabel:
        key_label = caption(key)
        key_label.setAlignment(Qt.AlignmentFlag.AlignRight
                               | Qt.AlignmentFlag.AlignTop)
        widget = mono(text) if monospace else value(text)
        widget.setWordWrap(True)
        widget.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        if tone:
            widget.setStyleSheet(
                f"color:{tone}; font-family:{theme.FONT_MONO}; font-size:12px;"
                if monospace else f"color:{tone}; font-size:13px;")
        self._grid.addWidget(key_label, self._rows, 0)
        self._grid.addWidget(widget, self._rows, 1)
        self._rows += 1
        return widget

    def clear(self) -> None:
        while self._grid.count():
            item = self._grid.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
                widget.deleteLater()
        self._rows = 0

    @property
    def is_empty(self) -> bool:
        return self._rows == 0

    def pairs(self) -> list[tuple[str, str]]:
        """The rendered key/value pairs. A read API so callers and tests do
        not have to walk the layout to find out what is on screen."""
        out: list[tuple[str, str]] = []
        for row in range(self._rows):
            key_item = self._grid.itemAtPosition(row, 0)
            value_item = self._grid.itemAtPosition(row, 1)
            if key_item is None or value_item is None:
                continue
            key_widget, value_widget = key_item.widget(), value_item.widget()
            if key_widget is None or value_widget is None:
                continue
            out.append((key_widget.text(), value_widget.text()))
        return out


# -------------------------------------------------------------------- metrics

class Metric(QWidget):
    """One figure with its label beneath. No box.

    ``emphasis`` colours the number; exactly one metric on a screen should use
    it, or the accent stops meaning anything.
    """

    def __init__(self, name: str, text: str = "-", note: str = "",
                 emphasis: str = "", parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        column = QVBoxLayout(self)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(1)

        self._value = label(text, "metricValue")
        if emphasis:
            self._value.setStyleSheet(f"color:{emphasis};")
        self._note = caption(note)
        column.addWidget(caption(name))
        column.addWidget(self._value)
        column.addWidget(self._note)

    def set(self, text: object, note: str | None = None,
            emphasis: str | None = None) -> None:
        self._value.setText(str(text))
        if note is not None:
            self._note.setText(note)
        if emphasis is not None:
            self._value.setStyleSheet(f"color:{emphasis};" if emphasis else "")

    @property
    def text(self) -> str:
        return self._value.text()


class MetricRow(QWidget):
    """Metrics on one flush line, divided by hairlines rather than boxed."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._row = QHBoxLayout(self)
        self._row.setContentsMargins(0, 0, 0, 0)
        self._row.setSpacing(0)
        self._metrics: list[Metric] = []

    def add(self, metric: Metric, stretch: int = 1) -> Metric:
        if self._metrics:
            self._row.addSpacing(26)
            self._row.addWidget(Rule(vertical=True))
            self._row.addSpacing(26)
        self._row.addWidget(metric, stretch)
        self._metrics.append(metric)
        return metric

    def add_stretch(self) -> None:
        self._row.addStretch()


class SeverityCounts(QWidget):
    """The severity histogram as a single flush line of figures."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(0)

        self._counts: dict[Severity, QLabel] = {}
        for index, severity in enumerate(Severity):
            if index:
                row.addSpacing(22)
            cell = QVBoxLayout()
            cell.setSpacing(0)
            number = label("0", "severityValue",
                           f"color:{theme.severity_color(severity)};")
            self._counts[severity] = number
            cell.addWidget(number)
            cell.addWidget(caption(severity.value.title()))
            row.addLayout(cell)
        row.addStretch()

    def set_counts(self, counts: dict[Severity, int]) -> None:
        for severity, widget in self._counts.items():
            count = counts.get(severity, 0)
            widget.setText(str(count))
            # A level with nothing in it recedes rather than shouting a zero.
            widget.setStyleSheet(
                f"color:{theme.severity_color(severity) if count else theme.TEXT_MUTED};")


class CountRow(QWidget):
    """A colour chip, a name, and a right-aligned count. One line, no box."""

    def __init__(self, color: str, text: str, count: int,
                 parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 1, 0, 1)
        row.setSpacing(9)

        chip = QFrame()
        chip.setFixedSize(7, 7)
        chip.setStyleSheet(f"background:{color}; border-radius:3px;")
        row.addWidget(chip)
        row.addWidget(value(text))
        row.addStretch()
        self._count = mono(str(count))
        row.addWidget(self._count)

    def set_count(self, count: int) -> None:
        self._count.setText(str(count))


def page_layout(widget: QWidget) -> QVBoxLayout:
    """The standard page margins and rhythm."""
    layout = QVBoxLayout(widget)
    layout.setContentsMargins(MARGIN, 18, MARGIN, 16)
    layout.setSpacing(GAP_SECTION)
    return layout
