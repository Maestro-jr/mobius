"""Code: the decompiled-source browser.

A package tree on the left, the source on the right. This is the panel the
build plan describes as "click through to the exact decompiled line": a finding
or a component carries a class name, and this opens it.

Two things it does deliberately:

* **Loads a file only when it is opened.** A decompiled app is tens of
  thousands of files and hundreds of megabytes; reading them eagerly to build
  the tree would stall the UI for minutes. The tree comes from the class index
  jadx wrote, which is metadata only.
* **Refuses to open anything outside the project workspace.** Every path in
  that index came out of a container that parsed a hostile binary, so it goes
  through ``Workspace.resolve`` before anything is read.
"""
from __future__ import annotations

from typing import Any, Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (QFrame, QHBoxLayout, QLineEdit, QPlainTextEdit,
                             QSplitter, QTreeWidget, QTreeWidgetItem,
                             QVBoxLayout, QWidget)

from ...storage.workspace import Workspace, WorkspaceError
from .. import theme
from ..widgets.common import Rule, Section, caption, mono, page_layout
from ..widgets.java_highlighter import JavaHighlighter, source_font

#: Files above this are shown truncated. jadx can emit a single multi-megabyte
#: class for a heavily obfuscated app, and loading it whole locks the UI.
_MAX_SOURCE_BYTES = 4 * 1024 * 1024
#: Above this many classes the tree is built lazily per package.
_LARGE_TREE = 4000

_ROLE_PATH = Qt.ItemDataRole.UserRole
_ROLE_FQCN = Qt.ItemDataRole.UserRole + 1


class CodePanel(QWidget):
    """Browse and read the decompiled sources."""

    class_opened = pyqtSignal(str)          # fully-qualified class name

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._workspace: Workspace | None = None
        self._index: list[dict[str, Any]] = []
        self._by_fqcn: dict[str, dict[str, Any]] = {}
        self._current: str | None = None
        # Package item id -> (item, its class entries), for lazy population. A
        # huge app has tens of thousands of classes; building a tree item for
        # every one up front freezes the UI, so above _LARGE_TREE the classes
        # under a package are created only when the package is expanded.
        self._pending: dict[int, tuple] = {}

        root = page_layout(self)
        root.setSpacing(12)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)

        self._tree_panel = Section("Classes")
        self._filter = QLineEdit()
        self._filter.setPlaceholderText("filter classes...")
        self._filter.textChanged.connect(self._apply_filter)
        self._tree_panel.body.addWidget(self._filter)

        self._tree = QTreeWidget()
        self._tree.setHeaderHidden(True)
        self._tree.setUniformRowHeights(True)          # keeps a huge tree smooth
        self._tree.currentItemChanged.connect(self._on_selected)
        self._tree.itemExpanded.connect(self._on_item_expanded)
        self._tree_panel.body.addWidget(self._tree, 1)
        splitter.addWidget(self._tree_panel)

        self._source_panel = Section("Source")
        self._path_label = mono("")
        self._path_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        self._source_panel.add_header_widget(self._path_label)

        self._source = QPlainTextEdit()
        self._source.setReadOnly(True)
        self._source.setFont(source_font())
        self._source.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self._source.setStyleSheet(
            f"background:transparent; border:none; color:{theme.TEXT_PRIMARY};"
            f"selection-background-color:{theme.SELECTION_BG};")
        self._highlighter = JavaHighlighter(self._source.document())
        self._source_panel.body.addWidget(self._source, 1)
        splitter.addWidget(self._source_panel)

        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 3)
        splitter.setSizes([340, 900])
        root.addWidget(splitter, 1)

        self._status = caption("")
        root.addWidget(self._status)
        self.clear()

    # ------------------------------------------------------------------- data

    def load(self, workspace: Workspace | None, index: list[dict[str, Any]],
             *, partial: bool = False) -> None:
        """Render the class index. ``index`` comes from the jadx adapter."""
        self._workspace = workspace
        self._index = index
        self._by_fqcn = {entry["fqcn"]: entry for entry in index}
        self._build_tree(index)

        if not index:
            self._status.setText(
                "No decompiled sources yet. Run the jadx analyzer.")
        else:
            packages = len({entry["package"] for entry in index})
            note = "  ·  decompilation was partial" if partial else ""
            self._status.setText(
                f"{len(index):,} classes in {packages:,} packages{note}")
        self._tree_panel.set_meta(f"{len(index):,}" if index else "")

    def clear(self) -> None:
        self._workspace = None
        self._index = []
        self._by_fqcn = {}
        self._current = None
        self._tree.clear()
        self._source.clear()
        self._path_label.setText("")
        self._tree_panel.set_meta("")
        self._status.setText("No decompiled sources yet. Run the jadx analyzer.")

    # ------------------------------------------------------------------- tree

    def _build_tree(self, index: list[dict[str, Any]]) -> None:
        self._tree.clear()
        self._pending.clear()
        if not index:
            return

        by_package: dict[str, list[dict[str, Any]]] = {}
        for entry in index:
            by_package.setdefault(entry["package"] or "(default package)",
                                  []).append(entry)
        lazy = len(index) >= _LARGE_TREE

        self._tree.setUpdatesEnabled(False)
        try:
            for package in sorted(by_package):
                entries = sorted(by_package[package], key=lambda e: e["name"])
                parent = QTreeWidgetItem(self._tree,
                                         [f"{package}  ({len(entries)})"])
                parent.setForeground(0, _brush(theme.TEXT_SECONDARY))
                if lazy:
                    # A placeholder so the expand arrow shows; the real class
                    # items are created in _on_item_expanded, not now.
                    parent.addChild(QTreeWidgetItem(["..."]))
                    self._pending[id(parent)] = (parent, entries)
                else:
                    for entry in entries:
                        self._add_class_item(parent, entry)
            if not lazy:
                self._tree.expandAll()
        finally:
            self._tree.setUpdatesEnabled(True)

    @staticmethod
    def _add_class_item(parent: QTreeWidgetItem, entry: dict[str, Any]) -> None:
        item = QTreeWidgetItem(parent, [entry["name"]])
        item.setData(0, _ROLE_PATH, entry["path"])
        item.setData(0, _ROLE_FQCN, entry["fqcn"])
        item.setToolTip(0, entry["fqcn"])

    def _populate(self, package_item: QTreeWidgetItem) -> bool:
        """Create the real class items under a lazy package. Returns True if it
        was pending (and is now populated)."""
        pending = self._pending.pop(id(package_item), None)
        if pending is None:
            return False
        parent, entries = pending
        parent.takeChildren()                   # drop the placeholder
        self._tree.setUpdatesEnabled(False)
        try:
            for entry in entries:
                self._add_class_item(parent, entry)
        finally:
            self._tree.setUpdatesEnabled(True)
        return True

    def _on_item_expanded(self, item: QTreeWidgetItem) -> None:
        self._populate(item)

    def _apply_filter(self, text: str) -> None:
        needle = text.strip().lower()
        for i in range(self._tree.topLevelItemCount()):
            package_item = self._tree.topLevelItem(i)
            pending = self._pending.get(id(package_item))
            if pending is not None and needle:
                # Decide from the stored entries without building items for a
                # package that does not match, so filtering stays cheap.
                _parent, entries = pending
                if not any(needle in e["fqcn"].lower() for e in entries):
                    package_item.setHidden(True)
                    continue
                self._populate(package_item)    # it matches: build it, then filter
            elif pending is not None:
                package_item.setHidden(False)   # no filter: leave it lazy
                continue

            visible_children = 0
            for j in range(package_item.childCount()):
                child = package_item.child(j)
                fqcn = (child.data(0, _ROLE_FQCN) or "").lower()
                match = not needle or needle in fqcn
                child.setHidden(not match)
                visible_children += int(match)
            package_item.setHidden(visible_children == 0)
            if needle and visible_children:
                package_item.setExpanded(True)

    # ------------------------------------------------------------------ source

    def open_class(self, fqcn: str) -> bool:
        """Open a class by name. Returns whether it was found."""
        entry = self._by_fqcn.get(fqcn)
        if entry is None:
            return False
        self._select_in_tree(fqcn)
        self._show(entry)
        return True

    def _select_in_tree(self, fqcn: str) -> None:
        for i in range(self._tree.topLevelItemCount()):
            package_item = self._tree.topLevelItem(i)
            for j in range(package_item.childCount()):
                child = package_item.child(j)
                if child.data(0, _ROLE_FQCN) == fqcn:
                    package_item.setExpanded(True)
                    self._tree.setCurrentItem(child)
                    self._tree.scrollToItem(child)
                    return

    def _on_selected(self, current: QTreeWidgetItem | None, _previous) -> None:
        if current is None:
            return
        fqcn = current.data(0, _ROLE_FQCN)
        if fqcn:
            entry = self._by_fqcn.get(fqcn)
            if entry is not None:
                self._show(entry)

    def _show(self, entry: dict[str, Any]) -> None:
        self._current = entry["fqcn"]
        self._path_label.setText(entry["fqcn"])
        self._source.setPlainText(self._read(entry))
        self._source.moveCursor(self._source.textCursor().MoveOperation.Start)
        self.class_opened.emit(entry["fqcn"])

    def _read(self, entry: dict[str, Any]) -> str:
        """Read one source file, refusing anything outside the workspace."""
        if self._workspace is None:
            return "// no workspace is loaded"
        try:
            path = self._workspace.resolve(entry["path"])
        except WorkspaceError as exc:
            # The index came from tool output; a path that escapes is a red flag
            # worth showing rather than silently skipping.
            return f"// refused to open a path outside the project workspace\n// {exc}"
        if not path.is_file():
            return (f"// {entry['path']} is missing from the workspace\n"
                    "// re-run the jadx analyzer to regenerate it")

        try:
            size = path.stat().st_size
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                text = handle.read(_MAX_SOURCE_BYTES)
        except OSError as exc:
            return f"// could not read {entry['path']}: {exc}"

        if size > _MAX_SOURCE_BYTES:
            text += (f"\n\n// ... truncated at {_MAX_SOURCE_BYTES // 1024 // 1024} MB "
                     f"of {size / 1024 / 1024:.1f} MB")
        return text

    # ---------------------------------------------------------------- queries

    @property
    def current_class(self) -> str | None:
        return self._current

    def has_class(self, fqcn: str) -> bool:
        return fqcn in self._by_fqcn


def _brush(color: str):
    from PyQt6.QtGui import QBrush, QColor
    return QBrush(QColor(color))
