"""The decompiled-code browser and the Java highlighter.

The browser reads files whose paths came out of a container that parsed a
hostile binary, so the tests that matter are the ones proving it refuses to
open anything outside the project workspace, and that it stays usable on a tree
with tens of thousands of classes.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")

from PyQt6.QtWidgets import QApplication                       # noqa: E402

from themob.app.panels.code import CodePanel                   # noqa: E402
from themob.app.widgets.java_highlighter import (JavaHighlighter,
                                                 source_font)  # noqa: E402
from themob.storage.workspace import Workspace                 # noqa: E402

PACKAGE = "com.example.shop"

_SOURCE = """package com.example.shop;

import javax.crypto.Cipher;

/* decompiled by jadx */
public class MainActivity {
    private static final String KEY = "AKIAIOSFODNN7EXAMPLE";

    public void onCreate() {
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");   // weak
        int flags = 0x1F;
    }
}
"""


@pytest.fixture(scope="session")
def qapp():
    return QApplication.instance() or QApplication([])


@pytest.fixture()
def sources(workspace: Workspace) -> list[dict]:
    """A small decompiled tree, plus its index entries."""
    root = workspace.artifact_dir("jadx") / "sources"
    entries = []
    for package, name, text in (
        (PACKAGE, "MainActivity", _SOURCE),
        (PACKAGE, "SyncService", "package com.example.shop;\nclass SyncService {}\n"),
        ("okhttp3", "OkHttpClient", "package okhttp3;\nclass OkHttpClient {}\n"),
    ):
        directory = root / Path(*package.split("."))
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{name}.java"
        path.write_text(text, encoding="utf-8")
        entries.append({
            "fqcn": f"{package}.{name}",
            "package": package,
            "name": name,
            "path": workspace.relative(path),
            "size": path.stat().st_size,
        })
    return entries


# ------------------------------------------------------------------- loading

def test_empty_state_is_explicit(qapp) -> None:
    panel = CodePanel()
    assert panel._tree.topLevelItemCount() == 0
    assert "jadx" in panel._status.text()


def test_tree_groups_classes_by_package(qapp, workspace, sources) -> None:
    panel = CodePanel()
    panel.load(workspace, sources)

    packages = {panel._tree.topLevelItem(i).text(0).split("  (")[0]
                for i in range(panel._tree.topLevelItemCount())}
    assert packages == {PACKAGE, "okhttp3"}
    assert "3 classes in 2 packages" in panel._status.text()


def test_partial_decompilation_is_stated(qapp, workspace, sources) -> None:
    """A half-decompiled app must not read as a complete one."""
    panel = CodePanel()
    panel.load(workspace, sources, partial=True)
    assert "partial" in panel._status.text()


def test_clear_resets_everything(qapp, workspace, sources) -> None:
    panel = CodePanel()
    panel.load(workspace, sources)
    panel.open_class(f"{PACKAGE}.MainActivity")
    panel.clear()

    assert panel._tree.topLevelItemCount() == 0
    assert panel.current_class is None
    assert panel._source.toPlainText() == ""


# ------------------------------------------------------------------- opening

def test_opening_a_class_shows_its_source(qapp, workspace, sources) -> None:
    panel = CodePanel()
    panel.load(workspace, sources)

    assert panel.open_class(f"{PACKAGE}.MainActivity") is True
    assert panel.current_class == f"{PACKAGE}.MainActivity"
    assert "AES/ECB/PKCS5Padding" in panel._source.toPlainText()
    assert panel._path_label.text() == f"{PACKAGE}.MainActivity"


def test_opening_selects_it_in_the_tree(qapp, workspace, sources) -> None:
    panel = CodePanel()
    panel.load(workspace, sources)
    panel.open_class("okhttp3.OkHttpClient")

    current = panel._tree.currentItem()
    assert current is not None and current.text(0) == "OkHttpClient"


def test_unknown_class_is_reported_not_raised(qapp, workspace, sources) -> None:
    panel = CodePanel()
    panel.load(workspace, sources)
    assert panel.open_class("com.nope.Missing") is False
    assert panel.has_class("com.nope.Missing") is False


def test_selecting_in_the_tree_loads_the_file(qapp, workspace, sources) -> None:
    panel = CodePanel()
    panel.load(workspace, sources)

    package_item = next(panel._tree.topLevelItem(i)
                        for i in range(panel._tree.topLevelItemCount())
                        if panel._tree.topLevelItem(i).text(0).startswith(PACKAGE))
    panel._tree.setCurrentItem(package_item.child(0))
    assert panel.current_class is not None
    assert panel._source.toPlainText() != ""


# ------------------------------------------------------------------ filtering

def test_filter_hides_non_matching_classes(qapp, workspace, sources) -> None:
    panel = CodePanel()
    panel.load(workspace, sources)
    panel._filter.setText("okhttp")

    visible = []
    for i in range(panel._tree.topLevelItemCount()):
        package_item = panel._tree.topLevelItem(i)
        if package_item.isHidden():
            continue
        visible += [package_item.child(j).text(0)
                    for j in range(package_item.childCount())
                    if not package_item.child(j).isHidden()]
    assert visible == ["OkHttpClient"]

    panel._filter.setText("")
    assert not panel._tree.topLevelItem(0).isHidden()


# ------------------------------------------------------------- path safety

def test_refuses_a_path_outside_the_workspace(qapp, workspace) -> None:
    """The index came from tool output. Escaping it must be refused loudly,
    not silently skipped: a tester should see that something is wrong."""
    panel = CodePanel()
    panel.load(workspace, [{"fqcn": "a.Evil", "package": "a", "name": "Evil",
                            "path": "../../../../etc/passwd", "size": 1}])
    panel.open_class("a.Evil")

    text = panel._source.toPlainText()
    assert "refused" in text
    assert "root:" not in text


def test_a_missing_file_says_so(qapp, workspace) -> None:
    panel = CodePanel()
    panel.load(workspace, [{"fqcn": "a.Gone", "package": "a", "name": "Gone",
                            "path": "artifacts/jadx/sources/a/Gone.java",
                            "size": 1}])
    panel.open_class("a.Gone")
    assert "missing from the workspace" in panel._source.toPlainText()


def test_a_huge_file_is_truncated_not_loaded_whole(qapp, workspace) -> None:
    """An obfuscated app can decompile to one multi-megabyte class; loading it
    whole locks the UI."""
    from themob.app.panels import code as code_module

    directory = workspace.artifact_dir("jadx")
    big = directory / "Big.java"
    # Long lines, not many short ones: the size cap is what is under test, not
    # Qt's ability to lay out a million paragraphs.
    line = "// " + "x" * 4000 + "\n"
    big.write_text(line * ((code_module._MAX_SOURCE_BYTES // len(line)) + 200),
                   encoding="utf-8")
    assert big.stat().st_size > code_module._MAX_SOURCE_BYTES

    panel = CodePanel()
    panel.load(workspace, [{"fqcn": "a.Big", "package": "a", "name": "Big",
                            "path": workspace.relative(big),
                            "size": big.stat().st_size}])
    panel.open_class("a.Big")

    text = panel._source.toPlainText()
    assert "truncated" in text
    assert len(text) < big.stat().st_size


def test_no_workspace_is_handled(qapp, sources) -> None:
    panel = CodePanel()
    panel.load(None, sources)
    panel.open_class(f"{PACKAGE}.MainActivity")
    assert "no workspace" in panel._source.toPlainText()


# ------------------------------------------------------------------ big trees

def test_a_large_tree_loads_lazily(qapp, workspace) -> None:
    """Building a tree item for every one of tens of thousands of classes up
    front freezes the UI, so above the threshold only package nodes are built;
    a package's classes appear when it is expanded."""
    from themob.app.panels import code as code_module

    entries = [{"fqcn": f"p{i % 50}.C{i}", "package": f"p{i % 50}",
                "name": f"C{i}", "path": f"artifacts/jadx/sources/C{i}.java",
                "size": 10}
               for i in range(code_module._LARGE_TREE + 100)]
    panel = CodePanel()
    panel.load(workspace, entries)

    assert panel._tree.topLevelItemCount() == 50
    first = panel._tree.topLevelItem(0)
    assert not first.isExpanded()
    # Lazy: a single placeholder child, not the real class items, until expanded.
    assert first.childCount() == 1
    assert panel._pending                       # packages are queued, not built
    first.setExpanded(True)                     # triggers _on_item_expanded
    assert first.childCount() > 1               # now the real classes are there
    assert id(first) not in panel._pending

    # The filter reaches a class in a package that was never expanded.
    panel._apply_filter("C149")                 # in package p49 (149 % 50)
    hits = [panel._tree.topLevelItem(i) for i in range(panel._tree.topLevelItemCount())
            if not panel._tree.topLevelItem(i).isHidden()]
    assert any(h.text(0).startswith("p49") for h in hits)


def test_a_large_tree_loads_collapsed(qapp, workspace) -> None:
    from themob.app.panels import code as code_module

    entries = [{"fqcn": f"p{i % 50}.C{i}", "package": f"p{i % 50}",
                "name": f"C{i}", "path": f"artifacts/jadx/sources/C{i}.java",
                "size": 10}
               for i in range(code_module._LARGE_TREE + 100)]
    panel = CodePanel()
    panel.load(workspace, entries)

    assert panel._tree.topLevelItemCount() == 50
    assert not panel._tree.topLevelItem(0).isExpanded()


def test_a_small_tree_loads_expanded(qapp, workspace, sources) -> None:
    panel = CodePanel()
    panel.load(workspace, sources)
    assert panel._tree.topLevelItem(0).isExpanded()


# ---------------------------------------------------------------- highlighter

def test_highlighter_colours_tokens(qapp) -> None:
    from PyQt6.QtWidgets import QPlainTextEdit

    editor = QPlainTextEdit()
    editor.setFont(source_font())
    highlighter = JavaHighlighter(editor.document())
    editor.setPlainText(_SOURCE)
    # Highlighting is scheduled against layout; force it rather than depending
    # on a paint happening in an offscreen test.
    highlighter.rehighlight()

    block = editor.document().findBlockByLineNumber(5)      # `public class ...`
    formats = block.layout().formats()
    assert formats, "keywords on this line should be formatted"
    from themob.app import theme
    colours = {fmt.format.foreground().color().name() for fmt in formats}
    assert theme.ACCENT_BRIGHT.lower() in colours, "keywords use the accent"


def test_highlighter_survives_broken_decompiled_output(qapp) -> None:
    """jadx emits partial method bodies under --show-bad-code; the highlighter
    is lexical precisely so it does not give up on those files."""
    from PyQt6.QtWidgets import QPlainTextEdit

    editor = QPlainTextEdit()
    JavaHighlighter(editor.document())
    for text in ('public class A { /* unterminated',
                 'String s = "unterminated',
                 "/* block\nspanning\nlines */ int x = 1;",
                 "", "\x00\x01 not really java"):
        editor.setPlainText(text)
        assert editor.document().blockCount() >= 1
