"""The jadx worker's index builder, tested outside the container.

``workers/jadx/analyze.py`` runs inside Docker, but ``build_index`` is plain
stdlib and is what the whole code browser is built on: if it derives the wrong
fully-qualified name, "click a component, land on its code" silently never
matches anything.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_WORKER = (Path(__file__).resolve().parent.parent
           / "workers" / "jadx" / "analyze.py")


@pytest.fixture(scope="module")
def worker():
    spec = importlib.util.spec_from_file_location("themob_jadx_worker", _WORKER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def sources_tree(worker, tmp_path: Path, monkeypatch) -> Path:
    """A decompiled tree under a stand-in /output."""
    monkeypatch.setattr(worker, "OUTPUT_DIR", str(tmp_path))
    root = tmp_path / "sources"
    for relative, text in {
        "com/example/shop/MainActivity.java": "class MainActivity {}",
        "com/example/shop/SyncService.java": "class SyncService {}",
        "com/example/shop/data/ShopProvider.java": "class ShopProvider {}",
        "okhttp3/OkHttpClient.java": "class OkHttpClient {}",
        "Toplevel.java": "class Toplevel {}",
        "com/example/shop/notes.txt": "not java",
    }.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


# ------------------------------------------------------------------- indexing

def test_derives_fully_qualified_names(worker, sources_tree) -> None:
    classes, _packages, _truncated = worker.build_index(str(sources_tree))
    names = {c["fqcn"] for c in classes}
    assert names == {
        "com.example.shop.MainActivity",
        "com.example.shop.SyncService",
        "com.example.shop.data.ShopProvider",
        "okhttp3.OkHttpClient",
        "Toplevel",
    }


def test_a_default_package_class_has_no_dotted_prefix(worker, sources_tree) -> None:
    classes, _packages, _truncated = worker.build_index(str(sources_tree))
    toplevel = next(c for c in classes if c["name"] == "Toplevel")
    assert toplevel["fqcn"] == "Toplevel"
    assert toplevel["package"] == ""


def test_non_java_files_are_ignored(worker, sources_tree) -> None:
    classes, _packages, _truncated = worker.build_index(str(sources_tree))
    assert all(c["path"].endswith(".java") for c in classes)
    assert not any("notes" in c["fqcn"] for c in classes)


def test_paths_are_relative_to_the_output_mount(worker, sources_tree) -> None:
    """The engine turns these into workspace paths by prefixing; an absolute
    path here would produce something it then refuses to open."""
    classes, _packages, _truncated = worker.build_index(str(sources_tree))
    for entry in classes:
        assert not entry["path"].startswith("/")
        assert entry["path"].startswith("sources/")
        assert "\\" not in entry["path"], "paths are POSIX-style"


def test_counts_classes_per_package(worker, sources_tree) -> None:
    _classes, packages, _truncated = worker.build_index(str(sources_tree))
    assert packages["com.example.shop"] == 2
    assert packages["com.example.shop.data"] == 1
    assert packages["okhttp3"] == 1
    assert packages[""] == 1


def test_sizes_are_recorded(worker, sources_tree) -> None:
    classes, _packages, _truncated = worker.build_index(str(sources_tree))
    assert all(c["size"] > 0 for c in classes)


def test_index_is_capped_and_says_so(worker, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(worker, "OUTPUT_DIR", str(tmp_path))
    monkeypatch.setattr(worker, "MAX_CLASSES", 5)
    root = tmp_path / "sources" / "p"
    root.mkdir(parents=True)
    for i in range(20):
        (root / f"C{i}.java").write_text("x", encoding="utf-8")

    classes, _packages, truncated = worker.build_index(str(tmp_path / "sources"))
    assert len(classes) == 5
    assert truncated is True


def test_an_empty_tree_indexes_to_nothing(worker, tmp_path: Path,
                                          monkeypatch) -> None:
    monkeypatch.setattr(worker, "OUTPUT_DIR", str(tmp_path))
    root = tmp_path / "sources"
    root.mkdir()
    classes, packages, truncated = worker.build_index(str(root))
    assert classes == [] and packages == {} and truncated is False


def test_indexing_is_deterministic(worker, sources_tree) -> None:
    """The code browser's tree order should not shuffle between runs."""
    first, _p, _t = worker.build_index(str(sources_tree))
    second, _p, _t = worker.build_index(str(sources_tree))
    assert [c["fqcn"] for c in first] == [c["fqcn"] for c in second]


# ------------------------------------------------------------------- contract

def test_resources_are_not_decoded_here(worker) -> None:
    """apktool owns resources; jadx redoing them doubles the slowest stage."""
    source = _WORKER.read_text(encoding="utf-8")
    assert '"--no-res"' in source


def test_partial_output_is_kept(worker) -> None:
    """jadx exits non-zero when some classes fail but still writes the rest.
    Throwing that away would lose most of a large app over a few bad methods."""
    source = _WORKER.read_text(encoding="utf-8")
    assert '"--show-bad-code"' in source
    assert "os.path.isdir(sources)" in source


def test_error_count_is_parsed_from_jadx_output(worker) -> None:
    for text, expected in (
        ("finished with errors, count: 12", "12"),
        ("INFO - finished with errors count=3", "3"),
        ("finished with error, count: 1", "1"),
    ):
        match = worker._ERROR_RE.search(text)
        assert match is not None and match.group(1) == expected
    assert worker._ERROR_RE.search("done, no problems") is None


def test_clip_bounds_every_string(worker) -> None:
    assert len(worker.clip("x" * 10_000)) == worker.MAX_STRING
    assert worker.clip(None) is None
