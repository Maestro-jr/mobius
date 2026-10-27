"""themob jadx worker: decompile DEX to Java.

Runs inside a network-less container with the sample mounted read-only at
``/input`` and a writable ``/output``. Decompiles with jadx, then reports what
came out as one JSON document on stdout. It never raises: a failure is reported
as ``{"ok": false, "error": ...}``.

Resources are **not** decoded here (``--no-res``): apktool already produced
them, and jadx redoing that work would double the slowest stage for nothing.

The class index goes to ``/output/classes.json`` rather than stdout. A large
app decompiles to tens of thousands of files, and an index that size does not
belong in a pipe the engine caps at 64 MiB.

Contract with ``themob/adapters/jadx_decompile.py``:

    { "ok": bool, "error": str|null, "tool": "jadx", "tool_version": str,
      "sources_dir": "sources", "index_path": "classes.json",
      "stats": {...}, "packages": [...], "partial": bool, "stderr_tail": str }
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import traceback

INPUT_DIR = "/input"
OUTPUT_DIR = "/output"
SOURCES_NAME = "sources"
INDEX_NAME = "classes.json"
JADX_LIB = os.environ.get("JADX_LIB", "/opt/jadx/lib")

# Caps. A very large app really does have tens of thousands of classes; the
# index is bounded so neither this process nor the engine can be flooded.
MAX_CLASSES = 40000
MAX_PACKAGES = 4000
MAX_STRING = 4096
STDERR_TAIL = 6000

DECOMPILE_TIMEOUT = 1500

# jadx prints a per-class error tally on completion; worth surfacing, because a
# run that half-failed looks identical to a small app from the outside.
_ERROR_RE = re.compile(r"finished with errors?,?\s*count[:=]?\s*(\d+)", re.I)
_JAVA_CLASS_RE = re.compile(r"^[A-Za-z_$][\w$]*$")


def clip(value, limit: int = MAX_STRING):
    if value is None:
        return None
    text = value if isinstance(value, str) else str(value)
    return text[:limit]


def find_sample() -> str:
    if not os.path.isdir(INPUT_DIR):
        raise RuntimeError("no /input mount")
    names = sorted(n for n in os.listdir(INPUT_DIR)
                   if os.path.isfile(os.path.join(INPUT_DIR, n)))
    if not names:
        raise RuntimeError("no sample mounted at /input")
    return os.path.join(INPUT_DIR, names[0])


def _java(args: list[str], timeout: float) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["java", "-cp", f"{JADX_LIB}/*", "jadx.cli.JadxCLI", *args],
        capture_output=True, text=True, timeout=timeout, check=False)


def jadx_version() -> str:
    try:
        proc = _java(["--version"], timeout=120)
        return clip((proc.stdout or proc.stderr).strip().splitlines()[0], 64)
    except Exception:                                   # noqa: BLE001
        return "unknown"


def decompile(sample: str, destination: str) -> tuple[bool, str]:
    """Run jadx. Returns ``(ok, output_tail)``.

    ``--show-bad-code`` is deliberate: a method jadx cannot fully decompile
    still yields readable-enough output, and a tester would much rather see
    imperfect code than a hole where a method used to be.
    """
    args = [
        "--output-dir", destination,
        "--no-res",                 # apktool owns resources
        "--show-bad-code",
        "--escape-unicode",
        "--deobf",                  # readable names for obfuscated classes...
        "--deobf-min", "2",
        "--threads-count", str(min(4, os.cpu_count() or 2)),
        sample,
    ]
    try:
        proc = _java(args, timeout=DECOMPILE_TIMEOUT)
    except subprocess.TimeoutExpired:
        return False, f"jadx timed out after {DECOMPILE_TIMEOUT}s"
    except OSError as exc:
        return False, f"could not start jadx: {exc}"

    tail = ((proc.stderr or "") + (proc.stdout or ""))[-STDERR_TAIL:]
    sources = os.path.join(destination, SOURCES_NAME)
    if os.path.isdir(sources):
        # jadx exits non-zero when *some* classes failed but still writes the
        # rest. Partial output is worth keeping, so the directory decides.
        return True, tail
    if proc.returncode != 0:
        return False, tail or f"jadx exited with code {proc.returncode}"
    return False, tail or "jadx produced no sources directory"


def build_index(sources_root: str) -> tuple[list[dict], dict[str, int], bool]:
    """Walk the decompiled tree into a class index.

    Returns ``(classes, package_counts, truncated)``. Each entry carries the
    path relative to ``/output`` so the engine can turn it into a workspace
    path without guessing.
    """
    classes: list[dict] = []
    packages: dict[str, int] = {}
    truncated = False

    for dirpath, dirnames, filenames in os.walk(sources_root):
        dirnames.sort()
        for name in sorted(filenames):
            if not name.endswith(".java"):
                continue
            if len(classes) >= MAX_CLASSES:
                truncated = True
                break
            full = os.path.join(dirpath, name)
            relative = os.path.relpath(full, OUTPUT_DIR).replace(os.sep, "/")
            package_path = os.path.relpath(dirpath, sources_root).replace(os.sep, ".")
            package = "" if package_path == "." else package_path
            simple = name[:-5]
            fqcn = f"{package}.{simple}" if package else simple

            try:
                size = os.path.getsize(full)
            except OSError:
                size = 0
            classes.append({
                "fqcn": clip(fqcn, 512),
                "package": clip(package, 400),
                "name": clip(simple, 200),
                "path": clip(relative, 700),
                "size": size,
            })
            packages[package] = packages.get(package, 0) + 1
        if truncated:
            break

    return classes, packages, truncated


def analyze(sample: str) -> dict:
    ok, tail = decompile(sample, OUTPUT_DIR)
    version = jadx_version()
    if not ok:
        return {"ok": False, "error": clip(tail, STDERR_TAIL), "tool": "jadx",
                "tool_version": version}

    sources_root = os.path.join(OUTPUT_DIR, SOURCES_NAME)
    classes, packages, truncated = build_index(sources_root)

    index_path = os.path.join(OUTPUT_DIR, INDEX_NAME)
    try:
        with open(index_path, "w", encoding="utf-8") as handle:
            json.dump({"classes": classes}, handle, separators=(",", ":"))
        index_written = True
    except OSError as exc:
        tail = f"{tail}\ncould not write the class index: {exc}"[-STDERR_TAIL:]
        index_written = False

    match = _ERROR_RE.search(tail or "")
    top_packages = sorted(packages.items(), key=lambda kv: -kv[1])[:MAX_PACKAGES]

    return {
        "ok": True,
        "error": None,
        "tool": "jadx",
        "tool_version": version,
        "sources_dir": SOURCES_NAME,
        "index_path": INDEX_NAME if index_written else None,
        "stats": {
            "class_count": len(classes),
            "package_count": len(packages),
            "source_bytes": sum(c["size"] for c in classes),
            "decompile_errors": int(match.group(1)) if match else None,
            "truncated": truncated,
        },
        # A small sample so the engine can report something even if the index
        # file could not be written.
        "packages": [{"name": name, "classes": count}
                     for name, count in top_packages],
        "partial": bool(match) or truncated,
        "stderr_tail": clip(tail, STDERR_TAIL),
    }


def main() -> int:
    try:
        path = sys.argv[1] if len(sys.argv) > 1 else find_sample()
        document = analyze(path)
    except Exception as exc:                            # noqa: BLE001
        document = {
            "ok": False,
            "error": clip(f"{type(exc).__name__}: {exc}"),
            "tool": "jadx",
            "traceback": clip(traceback.format_exc(), 8000),
        }
    json.dump(document, sys.stdout, separators=(",", ":"), default=str)
    sys.stdout.write("\n")
    sys.stdout.flush()
    return 0 if document.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
