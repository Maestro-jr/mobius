"""Preflight: does this installation actually work, and if not, what is missing.

``python -m themob --check``

Written for the moment before the first real assessment, and for the bug report
that follows a failed one. themob depends on things it does not control: a
Docker daemon, seven built images, a Java runtime inside two of them, data packs
that may live in a checkout or in an installed prefix. When one of those is
missing the symptom is usually a stage that quietly reports nothing, and "no
findings" reads exactly like "nothing wrong with the app".

So every check states what it looked for and where. A check that fails prints
the command that fixes it. Nothing here starts a container or touches a project:
it reports, and exits non-zero if anything required is missing.
"""
from __future__ import annotations

import platform
import sqlite3
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

OK = "ok"
WARN = "warn"
FAIL = "fail"

# Wide enough for "not built" and for a version string, narrow enough that the
# detail column starts in the same place on every line.
_STATE_WIDTH = 6


@dataclass
class Check:
    """One thing that has to be true, and what to do when it is not."""

    name: str
    state: str
    detail: str = ""
    fix: str = ""

    @property
    def required(self) -> bool:
        return self.state == FAIL


def themob_version() -> Check:
    """First line of any bug report, so it is the first line of the check.

    A checkout that was never installed has no package metadata to read, which
    is worth saying rather than papering over: it is also the state in which
    the weakness packs resolve from the working tree rather than the install.
    """
    from . import __version__

    if __version__.endswith("+unknown"):
        return Check("themob", WARN, f"{__version__} (no package metadata)",
                     'pip install -e "." so the version is recorded in reports')
    return Check("themob", OK, __version__)


def python_version() -> Check:
    major, minor = sys.version_info[:2]
    detail = f"{major}.{minor}.{sys.version_info[2]} on {platform.system()}"
    if (major, minor) < (3, 11):
        return Check("python", FAIL, detail, "themob needs Python 3.11 or newer")
    return Check("python", OK, detail)


def dependencies() -> list[Check]:
    """The three imports the engine cannot start without, plus their versions.

    Versioned because a report is only reproducible against the code that made
    it, and "it worked on my machine" usually means a different pydantic.
    """
    out: list[Check] = []
    for module, label in (("PyQt6.QtCore", "PyQt6"), ("pydantic", "pydantic"),
                          ("networkx", "networkx")):
        try:
            imported = __import__(module, fromlist=["*"])
        except ImportError as exc:
            out.append(Check(label, FAIL, str(exc),
                             'pip install -e ".[dev]"'))
            continue
        version = (getattr(imported, "PYQT_VERSION_STR", None)
                   or getattr(imported, "__version__", "unknown"))
        out.append(Check(label, OK, str(version)))
    return out


def knowledge_packs() -> Check:
    """The weakness catalogue: without it no finding can be keyed at all."""
    try:
        from .knowledge import KNOWLEDGE_DIR, catalogue
    except Exception as exc:                            # noqa: BLE001
        return Check("weakness packs", FAIL, str(exc),
                     "set THEMOB_KNOWLEDGE_DIR, or run from a checkout")

    entries = catalogue()
    from .knowledge import warnings as pack_warnings

    pack_issues = pack_warnings()
    if pack_issues:
        # An unsigned or skipped extra pack changes what the tool checks, so it
        # is surfaced here rather than left in a log nobody reads.
        return Check("weakness packs", WARN,
                     f"{len(entries)} weaknesses; " + "; ".join(pack_issues[:3]),
                     "sign extra packs, or set THEMOB_KNOWLEDGE_PUBKEYS to trust "
                     "them, or drop them")

    unmapped = sum(1 for w in entries.values() if not w.maswe_id)
    detail = f"{len(entries)} weaknesses from {KNOWLEDGE_DIR}"
    if unmapped:
        # Stated, not hidden: a null standards id is a gap in the report, and
        # the operator should know before a client asks about it.
        return Check("weakness packs", WARN,
                     f"{detail} ({unmapped} with no MASWE id)",
                     "fill maswe_id from https://mas.owasp.org/MASWE/")
    return Check("weakness packs", OK, detail)


def semgrep_rules() -> Check:
    from .knowledge import KNOWLEDGE_DIR

    rules = sorted((KNOWLEDGE_DIR / "semgrep").glob("*.yml"))
    if not rules:
        return Check("semgrep rules", WARN,
                     f"none found in {KNOWLEDGE_DIR / 'semgrep'}",
                     "the SAST stage will report nothing")
    return Check("semgrep rules", OK,
                 f"{len(rules)} file(s): {', '.join(p.name for p in rules)}")


def migrations() -> Check:
    """Every migration must be present and applyable to a fresh database."""
    from .storage.db import open_database

    directory = Path(__file__).resolve().parent / "storage" / "migrations"
    files = sorted(directory.glob("*.sql"))
    if not files:
        return Check("migrations", FAIL, f"none found in {directory}",
                     "reinstall themob: the package data is incomplete")
    # Applied to a throwaway file rather than ":memory:": Database resolves its
    # path, so an in-memory handle would become a file literally named
    # ":memory:", which Windows refuses outright.
    try:
        with tempfile.TemporaryDirectory(prefix="themob-preflight-") as tmp:
            database = open_database(Path(tmp) / "probe.db")
            tables = {row["name"] for row in database.query(
                "SELECT name FROM sqlite_master WHERE type = 'table'")}
            database.close_all()
    except (sqlite3.Error, OSError) as exc:
        return Check("migrations", FAIL, f"{len(files)} file(s): {exc}",
                     "the schema could not be applied to a fresh database")
    return Check("migrations", OK,
                 f"{len(files)} applied, {len(tables)} tables")


def logo() -> Check:
    asset = Path(__file__).resolve().parent / "app" / "assets" / "mob-logo.png"
    if not asset.is_file():
        return Check("logo artwork", WARN, f"no {asset.name}",
                     "python tools/install_logo.py <image>, or the painted "
                     "fallback is used")
    return Check("logo artwork", OK, f"{asset.stat().st_size} bytes")


def docker() -> list[Check]:
    """The daemon, and every image the registered analyzers actually ask for.

    Asked of the registry rather than of ``workers/``, because the registry is
    what the pipeline consults: each analyzer names its own image, and an
    installed copy has no ``workers/`` directory at all yet runs perfectly well
    against images that are already built.

    A missing image is FAIL rather than WARN. themob has no host fallback by
    design, so the stage is skipped, and a skipped stage reads exactly like a
    clean one, which is the failure this whole file exists to prevent.
    """
    from .adapters import build_registry
    from .adapters.base import Availability
    from .sandbox.build import WORKERS_DIR, discover
    from .sandbox.runner import SandboxRunner

    runner = SandboxRunner()
    if not runner.is_available():
        return [Check("docker", FAIL, "daemon not reachable",
                      "start Docker Desktop, then python -m themob.sandbox.build")]

    out = [Check("docker", OK, "daemon reachable")]

    # Each analyzer is asked whether *it* is ready, rather than having its
    # image looked up here. MobSF needs two images and says so in its own
    # availability(); reimplementing that check would get it wrong, and the
    # symptom would be a preflight that reports ready and a stage that finds
    # nothing.
    #
    # An analyzer with no image reads another stage's output rather than the
    # package, so it needs no container and belongs in neither count.
    containerised = [a for a in build_registry().all() if a.image]
    missing = sorted(a.name for a in containerised
                     if a.availability(runner) != Availability.READY)
    if missing:
        out.append(Check("worker images", FAIL,
                         f"{len(containerised) - len(missing)}/"
                         f"{len(containerised)} ready, "
                         f"not ready: {', '.join(missing)}",
                         "python -m themob.sandbox.build"))
    else:
        out.append(Check("worker images", OK,
                         f"{len(containerised)} analyzers ready"))

    # Buildable is a separate question from runnable. Docker cannot build from
    # outside a build context, so the Dockerfiles only exist in a checkout.
    if not discover():
        out.append(Check("worker sources", WARN,
                         f"no Dockerfiles under {WORKERS_DIR}",
                         "images cannot be built or rebuilt from here; that "
                         "needs a checkout of the repository"))
    return out


def android_tools() -> Check:
    """adb, which Phase 3 needs and Phases 1 and 2 do not.

    A warning rather than a failure: the static pipeline is the whole of what
    most runs use, and failing a preflight over a tool nothing has asked for
    yet would train an operator to ignore it.
    """
    from .dynamic.adb import Adb

    adb = Adb()
    if not adb.is_available():
        return Check("adb", WARN, "not on PATH",
                     "needed only for dynamic analysis; install the Android "
                     "platform tools when you get to it")
    devices = []
    try:
        devices = adb.devices(with_properties=False)
    except Exception:                                   # noqa: BLE001
        pass
    detail = adb.version() or "available"
    if devices:
        detail += f", {len(devices)} device(s): " + ", ".join(
            f"{d.serial} ({d.state})" for d in devices[:4])
    return Check("adb", OK, detail)


def capture_tools() -> Check:
    """mitmproxy, for Phase 3 traffic capture. A warning, like adb."""
    from .dynamic import capture

    if capture.is_available():
        return Check("mitmproxy", OK, "available")
    return Check("mitmproxy", WARN, "not on PATH",
                 "needed only for traffic capture; attach-your-own-Burp works "
                 "without it, or pip install mitmproxy")


def workspace() -> Check:
    from .storage.workspace import default_root

    root = default_root()
    try:
        root.mkdir(parents=True, exist_ok=True)
        probe = root / ".themob-write-probe"
        probe.write_text("", encoding="utf-8")
        probe.unlink()
    except OSError as exc:
        return Check("workspace", FAIL, f"{root}: {exc}",
                     "set THEMOB_HOME to a writable directory")
    return Check("workspace", OK, str(root))


def run() -> list[Check]:
    """Every check, in the order an operator would hit them."""
    checks: list[Check] = [themob_version(), python_version()]
    checks.extend(dependencies())
    checks.append(knowledge_packs())
    checks.append(semgrep_rules())
    checks.append(migrations())
    checks.append(logo())
    checks.append(workspace())
    checks.append(android_tools())
    checks.append(capture_tools())
    checks.extend(docker())
    return checks


def report(checks: list[Check] | None = None, stream=None) -> int:
    """Print the checks. Returns 0 when nothing required is missing."""
    checks = run() if checks is None else checks
    stream = stream or sys.stdout
    width = max(len(c.name) for c in checks)

    print("themob preflight\n", file=stream)
    for check in checks:
        print(f"  {check.name:<{width}}  {check.state:<{_STATE_WIDTH}}"
              f"{check.detail}", file=stream)
        if check.fix and check.state != OK:
            print(f"  {'':<{width}}  {'':<{_STATE_WIDTH}}{check.fix}",
                  file=stream)

    failed = [c for c in checks if c.state == FAIL]
    warned = [c for c in checks if c.state == WARN]
    print(file=stream)
    if failed:
        print(f"{len(failed)} required check(s) failed. themob will not "
              "analyze anything until they pass.", file=stream)
        return 1
    if warned:
        print(f"Ready, with {len(warned)} warning(s) above.", file=stream)
        return 0
    print("Ready.", file=stream)
    return 0


if __name__ == "__main__":                                # pragma: no cover
    sys.exit(report())
