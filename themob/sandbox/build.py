"""Build the sandboxed worker images.

Every analyzer runs inside a container, and themob never pulls one implicitly,
an image that appears on its own is an image nobody reviewed. Worker images are
built locally from ``workers/<tool>/`` and pinned by tag.

Usage::

    python -m themob.sandbox.build            # build every worker
    python -m themob.sandbox.build androguard # build one
    python -m themob.sandbox.build --list     # show images and their state
"""
from __future__ import annotations

import argparse
import os
import shutil
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

from .runner import SandboxRunner

# Repo root: themob/themob/sandbox/build.py -> themob/
WORKERS_DIR = Path(__file__).resolve().parent.parent.parent / "workers"


@dataclass(frozen=True)
class Worker:
    """One buildable worker image."""
    name: str
    image: str
    context: Path

    @property
    def dockerfile(self) -> Path:
        return self.context / "Dockerfile"

    @property
    def buildable(self) -> bool:
        return self.dockerfile.is_file() or self.pin_file.is_file()

    @property
    def pin_file(self) -> Path:
        """``image.txt``: an upstream image this worker pulls instead of builds.

        Some tools are published by their own maintainers and are better run as
        the artifact they ship than as something rebuilt here. MobSF is the
        case this exists for: locked decision 11 says it is reached over REST
        and never vendored, and rebuilding it here would be vendoring it in all
        but name.
        """
        return self.context / "image.txt"

    @property
    def pinned(self) -> str:
        """The upstream reference, which must be pinned by digest.

        A tag is a moving pointer and "v4.3.2" can be repushed under the same
        name; a digest cannot. This is the same guarantee the built workers get
        from checksumming a release archive.
        """
        if not self.pin_file.is_file():
            return ""
        for line in self.pin_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                return line
        return ""

    @property
    def stage_file(self) -> Path:
        return self.context / "stage.txt"

    def staged(self) -> list[tuple[Path, Path]]:
        """Repository paths to copy into the build context before building.

        Docker cannot COPY from outside the build context, and some workers
        need data that lives elsewhere in the repository on purpose. The
        semgrep rules are the case this exists for: the build plan puts rule
        packs in ``knowledge/``, and duplicating them under ``workers/`` to
        satisfy Docker would mean two copies drifting apart.

        Format is one ``source -> destination`` pair per line, source relative
        to the repository root, destination relative to the build context.
        """
        if not self.stage_file.is_file():
            return []
        root = WORKERS_DIR.parent
        pairs: list[tuple[Path, Path]] = []
        for line in self.stage_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "->" not in line:
                continue
            source, _, destination = line.partition("->")
            pairs.append((root / source.strip(), self.context / destination.strip()))
        return pairs


def discover(workers_dir: Path = WORKERS_DIR) -> list[Worker]:
    """Every ``workers/<tool>/Dockerfile`` in the repository.

    The image tag is derived from the directory name, so adding a worker is
    adding a directory: no registry to keep in sync.
    """
    if not workers_dir.is_dir():
        return []
    workers = [
        Worker(name=child.name, image=f"themob/{child.name}:1", context=child)
        for child in sorted(workers_dir.iterdir()) if child.is_dir()
    ]
    return [w for w in workers if w.buildable]


def build(names: list[str] | None = None, *, runner: SandboxRunner | None = None,
          workers_dir: Path = WORKERS_DIR) -> int:
    """Build the named workers (all of them by default). Returns an exit code."""
    runner = runner or SandboxRunner()
    if not runner.is_available():
        print("docker is not available: start Docker Desktop or the daemon "
              "and try again", file=sys.stderr)
        return 2

    workers = discover(workers_dir)
    if names:
        wanted = set(names)
        unknown = wanted - {w.name for w in workers}
        if unknown:
            print(f"unknown worker(s): {', '.join(sorted(unknown))}", file=sys.stderr)
            return 2
        workers = [w for w in workers if w.name in wanted]

    if not workers:
        print(f"no workers found under {workers_dir}", file=sys.stderr)
        return 2

    failures = 0
    for worker in workers:
        if worker.pinned:
            print(f"pulling {worker.image} from {worker.pinned}...", flush=True)
            result = runner.pull_image(worker.pinned, worker.image)
            if result.ok:
                print(f"  ok  {worker.image}")
            else:
                failures += 1
                print(f"  FAILED  {worker.image}: {result.error}", file=sys.stderr)
            continue

        print(f"building {worker.image} from {worker.context}...", flush=True)
        staged = _stage(worker)
        try:
            result = runner.build_image(worker.image, worker.context)
        finally:
            # Always clean up, or a stale staged copy silently becomes the
            # thing that gets built next time. Force-remove so a read-only file
            # does not leave the directory behind for the next run to trip on.
            for path in staged:
                _force_rmtree(path)
        if result.ok:
            print(f"  ok  {worker.image}")
        else:
            failures += 1
            print(f"  FAILED  {worker.image}: {result.error}", file=sys.stderr)
    return 1 if failures else 0


def _force_rmtree(path: Path) -> None:
    """Remove a staged directory, clearing read-only files on the way.

    ``shutil.rmtree(..., ignore_errors=True)`` swallows the failure Windows
    raises on a read-only file and leaves the directory behind, which is what
    made a later ``copytree`` fail with "file already exists". This retries each
    failed removal after dropping the read-only bit, like the workspace teardown.
    """
    def _onerror(func, target, _exc):
        try:
            os.chmod(target, stat.S_IWRITE)
            func(target)
        except OSError:
            pass

    if path.exists():
        shutil.rmtree(path, onerror=_onerror)


def _stage(worker: Worker) -> list[Path]:
    """Copy a worker's declared repository paths into its build context."""
    created: list[Path] = []
    for source, destination in worker.staged():
        if not source.exists():
            print(f"  staged path missing, skipping: {source}", file=sys.stderr)
            continue
        # Clear any leftover from an interrupted build, then copy fresh.
        # dirs_exist_ok is a backstop in case the removal could not fully clear
        # the destination, so a stale directory never blocks the build again.
        _force_rmtree(destination)
        shutil.copytree(source, destination, dirs_exist_ok=True)
        created.append(destination)
        print(f"  staged {source.name} -> {destination.name}")
    return created


def report(runner: SandboxRunner | None = None,
           workers_dir: Path = WORKERS_DIR) -> int:
    runner = runner or SandboxRunner()
    available = runner.is_available()
    print(f"docker: {'available' if available else 'NOT available'}")
    for worker in discover(workers_dir):
        state = ("built" if available and runner.has_image(worker.image)
                 else "not built")
        print(f"  {worker.name:<16} {worker.image:<28} {state}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m themob.sandbox.build",
        description="Build themob's sandboxed analyzer worker images.")
    parser.add_argument("workers", nargs="*",
                        help="worker names to build (default: all)")
    parser.add_argument("--list", action="store_true",
                        help="list worker images and whether they are built")
    args = parser.parse_args(argv)
    return report() if args.list else build(args.workers or None)


if __name__ == "__main__":
    sys.exit(main())
