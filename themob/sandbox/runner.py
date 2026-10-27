"""Sandboxed execution of analysis tools in disposable Docker containers.

An uploaded APK/IPA is hostile input and the parsers that chew on it have their
own CVEs. Nothing in themob parses a sample in the engine process: every tool
runs here, in a container that has

* **no network** (``--network none``), a malicious sample cannot phone home,
  and a copyleft tool cannot exfiltrate,
* **a read-only root filesystem** plus a ``noexec`` tmpfs for scratch,
* **the sample mounted read-only** at ``/input`` and one writable output mount,
* **no capabilities**, ``no-new-privileges``, and an unprivileged uid,
* **hard CPU / memory / pid / wall-clock limits**, and
* **bounded output capture**: a tool that spews gigabytes is killed, not
  allowed to exhaust engine memory.

This is also the licensing boundary (build plan Sec 6): tools are invoked as
subprocesses, never imported, so a GPL tool stays a separate program.
"""
from __future__ import annotations

import logging
import re
import shutil
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Iterable

logger = logging.getLogger(__name__)

_MEMORY_RE = re.compile(r"^\d+[bkmg]?$", re.IGNORECASE)
# Image references we are willing to run. Anything with a shell metacharacter or
# a leading dash (which would be read as a flag) is refused.
_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}(:[A-Za-z0-9._-]{1,127})?$")
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# An entrypoint override is a bare program name or an absolute path, never a
# shell string, so nothing here can smuggle in a second command.
_ENTRYPOINT_RE = re.compile(r"^/?[A-Za-z0-9._][A-Za-z0-9._/-]{0,127}$")
# A Docker network name, or the literal "none". Validated like everything else
# that reaches argv: this one decides whether the container has a network at
# all, so it is the last place to accept a string on trust.
_NETWORK_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

_DEFAULT_DOCKER = "docker"

# Mount points inside the container. Workers are written against these.
CONTAINER_INPUT = "/input"
CONTAINER_OUTPUT = "/output"
CONTAINER_WORKDIR = "/work"
# Where a scanner reads what an earlier stage already produced. Read-only, and
# separate from /input so a worker cannot confuse "the sample" with "the decoded
# tree": the secret scanners never touch the APK itself.
CONTAINER_SCAN = "/scan"

# nobody:nogroup: present in the distro bases the workers are built on.
_UNPRIVILEGED_UID = "65534:65534"


class SandboxError(RuntimeError):
    """The sandbox could not be used (Docker missing, image missing, bad args)."""


@dataclass(frozen=True)
class SandboxLimits:
    """Resource ceilings for one container run.

    Defaults suit static analysis of a normal-sized APK. jadx on a large app is
    the memory-hungry case; raise ``memory`` for that adapter specifically
    rather than for everything.
    """
    cpus: float = 2.0
    memory: str = "2g"
    pids: int = 512
    timeout_s: float = 300.0
    max_stdout_bytes: int = 64 * 1024 * 1024      # 64 MiB of JSON is already absurd
    max_stderr_bytes: int = 1 * 1024 * 1024
    tmpfs_size: str = "512m"

    def validate(self) -> None:
        if self.cpus <= 0:
            raise SandboxError("cpus must be positive")
        if self.pids <= 0:
            raise SandboxError("pids limit must be positive")
        if self.timeout_s <= 0:
            raise SandboxError("timeout must be positive")
        if not _MEMORY_RE.match(self.memory):
            raise SandboxError(f"invalid memory limit: {self.memory!r}")
        if not _MEMORY_RE.match(self.tmpfs_size):
            raise SandboxError(f"invalid tmpfs size: {self.tmpfs_size!r}")


@dataclass
class SandboxResult:
    """Outcome of one container run."""
    ok: bool = False
    exit_code: int | None = None
    stdout: bytes = b""
    stderr: str = ""
    duration_s: float = 0.0
    timed_out: bool = False
    truncated: bool = False
    error: str | None = None
    command: list[str] = field(default_factory=list)

    def stdout_text(self, limit: int | None = None) -> str:
        data = self.stdout if limit is None else self.stdout[:limit]
        return data.decode("utf-8", "replace")


class _BoundedReader(threading.Thread):
    """Drains a pipe into a bounded buffer, flagging overflow."""

    def __init__(self, stream, cap: int) -> None:
        super().__init__(daemon=True)
        self._stream = stream
        self._cap = cap
        self.data = bytearray()
        self.overflowed = False

    def run(self) -> None:
        try:
            while True:
                chunk = self._stream.read(65536)
                if not chunk:
                    break
                if len(self.data) < self._cap:
                    room = self._cap - len(self.data)
                    self.data.extend(chunk[:room])
                    if len(chunk) > room:
                        self.overflowed = True
                else:
                    self.overflowed = True
        except (ValueError, OSError):          # pipe closed under us on kill
            pass
        finally:
            try:
                self._stream.close()
            except Exception:                  # noqa: BLE001
                pass


class SandboxRunner:
    """Runs analyzer worker images under a locked-down Docker configuration."""

    def __init__(self, docker_bin: str = _DEFAULT_DOCKER,
                 limits: SandboxLimits | None = None) -> None:
        self.docker_bin = docker_bin
        self.limits = limits or SandboxLimits()
        self.limits.validate()
        self._available: bool | None = None
        self._image_cache: dict[str, bool] = {}

    # ------------------------------------------------------------ availability

    def is_available(self) -> bool:
        """Whether a working Docker daemon is reachable (probed once)."""
        if self._available is None:
            if shutil.which(self.docker_bin) is None:
                self._available = False
            else:
                probe = self._docker(["version", "--format", "{{.Server.Version}}"],
                                     timeout=5.0)
                self._available = probe.returncode == 0
                if not self._available:
                    logger.warning("docker is installed but the daemon is not "
                                   "reachable: %s", probe.stderr.strip()[:200])
        return self._available

    def has_image(self, image: str) -> bool:
        """Whether *image* is present locally. themob never pulls implicitly."""
        _validate_image(image)
        if image in self._image_cache:
            return self._image_cache[image]
        if not self.is_available():
            return False
        probe = self._docker(["image", "inspect", image, "--format", "{{.Id}}"],
                             timeout=30.0)
        # docker exits 0 when the image is there and 1 when it genuinely is not.
        # Anything else means the question was not answered: a timeout while the
        # daemon was busy starting a 4GB service, most often. Caching that as
        # "missing" is how a present image gets reported as unbuilt for the rest
        # of the process, with a fix-it message telling the operator to build
        # what they already have. Seen exactly once, which was enough.
        if probe.returncode not in (0, 1):
            logger.warning("could not determine whether %s is present: %s",
                           image, (probe.stderr or "").strip()[:200])
            return False
        present = probe.returncode == 0
        self._image_cache[image] = present
        return present

    def forget_images(self) -> None:
        """Drop the image cache (call after building or pulling worker images)."""
        self._image_cache.clear()

    def prime_images(self, images: Iterable[str]) -> None:
        """Resolve many image probes with a single ``docker images``.

        The per-analyzer availability sweep otherwise shells out once per unique
        image, and a cold ``docker image inspect`` carries a 30s timeout each: a
        dozen of them in series is the UI-thread stall the operator sees as a
        hang. One ``docker images`` lists every local tag in a single call.

        Only presence is cached from it. An image the summary does not name is
        left out of the cache, so :meth:`has_image` still settles it with an
        authoritative inspect: a tag the listing format does not surface (a
        digest reference, say) is never mistaken for absent on the strength of
        this shortcut.
        """
        wanted = {image for image in images
                  if image and image not in self._image_cache
                  and _IMAGE_RE.match(image)}
        if not wanted or not self.is_available():
            return
        probe = self._docker(["images", "--format", "{{.Repository}}:{{.Tag}}"],
                             timeout=15.0)
        if probe.returncode != 0:
            return
        present = {line.strip() for line in probe.stdout.splitlines() if line.strip()}
        for image in wanted:
            if image in present:
                self._image_cache[image] = True

    # -------------------------------------------------------------------- run

    def run(self, image: str, args: list[str], *,
            sample: Path | None = None,
            scan_dir: Path | None = None,
            output_dir: Path | None = None,
            limits: SandboxLimits | None = None,
            env: dict[str, str] | None = None,
            entrypoint: str | None = None,
            network: str = "none") -> SandboxResult:
        """Run ``image`` with ``args`` against ``sample``.

        The sample is mounted read-only at ``/input/<filename>``; ``output_dir``
        is mounted read-write at ``/output``. Neither the host filesystem nor
        the network is otherwise reachable from the container.

        ``scan_dir`` is mounted read-only at ``/scan``, and is how a later stage
        reads what an earlier one produced. The secret scanners work on the
        decoded resources and decompiled sources, not on the package, so giving
        them the sample as well would widen their reach for nothing.

        ``entrypoint`` replaces the image's own. That is how a worker gets
        inspected, and how the containment guarantees are asserted against a
        live container rather than only against the argv.

        ``network`` is ``"none"`` for every analyzer that reads a sample, and
        that is the invariant this module exists to hold. The one exception is
        a client talking to a :class:`~themob.sandbox.service.SandboxService`,
        which joins that service's **internal** network: a network with no
        gateway, so the pair can reach each other and neither can reach the
        internet. See ``service.py`` for why that is stronger than publishing a
        port to the host rather than weaker.
        """
        _validate_image(image)
        if not _NETWORK_RE.match(network):
            raise SandboxError(f"invalid network name: {network!r}")
        limits = limits or self.limits
        limits.validate()

        if not self.is_available():
            return SandboxResult(error="Docker is not available, start Docker "
                                       "Desktop or the docker daemon and retry")
        if not self.has_image(image):
            return SandboxResult(error=f"worker image {image!r} is not built; "
                                       f"run `themob workers build` first")

        container = f"themob-{uuid.uuid4().hex[:12]}"
        command = [self.docker_bin, "run", "--rm", "--name", container]
        command += self._hardening_flags(limits, network)
        if entrypoint is not None:
            if not _ENTRYPOINT_RE.match(entrypoint):
                raise SandboxError(f"unsafe entrypoint: {entrypoint!r}")
            command += ["--entrypoint", entrypoint]

        if sample is not None:
            sample = Path(sample).resolve()
            if not sample.is_file():
                return SandboxResult(error=f"sample not found: {sample}")
            # The container-side name is derived from the host name but never
            # interpolated into a shell: argv only.
            mount_name = _safe_mount_name(sample.name)
            command += ["-v", f"{sample}:{CONTAINER_INPUT}/{mount_name}:ro"]

        if scan_dir is not None:
            scan_dir = Path(scan_dir).resolve()
            if not scan_dir.is_dir():
                return SandboxResult(
                    error=f"nothing to scan: {scan_dir} is not a directory")
            command += ["-v", f"{scan_dir}:{CONTAINER_SCAN}:ro"]

        if output_dir is not None:
            output_dir = Path(output_dir).resolve()
            output_dir.mkdir(parents=True, exist_ok=True)
            command += ["-v", f"{output_dir}:{CONTAINER_OUTPUT}:rw"]

        for key, value in (env or {}).items():
            if not _ENV_NAME_RE.match(key):
                raise SandboxError(f"invalid environment variable name: {key!r}")
            command += ["-e", f"{key}={value}"]

        command.append(image)
        command += [str(a) for a in args]

        return self._execute(command, container, limits)

    def _hardening_flags(self, limits: SandboxLimits,
                         network: str = "none") -> list[str]:
        return [
            "--network", network,
            "--read-only",
            "--tmpfs", f"/tmp:rw,noexec,nosuid,size={limits.tmpfs_size}",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--user", _UNPRIVILEGED_UID,
            "--cpus", str(limits.cpus),
            "--memory", limits.memory,
            # Equal memory and memory-swap disables swap, so the memory cap is real.
            "--memory-swap", limits.memory,
            "--pids-limit", str(limits.pids),
            "--workdir", CONTAINER_WORKDIR,
        ]

    def _execute(self, command: list[str], container: str,
                 limits: SandboxLimits) -> SandboxResult:
        started = time.monotonic()
        try:
            proc = subprocess.Popen(          # noqa: S603, argv list, never a shell
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                shell=False,
            )
        except OSError as exc:
            return SandboxResult(error=f"could not start docker: {exc}",
                                 command=command)

        out_reader = _BoundedReader(proc.stdout, limits.max_stdout_bytes)
        err_reader = _BoundedReader(proc.stderr, limits.max_stderr_bytes)
        out_reader.start()
        err_reader.start()

        timed_out = False
        try:
            proc.wait(timeout=limits.timeout_s)
        except subprocess.TimeoutExpired:
            timed_out = True
            self._force_remove(container)
            try:
                proc.wait(timeout=15.0)
            except subprocess.TimeoutExpired:      # pragma: no cover
                proc.kill()

        out_reader.join(timeout=10.0)
        err_reader.join(timeout=10.0)

        # An output flood is a hostile signal in its own right: kill the run.
        if out_reader.overflowed and not timed_out:
            logger.warning("%s exceeded the stdout cap; container removed", container)
            self._force_remove(container)

        duration = time.monotonic() - started
        stderr = bytes(err_reader.data).decode("utf-8", "replace").strip()
        exit_code = proc.returncode

        if timed_out:
            error = f"timed out after {limits.timeout_s:.0f}s"
        elif out_reader.overflowed:
            error = "tool produced more output than the sandbox allows"
        elif exit_code != 0:
            error = f"exited with code {exit_code}: {stderr[:500]}" if stderr \
                else f"exited with code {exit_code}"
        else:
            error = None

        return SandboxResult(
            ok=error is None,
            exit_code=exit_code,
            stdout=bytes(out_reader.data),
            stderr=stderr,
            duration_s=duration,
            timed_out=timed_out,
            truncated=out_reader.overflowed or err_reader.overflowed,
            error=error,
            command=command,
        )

    # ----------------------------------------------------------------- images

    def build_image(self, image: str, context: Path,
                    dockerfile: Path | None = None,
                    timeout: float = 1800.0) -> SandboxResult:
        """Build a worker image from ``workers/<tool>/``."""
        _validate_image(image)
        context = Path(context).resolve()
        if not context.is_dir():
            return SandboxResult(error=f"build context not found: {context}")
        args = ["build", "-t", image]
        if dockerfile is not None:
            args += ["-f", str(Path(dockerfile).resolve())]
        args.append(str(context))
        probe = self._docker(args, timeout=timeout)
        self.forget_images()
        return SandboxResult(
            ok=probe.returncode == 0, exit_code=probe.returncode,
            stdout=probe.stdout.encode("utf-8", "replace"),
            stderr=probe.stderr.strip(),
            error=None if probe.returncode == 0
            else f"image build failed: {probe.stderr.strip()[:500]}")

    def pull_image(self, reference: str, tag_as: str,
                   timeout: float = 3600.0) -> SandboxResult:
        """Pull an upstream image pinned by digest, and tag it as *tag_as*.

        Only a digest reference is accepted. A tag is a moving pointer and
        "v4.3.2" can be repushed under the same name, so pulling one would give
        a different program on two machines while both claim the same version.

        The local tag is a second name for the same content, not a rebuild: the
        pull is verified afterwards by checking that the image really carries
        the digest that was asked for, which is the closest thing to the
        checksum the built workers verify at build time.
        """
        _validate_image(tag_as)
        repository, _, digest = reference.partition("@")
        if not digest.startswith("sha256:") or len(digest) != 71:
            return SandboxResult(
                error=f"refusing to pull {reference!r}: an upstream image must "
                      "be pinned by digest, as repository@sha256:<64 hex>")
        if not _IMAGE_RE.match(repository):
            return SandboxResult(error=f"invalid repository: {repository!r}")

        probe = self._docker(["pull", reference], timeout=timeout)
        if probe.returncode != 0:
            return SandboxResult(
                ok=False, exit_code=probe.returncode,
                stderr=probe.stderr.strip(),
                error=f"pull failed: {probe.stderr.strip()[:500]}")

        verified = self._docker(
            ["image", "inspect", reference, "-f", "{{json .RepoDigests}}"],
            timeout=60.0)
        if digest not in verified.stdout:
            return SandboxResult(
                error=f"pulled image does not carry {digest}: refusing to tag it")

        tagged = self._docker(["tag", reference, tag_as], timeout=60.0)
        self.forget_images()
        return SandboxResult(
            ok=tagged.returncode == 0, exit_code=tagged.returncode,
            stdout=probe.stdout.encode("utf-8", "replace"),
            stderr=tagged.stderr.strip(),
            error=None if tagged.returncode == 0
            else f"could not tag {reference} as {tag_as}: {tagged.stderr.strip()[:300]}")

    # --------------------------------------------------------------- internals

    def _docker(self, args: list[str], timeout: float) -> subprocess.CompletedProcess:
        """Run the docker CLI and decode its output as UTF-8, never as cp1252.

        ``text=True`` alone decodes with the *locale* encoding, which on Windows
        is cp1252. Docker emits UTF-8, and a build log containing a byte cp1252
        has no mapping for killed the reader thread outright: the exception was
        raised inside the thread, so ``subprocess`` returned ``None`` for both
        streams and the caller then failed on ``None.strip()``, blaming the
        build for what was a decoding bug. Explicit encoding, and ``replace``
        so an undecodable byte is a question mark rather than an exception.
        """
        try:
            proc = subprocess.run(            # noqa: S603, argv list, never a shell
                [self.docker_bin, *args],
                capture_output=True, text=True, timeout=timeout,
                encoding="utf-8", errors="replace",
                stdin=subprocess.DEVNULL, shell=False, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return subprocess.CompletedProcess(args, returncode=125, stdout="",
                                               stderr=str(exc))
        # Belt as well as braces: a caller should never have to guard these.
        if proc.stdout is None:
            proc.stdout = ""
        if proc.stderr is None:
            proc.stderr = ""
        return proc

    def _force_remove(self, container: str) -> None:
        """Kill a container that outlived its budget (the CLI dying does not)."""
        self._docker(["rm", "-f", container], timeout=30.0)


def _validate_image(image: str) -> None:
    if not _IMAGE_RE.match(image or ""):
        raise SandboxError(f"refusing to run unsafe image reference: {image!r}")


def _safe_mount_name(name: str) -> str:
    """A container-side filename that cannot be read as a flag or a path."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", name).lstrip("-")[:120]
    return cleaned or "sample"


def with_limits(runner: SandboxRunner, **overrides) -> SandboxLimits:
    """Copy the runner's limits with per-analyzer overrides applied."""
    limits = replace(runner.limits, **overrides)
    limits.validate()
    return limits
