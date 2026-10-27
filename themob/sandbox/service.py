"""A long-lived analyzer that is a server, on a network with no way out.

Every worker in Phase 1 is one shot: start a container with ``--network none``,
read its stdout, throw it away. MobSF is not a program you run, it is a server
you talk to, so it needs a network, and "no network" is the claim this whole
package exists to make. Widening it deserved its own module rather than a flag
quietly added to an adapter.

**The shape, and why it is not the obvious one.** The obvious design publishes
the service's port to ``127.0.0.1`` and has the engine speak HTTP to it. Docker
refuses that on an ``--internal`` network, which turned out to be a favour: the
design it forces is stronger. Instead

* the service runs on an **internal** Docker network, one with no gateway, so
  nothing on it can reach the internet;
* the HTTP client is **another container on that same network**, a one-shot
  worker like any other, which writes its JSON to ``/output``;
* the engine process never opens a socket to the service at all. It reads a
  file, exactly as it does for every other analyzer.

So the sample never touches a network with a route out, the engine never parses
a hostile server's response over the wire, and the adapter above this looks like
every other adapter. The hole in the invariant is "two containers can talk to
each other", not "a container can reach the network".

**Teardown is not optional.** A leaked container holds a copy of someone's app
and a leaked network holds a name that the next run will collide with, so both
are removed in a ``finally``, and removing them is attempted even when the start
itself failed halfway.
"""
from __future__ import annotations

import logging
import re
import subprocess
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Iterator

from .runner import (_ENTRYPOINT_RE, _UNPRIVILEGED_UID, SandboxError,
                     SandboxLimits, SandboxRunner, _validate_image)

logger = logging.getLogger(__name__)

# The alias the client resolves. Fixed, so a worker can be written against it.
SERVICE_HOST = "service"

_ALIAS_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,62}$")


class ServiceError(SandboxError):
    """The service could not be started, or never became ready."""


@dataclass
class ServiceHandle:
    """A running service: what a client needs to reach it, and nothing else."""

    network: str
    host: str
    port: int
    container: str

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"


@dataclass
class ServiceSpec:
    """How to start one service and how to know it is ready.

    ``ready_argv`` runs *inside* the service container via ``docker exec``, and
    must exit zero once the service can answer. It is run from the host rather
    than from the network because the host can always reach a container it
    started, while a client on the internal network cannot be started until the
    network exists and would only tell us the same thing later.
    """

    image: str
    port: int
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    ready_argv: list[str] = field(default_factory=list)
    ready_timeout_s: float = 180.0
    ready_interval_s: float = 2.0
    limits: SandboxLimits | None = None
    # A server needs a writable place to work, and a read-only root plus a
    # noexec tmpfs is not always enough for one. Named here per service rather
    # than relaxed for everything.
    writable_paths: list[str] = field(default_factory=list)
    alias: str = SERVICE_HOST
    # Replaces the image's own, for an image whose entrypoint is an analyzer
    # rather than a server. Validated exactly as the runner validates one: a
    # bare program name or an absolute path, never a shell string.
    entrypoint: str | None = None

    # The two hardening flags a *third-party* image can legitimately refuse.
    #
    # themob builds its workers, so it can guarantee they run as uid 65534 on a
    # read-only root. A service is somebody else's image: MobSF ships its own
    # unprivileged user, owns its home directory, and writes a database into
    # it. Forcing uid 65534 makes it unable to read its own files, and a tmpfs
    # over its home masks the installation, which is exactly how the first
    # attempt at this failed.
    #
    # Opting out is per-service and explicit, so nobody has to guess which
    # profile a container is running under. Everything that carries the actual
    # containment still applies and cannot be opted out of: no route off the
    # host, all capabilities dropped, no-new-privileges, and memory, cpu and
    # pid ceilings. The service is also never given a mount of the sample: a
    # client hands it the bytes over HTTP, so its filesystem reach is its own
    # container and nothing else.
    user: str | None = _UNPRIVILEGED_UID
    read_only: bool = True

    def validate(self) -> None:
        _validate_image(self.image)
        if not 1 <= self.port <= 65535:
            raise ServiceError(f"invalid port: {self.port}")
        if not _ALIAS_RE.match(self.alias):
            raise ServiceError(f"invalid network alias: {self.alias!r}")
        if self.ready_timeout_s <= 0 or self.ready_interval_s <= 0:
            raise ServiceError("readiness timeout and interval must be positive")
        for path in self.writable_paths:
            if not path.startswith("/") or ".." in path:
                raise ServiceError(f"writable path must be absolute: {path!r}")
        if self.entrypoint is not None and not _ENTRYPOINT_RE.match(self.entrypoint):
            raise ServiceError(f"unsafe entrypoint: {self.entrypoint!r}")


class SandboxService:
    """Starts a service container on a private internal network, and removes it."""

    def __init__(self, runner: SandboxRunner | None = None) -> None:
        self._runner = runner or SandboxRunner()
        self.docker_bin = self._runner.docker_bin

    # ------------------------------------------------------------------ public

    @contextmanager
    def running(self, spec: ServiceSpec) -> Iterator[ServiceHandle]:
        """Start *spec*, yield a handle, and always tear it down."""
        spec.validate()
        if not self._runner.is_available():
            raise ServiceError("Docker is not available, start Docker Desktop "
                               "or the docker daemon and retry")
        if not self._runner.has_image(spec.image):
            raise ServiceError(f"service image {spec.image!r} is not built; "
                               "run python -m themob.sandbox.build first")

        token = uuid.uuid4().hex[:12]
        network = f"themob-net-{token}"
        container = f"themob-svc-{token}"

        try:
            self._create_network(network)
            self._start(spec, network, container)
            self._await_ready(spec, container)
            yield ServiceHandle(network=network, host=spec.alias,
                                port=spec.port, container=container)
        finally:
            # Order matters: a network with a container still on it cannot be
            # removed, so the container goes first and its failure does not stop
            # the network from being cleaned up.
            self._remove_container(container)
            self._remove_network(network)

    def client_run(self, handle: ServiceHandle, image: str, args: list[str],
                   **kwargs):
        """Run a one-shot client worker on the service's network.

        Everything else about the container is unchanged: read-only root,
        dropped capabilities, unprivileged uid, the same limits. The only
        difference from any other analyzer is which network it joins.
        """
        return self._runner.run(image, args, network=handle.network, **kwargs)

    # ----------------------------------------------------------------- private

    def _create_network(self, name: str) -> None:
        # --internal is the whole point: Docker creates no gateway for it, so a
        # container on this network has no route off the host. Verified by
        # test_the_service_network_has_no_route_out rather than assumed.
        self._docker(["network", "create", "--internal", name],
                     what=f"create network {name}")

    def _start(self, spec: ServiceSpec, network: str, container: str) -> None:
        limits = spec.limits or self._runner.limits
        limits.validate()

        command = [self.docker_bin, "run", "-d", "--name", container,
                   "--network", network, "--network-alias", spec.alias,
                   # Not negotiable, whatever the image wants.
                   "--cap-drop", "ALL",
                   "--security-opt", "no-new-privileges",
                   "--cpus", str(limits.cpus),
                   "--memory", limits.memory,
                   "--memory-swap", limits.memory,
                   "--pids-limit", str(limits.pids)]
        if spec.read_only:
            command += ["--read-only",
                        "--tmpfs",
                        f"/tmp:rw,noexec,nosuid,size={limits.tmpfs_size}"]
        if spec.user is not None:
            command += ["--user", spec.user]
        for path in spec.writable_paths:
            command += ["--tmpfs", f"{path}:rw,noexec,nosuid,size={limits.tmpfs_size}"]
        for key, value in sorted(spec.env.items()):
            command += ["-e", f"{key}={value}"]
        if spec.entrypoint is not None:
            command += ["--entrypoint", spec.entrypoint]
        command.append(spec.image)
        command += [str(a) for a in spec.args]

        self._docker(command, what=f"start service {spec.image}")

    def _await_ready(self, spec: ServiceSpec, container: str) -> None:
        """Poll until the service answers, or say plainly that it never did.

        A service that is still starting and a service that crashed look the
        same from outside, so a timeout reports the container's own logs. "It
        timed out" on its own sends a reader to the wrong place.
        """
        if not spec.ready_argv:
            return

        deadline = time.monotonic() + spec.ready_timeout_s
        last = ""
        while time.monotonic() < deadline:
            if not self._is_running(container):
                raise ServiceError(
                    f"the service exited before it was ready:\n"
                    f"{self._logs(container)}")
            probe = subprocess.run(          # noqa: S603, argv list, never a shell
                [self.docker_bin, "exec", container, *spec.ready_argv],
                capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=30, shell=False)
            if probe.returncode == 0:
                return
            last = (probe.stderr or probe.stdout).strip()[:400]
            time.sleep(spec.ready_interval_s)

        raise ServiceError(
            f"the service did not become ready within "
            f"{spec.ready_timeout_s:.0f}s. Last probe said: {last or '(nothing)'}\n"
            f"{self._logs(container)}")

    def _is_running(self, container: str) -> bool:
        probe = subprocess.run(              # noqa: S603, argv list, never a shell
            [self.docker_bin, "inspect", "-f", "{{.State.Running}}", container],
            capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=30, shell=False)
        return probe.returncode == 0 and probe.stdout.strip() == "true"

    def _logs(self, container: str, tail: int = 40) -> str:
        probe = subprocess.run(              # noqa: S603, argv list, never a shell
            [self.docker_bin, "logs", "--tail", str(tail), container],
            capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=30, shell=False)
        return (probe.stdout + probe.stderr).strip() or "(the service logged nothing)"

    def _remove_container(self, container: str) -> None:
        self._quiet(["rm", "-f", container])

    def _remove_network(self, network: str) -> None:
        self._quiet(["network", "rm", network])

    def _docker(self, command: list[str], *, what: str) -> str:
        argv = command if command[0] == self.docker_bin else [self.docker_bin, *command]
        try:
            proc = subprocess.run(           # noqa: S603, argv list, never a shell
                argv, capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=120, shell=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ServiceError(f"could not {what}: {exc}") from None
        if proc.returncode != 0:
            raise ServiceError(f"could not {what}: "
                               f"{(proc.stderr or proc.stdout).strip()}")
        return proc.stdout.strip()

    def _quiet(self, command: list[str]) -> None:
        """Teardown, which must never raise over the top of a real failure."""
        try:
            subprocess.run(                  # noqa: S603, argv list, never a shell
                [self.docker_bin, *command],
                capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=60, shell=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            logger.warning("sandbox teardown failed for %s: %s", command, exc)
