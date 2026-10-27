"""Service mode: the one place a container is allowed a network.

Phase 1 runs every worker with `--network none` and that is themob's central
claim. MobSF is a server, so it cannot. These tests are about the size of the
hole: two containers may talk to each other, and neither may reach the
internet. The container tests are marked `docker` and prove it against a live
daemon rather than against the argv.
"""
from __future__ import annotations

import pytest

from themob.sandbox.runner import SandboxError, SandboxLimits, SandboxRunner
from themob.sandbox.service import (SERVICE_HOST, SandboxService, ServiceError,
                                    ServiceHandle, ServiceSpec)


# ------------------------------------------------------------------ argv only

def test_every_worker_still_runs_with_no_network() -> None:
    """The default must stay `none`, or the invariant erodes by omission."""
    runner = SandboxRunner()
    flags = runner._hardening_flags(runner.limits)
    assert flags[:2] == ["--network", "none"]


def test_a_network_name_reaches_the_flag(monkeypatch) -> None:
    runner = SandboxRunner()
    flags = runner._hardening_flags(runner.limits, "themob-net-abc123")
    assert flags[:2] == ["--network", "themob-net-abc123"]


def test_an_unsafe_network_name_is_refused() -> None:
    """It decides whether the container has a network at all."""
    runner = SandboxRunner()
    for bad in ("; rm -rf /", "--privileged", "net work", "", "a" * 200):
        with pytest.raises(SandboxError, match="invalid network name"):
            runner.run("themob/androguard:1", [], network=bad)


def test_joining_a_network_keeps_every_other_guarantee() -> None:
    """A network is the only thing that changes; hardening is not traded for it."""
    runner = SandboxRunner()
    flags = runner._hardening_flags(runner.limits, "themob-net-abc123")
    for expected in ("--read-only", "--cap-drop", "no-new-privileges",
                     "--pids-limit", "--memory-swap"):
        assert expected in flags, expected
    assert "65534:65534" in flags


# -------------------------------------------------------------------- the spec

def test_a_spec_refuses_what_it_cannot_run_safely() -> None:
    for bad in (
        ServiceSpec(image="themob/x:1", port=0),
        ServiceSpec(image="themob/x:1", port=99999),
        ServiceSpec(image="themob/x:1", port=8000, alias="not an alias"),
        ServiceSpec(image="themob/x:1", port=8000, ready_timeout_s=0),
        ServiceSpec(image="themob/x:1", port=8000, writable_paths=["relative"]),
        ServiceSpec(image="themob/x:1", port=8000, writable_paths=["/a/../b"]),
    ):
        with pytest.raises(ServiceError):
            bad.validate()


def test_a_handle_says_where_the_client_should_talk() -> None:
    handle = ServiceHandle(network="themob-net-1", host=SERVICE_HOST, port=8000,
                           container="themob-svc-1")
    assert handle.url == "http://service:8000"


def test_a_missing_daemon_is_reported_before_anything_is_created(
        monkeypatch) -> None:
    monkeypatch.setattr(SandboxRunner, "is_available", lambda self: False)
    service = SandboxService()
    with pytest.raises(ServiceError, match="Docker is not available"):
        with service.running(ServiceSpec(image="themob/x:1", port=8000)):
            pass


def test_a_missing_image_names_the_build_command(monkeypatch) -> None:
    monkeypatch.setattr(SandboxRunner, "is_available", lambda self: True)
    monkeypatch.setattr(SandboxRunner, "has_image", lambda self, image: False)
    service = SandboxService()
    with pytest.raises(ServiceError, match="sandbox.build"):
        with service.running(ServiceSpec(image="themob/x:1", port=8000)):
            pass


def test_teardown_runs_even_when_the_body_raises(monkeypatch) -> None:
    """A leaked container holds a copy of someone's app."""
    monkeypatch.setattr(SandboxRunner, "is_available", lambda self: True)
    monkeypatch.setattr(SandboxRunner, "has_image", lambda self, image: True)

    service = SandboxService()
    removed = []
    monkeypatch.setattr(service, "_create_network", lambda name: None)
    monkeypatch.setattr(service, "_start", lambda *a: None)
    monkeypatch.setattr(service, "_await_ready", lambda *a: None)
    monkeypatch.setattr(service, "_remove_container",
                        lambda c: removed.append(("container", c)))
    monkeypatch.setattr(service, "_remove_network",
                        lambda n: removed.append(("network", n)))

    with pytest.raises(RuntimeError, match="the adapter blew up"):
        with service.running(ServiceSpec(image="themob/x:1", port=8000)):
            raise RuntimeError("the adapter blew up")

    assert [kind for kind, _ in removed] == ["container", "network"]


def test_teardown_runs_when_the_service_never_becomes_ready(monkeypatch) -> None:
    monkeypatch.setattr(SandboxRunner, "is_available", lambda self: True)
    monkeypatch.setattr(SandboxRunner, "has_image", lambda self, image: True)

    service = SandboxService()
    removed = []
    monkeypatch.setattr(service, "_create_network", lambda name: None)
    monkeypatch.setattr(service, "_start", lambda *a: None)

    def never(*_a):
        raise ServiceError("the service did not become ready")

    monkeypatch.setattr(service, "_await_ready", never)
    monkeypatch.setattr(service, "_remove_container",
                        lambda c: removed.append(c))
    monkeypatch.setattr(service, "_remove_network", lambda n: removed.append(n))

    with pytest.raises(ServiceError):
        with service.running(ServiceSpec(image="themob/x:1", port=8000)):
            pass
    assert len(removed) == 2, "the half-started service was left behind"


# --------------------------------------------------------- against a real daemon

pytestmark_docker = pytest.mark.docker

_PROBE_IMAGE = "themob/androguard:1"


@pytest.fixture(scope="module")
def probe_service():
    """A trivial HTTP server standing in for MobSF.

    Deliberately not MobSF: what is under test is the network shape, and a
    2GB image would make these tests something nobody runs.
    """
    runner = SandboxRunner()
    if not runner.is_available() or not runner.has_image(_PROBE_IMAGE):
        pytest.skip("docker or the probe image is unavailable")

    service = SandboxService(runner)
    spec = ServiceSpec(
        image=_PROBE_IMAGE,
        port=8000,
        args=["-m", "http.server", "8000", "--bind", "0.0.0.0"],
        ready_argv=["python", "-c",
                    "import urllib.request;"
                    "urllib.request.urlopen('http://127.0.0.1:8000/', timeout=3)"],
        ready_timeout_s=60.0,
        ready_interval_s=1.0,
        # The image's entrypoint is its analyzer, so the service replaces it.
        entrypoint="python",
    )
    with service.running(spec) as handle:
        yield service, handle


@pytest.mark.docker
def test_a_client_container_reaches_the_service(probe_service) -> None:
    service, handle = probe_service
    result = service.client_run(
        handle, _PROBE_IMAGE,
        ["-c", f"import urllib.request;"
               f"r=urllib.request.urlopen('{handle.url}/', timeout=8);"
               f"print('http', r.status)"],
        entrypoint="python")
    assert result.ok, result.stderr or result.error
    assert "http 200" in result.stdout_text()


@pytest.mark.docker
def test_the_service_network_has_no_route_out(probe_service) -> None:
    """The whole justification for the hole: two containers, no internet.

    Asserted against a live container rather than against the argv, because
    "--internal" meaning what the documentation says it means is exactly the
    kind of thing that should not be taken on trust.
    """
    service, handle = probe_service
    result = service.client_run(
        handle, _PROBE_IMAGE,
        ["-c", "import socket; socket.setdefaulttimeout(6)\n"
               "try:\n"
               "    socket.create_connection(('1.1.1.1', 443))\n"
               "    print('REACHED')\n"
               "except OSError:\n"
               "    print('blocked')"],
        entrypoint="python")
    assert result.ok, result.stderr or result.error
    assert "blocked" in result.stdout_text()
    assert "REACHED" not in result.stdout_text()


@pytest.mark.docker
def test_dns_does_not_resolve_off_the_network(probe_service) -> None:
    """A name that only exists outside must not resolve from inside."""
    service, handle = probe_service
    result = service.client_run(
        handle, _PROBE_IMAGE,
        ["-c", "import socket\n"
               "try:\n"
               "    print('RESOLVED', socket.gethostbyname('example.com'))\n"
               "except OSError:\n"
               "    print('no resolution')"],
        entrypoint="python")
    assert result.ok, result.stderr or result.error
    assert "RESOLVED" not in result.stdout_text()


@pytest.mark.docker
def test_a_client_on_the_service_network_is_still_hardened(probe_service) -> None:
    """Joining a network buys a network, not root."""
    service, handle = probe_service
    result = service.client_run(
        handle, _PROBE_IMAGE,
        ["-c", "import os\n"
               "print('uid', os.getuid())\n"
               "try:\n"
               "    open('/proof', 'w').write('x'); print('ROOT FS WRITABLE')\n"
               "except OSError:\n"
               "    print('root fs read-only')"],
        entrypoint="python")
    assert result.ok, result.stderr or result.error
    text = result.stdout_text()
    assert "uid 65534" in text
    assert "root fs read-only" in text
    assert "ROOT FS WRITABLE" not in text


@pytest.mark.docker
def test_the_service_and_its_network_are_gone_afterwards() -> None:
    """Nothing is left holding a copy of a sample."""
    import subprocess

    runner = SandboxRunner()
    if not runner.is_available() or not runner.has_image(_PROBE_IMAGE):
        pytest.skip("docker or the probe image is unavailable")

    service = SandboxService(runner)
    spec = ServiceSpec(image=_PROBE_IMAGE, port=8000, entrypoint="python",
                       args=["-m", "http.server", "8000", "--bind", "0.0.0.0"],
                       ready_argv=["python", "-c",
                                   "import urllib.request;"
                                   "urllib.request.urlopen("
                                   "'http://127.0.0.1:8000/', timeout=3)"],
                       ready_timeout_s=60.0, ready_interval_s=1.0)
    with service.running(spec) as handle:
        container, network = handle.container, handle.network

    for kind, name in (("container", container), ("network", network)):
        listed = subprocess.run(
            ["docker", kind, "ls", "--format", "{{.Name}}"] if kind == "network"
            else ["docker", "ps", "-a", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=60)
        assert name not in listed.stdout, f"the {kind} was left behind: {name}"
