"""Sandbox hardening.

These assert the *argv* the runner would hand to Docker, because the hardening
flags are the whole security story: if `--network none` or the `:ro` sample
mount ever silently disappears, an analysis run starts parsing hostile input
with a live network. Docker itself is not exercised here (the integration test
that does is marked `docker`).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from themob.sandbox.runner import (CONTAINER_INPUT, CONTAINER_OUTPUT,
                                   SandboxError, SandboxLimits, SandboxRunner,
                                   _safe_mount_name, with_limits)


class _FakeRunner(SandboxRunner):
    """A runner that records the command instead of executing it."""

    def __init__(self, **kw) -> None:
        super().__init__(**kw)
        self.last_command: list[str] = []
        self._available = True

    def has_image(self, image: str) -> bool:
        return True

    def _execute(self, command, container, limits):    # type: ignore[override]
        from themob.sandbox.runner import SandboxResult
        self.last_command = command
        return SandboxResult(ok=True, exit_code=0, stdout=b"{}", command=command)


@pytest.fixture()
def runner() -> _FakeRunner:
    return _FakeRunner()


def _run(runner: _FakeRunner, tmp_path: Path, **kw) -> list[str]:
    sample = kw.pop("sample", None)
    if sample is None:
        sample = tmp_path / "sample.apk"
        sample.write_bytes(b"PK\x03\x04")
    runner.run("themob/androguard:1", ["analyze"], sample=sample,
               output_dir=tmp_path / "out", **kw)
    return runner.last_command


def test_container_has_no_network(runner: _FakeRunner, tmp_path: Path) -> None:
    cmd = _run(runner, tmp_path)
    assert "--network" in cmd and cmd[cmd.index("--network") + 1] == "none"


def test_sample_is_mounted_read_only(runner: _FakeRunner, tmp_path: Path) -> None:
    cmd = _run(runner, tmp_path)
    mounts = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-v"]
    sample_mount = [m for m in mounts if CONTAINER_INPUT in m]
    assert sample_mount and sample_mount[0].endswith(":ro")


def test_output_is_the_only_writable_mount(runner: _FakeRunner, tmp_path: Path) -> None:
    cmd = _run(runner, tmp_path)
    mounts = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-v"]
    writable = [m for m in mounts if m.endswith(":rw")]
    assert len(writable) == 1 and CONTAINER_OUTPUT in writable[0]


def test_full_hardening_set_is_present(runner: _FakeRunner, tmp_path: Path) -> None:
    cmd = _run(runner, tmp_path)
    joined = " ".join(cmd)
    assert "--read-only" in cmd
    assert "--rm" in cmd
    assert "--cap-drop ALL" in joined
    assert "--security-opt no-new-privileges" in joined
    assert "--user 65534:65534" in joined
    assert "--pids-limit" in cmd
    assert "noexec" in joined                  # the scratch tmpfs
    # Swap must equal memory or the memory ceiling is not a ceiling.
    assert cmd[cmd.index("--memory") + 1] == cmd[cmd.index("--memory-swap") + 1]


def test_no_shell_is_involved(runner: _FakeRunner, tmp_path: Path) -> None:
    cmd = _run(runner, tmp_path)
    assert cmd[0] == "docker"
    assert all(isinstance(part, str) for part in cmd)
    assert not any(part in ("sh", "-c", "bash") for part in cmd[:3])


def test_per_analyzer_limit_overrides(runner: _FakeRunner, tmp_path: Path) -> None:
    cmd = _run(runner, tmp_path, limits=with_limits(runner, memory="6g", cpus=4.0))
    assert cmd[cmd.index("--memory") + 1] == "6g"
    assert cmd[cmd.index("--cpus") + 1] == "4.0"


# ------------------------------------------------------------- input validation

@pytest.mark.parametrize("image", [
    "bad;rm -rf /", "-v/etc:/etc", "", "img$(whoami)", "a" * 300,
])
def test_unsafe_image_references_are_refused(runner: _FakeRunner, image: str) -> None:
    with pytest.raises(SandboxError):
        runner.run(image, ["x"])


def test_invalid_env_name_is_refused(runner: _FakeRunner, tmp_path: Path) -> None:
    sample = tmp_path / "s.apk"
    sample.write_bytes(b"PK")
    with pytest.raises(SandboxError):
        runner.run("themob/androguard:1", ["x"], sample=sample,
                   env={"PATH; rm -rf /": "1"})


@pytest.mark.parametrize("bad", [
    {"cpus": 0}, {"pids": 0}, {"timeout_s": 0},
    {"memory": "2 gigabytes"}, {"memory": "2g; rm -rf /"}, {"tmpfs_size": "-1"},
])
def test_invalid_limits_are_refused(bad: dict) -> None:
    with pytest.raises(SandboxError):
        SandboxLimits(**bad).validate()


def test_missing_sample_is_reported_not_raised(runner: _FakeRunner,
                                               tmp_path: Path) -> None:
    result = runner.run("themob/androguard:1", ["x"], sample=tmp_path / "nope.apk")
    assert not result.ok and "not found" in (result.error or "")


@pytest.mark.parametrize("name,expected", [
    ("app.apk", "app.apk"),
    ("--rm", "rm"),                     # cannot be read as a flag
    ("../../etc/passwd", ".._.._etc_passwd"),
    ("weird name;$(id).apk", "weird_name___id_.apk"),
    ("", "sample"),
])
def test_mount_names_are_sanitised(name: str, expected: str) -> None:
    assert _safe_mount_name(name) == expected


def test_unavailable_docker_is_reported_not_raised(tmp_path: Path) -> None:
    runner = SandboxRunner(docker_bin="definitely-not-a-real-binary")
    assert runner.is_available() is False
    result = runner.run("themob/androguard:1", ["x"])
    assert not result.ok and "Docker is not available" in (result.error or "")


# ------------------------------------------------- docker output is UTF-8

def test_docker_output_is_decoded_as_utf8_not_the_locale(monkeypatch) -> None:
    """A build log with a byte cp1252 cannot map used to kill the reader.

    `text=True` alone decodes with the locale encoding, which on Windows is
    cp1252. The exception was raised inside subprocess's reader thread, so
    stdout and stderr both came back None and the caller failed on
    `None.strip()`, blaming the build for a decoding bug.
    """
    import subprocess

    captured = {}

    def fake_run(argv, **kwargs):
        captured.update(kwargs)
        return subprocess.CompletedProcess(argv, 0, stdout="ok", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    SandboxRunner()._docker(["version"], timeout=5)

    assert captured.get("encoding") == "utf-8"
    assert captured.get("errors") == "replace"


def test_a_stream_that_comes_back_none_does_not_crash_the_caller(
        monkeypatch) -> None:
    """Belt as well as braces: no caller should have to guard these."""
    import subprocess

    def fake_run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 0, stdout=None, stderr=None)

    monkeypatch.setattr(subprocess, "run", fake_run)
    probe = SandboxRunner()._docker(["version"], timeout=5)

    assert probe.stdout == "" and probe.stderr == ""
    # The exact call that raised AttributeError on a real build.
    assert probe.stderr.strip() == ""


def test_building_an_image_survives_undecodable_output(monkeypatch,
                                                       tmp_path) -> None:
    import subprocess

    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")

    def fake_run(argv, **kwargs):
        # What docker actually emitted: bytes that are valid UTF-8 and not
        # valid cp1252. With the fix these decode; without it, nothing does.
        return subprocess.CompletedProcess(
            argv, 0, stdout="pulling \u2588\u2588\u2588 done", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = SandboxRunner().build_image("themob/probe:1", tmp_path)

    assert result.ok
    assert result.stderr == ""
