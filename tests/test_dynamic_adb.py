"""ADB, where the wrong device is not a wrong finding but a wrong phone.

No real device is involved. adb is replaced by a fake that records the argv it
was handed, because what these tests are about is which command themob issues
and which it refuses, and that is decided before anything is plugged in.
"""
from __future__ import annotations

import subprocess

import pytest

from themob.audit.attestation import AuditTrail
from themob.dynamic import gate
from themob.dynamic.adb import _REFUSED, Adb, AdbError, Device, describe
from themob.dynamic.gate import (DeviceAttestation, ExecutionAttestation,
                                 ExecutionNotAuthorized)
from themob.model.enums import Platform
from themob.storage.repositories import Project, Repositories

SERIAL = "emulator-5554"
OTHER = "R58M12345XY"


@pytest.fixture()
def project(repos: Repositories) -> Project:
    stored = repos.projects.create(Project(
        name="Example Shop", target_platform=Platform.ANDROID,
        source_path="input/shop.apk", source_sha256="a" * 64))
    return repos.projects.get(stored.id)


@pytest.fixture()
def authorized(repos: Repositories, project: Project) -> Project:
    gate.authorize(ExecutionAttestation(
        operator="tester@lab", engagement_ref="ENG-42",
        device=DeviceAttestation(identifier=SERIAL, dedicated_test_device=True,
                                 is_emulator=True),
        traffic_authorized=True, interception_scope=[".example.com"]),
        project.id, AuditTrail(repos.audit))
    return project


class _FakeAdb(Adb):
    """Records every argv, and answers whatever the test scripted."""

    def __init__(self, responses=None, connected=(SERIAL, "device")) -> None:
        super().__init__()
        self.calls: list[list[str]] = []
        self.responses = responses or {}
        self._connected = connected

    def _run(self, args, *, serial=None, timeout=None):
        command = ([self.adb_bin] + (["-s", serial] if serial else [])
                   + [str(a) for a in args])
        # Route through the real guard so refusals are still exercised.
        if args and args[0] in _REFUSED:
            return super()._run(args, serial=serial, timeout=timeout)
        self.calls.append(command)

        key = " ".join(str(a) for a in args)
        for prefix, value in self.responses.items():
            if key.startswith(prefix):
                out, code = value if isinstance(value, tuple) else (value, 0)
                return subprocess.CompletedProcess(command, code, out, "")
        if args[0] == "devices":
            serial_, state = self._connected
            body = f"List of devices attached\n{serial_}\t{state}\n"
            return subprocess.CompletedProcess(command, 0, body, "")
        return subprocess.CompletedProcess(command, 0, "", "")


# ------------------------------------------------------------------ discovery

def test_a_device_that_is_not_ready_is_still_reported() -> None:
    """"No devices found" sends the operator looking in the wrong place."""
    adb = _FakeAdb(connected=(SERIAL, "unauthorized"))
    found = adb.devices(with_properties=False)

    assert [d.serial for d in found] == [SERIAL]
    assert found[0].state == "unauthorized"
    assert not found[0].usable


def test_a_device_with_an_odd_serial_is_ignored() -> None:
    """A serial comes off a USB descriptor and reaches argv."""
    adb = _FakeAdb(responses={
        "devices": "List of devices attached\n; rm -rf /\tdevice\n"})
    assert adb.devices(with_properties=False) == []


def test_properties_are_read_one_at_a_time_by_name() -> None:
    adb = _FakeAdb(responses={"shell getprop ro.product.model": "Pixel 4a"})
    values = adb.properties(SERIAL)

    assert values["ro.product.model"] == "Pixel 4a"
    for call in adb.calls:
        if "getprop" in call:
            assert call[:3] == ["adb", "-s", SERIAL]


def test_an_emulator_is_recognised_and_is_not_a_daily_driver() -> None:
    emulator = Device(serial="emulator-5554", state="device",
                      properties={"ro.build.type": "user", "ro.secure": "1"})
    assert emulator.is_emulator
    assert not emulator.looks_like_a_daily_driver


def test_a_stock_user_build_looks_like_somebodys_phone() -> None:
    """Advisory only, and never a substitute for the attestation."""
    phone = Device(serial=OTHER, state="device",
                   properties={"ro.build.type": "user", "ro.secure": "1"})
    assert phone.looks_like_a_daily_driver

    lab = Device(serial=OTHER, state="device",
                 properties={"ro.build.type": "userdebug", "ro.secure": "0"})
    assert not lab.looks_like_a_daily_driver


# ------------------------------------------------------------------ the gate

def test_nothing_touches_a_device_without_an_execution_attestation(
        repos, project) -> None:
    adb = _FakeAdb()
    with pytest.raises(ExecutionNotAuthorized):
        adb.bind(repos, project.id)


def test_only_the_attested_serial_is_used(repos, authorized) -> None:
    adb = _FakeAdb()
    assert adb.bind(repos, authorized.id) == SERIAL


def test_another_connected_device_is_never_substituted(repos,
                                                       authorized) -> None:
    """A lab with three phones in it is normal. Picking wrong is not recoverable."""
    adb = _FakeAdb(connected=(OTHER, "device"))

    with pytest.raises(ExecutionNotAuthorized, match="not connected"):
        adb.bind(repos, authorized.id)


def test_an_unauthorized_device_says_what_to_do_about_it(repos,
                                                         authorized) -> None:
    adb = _FakeAdb(connected=(SERIAL, "unauthorized"))
    with pytest.raises(AdbError, match="debugging prompt"):
        adb.bind(repos, authorized.id)


# --------------------------------------------------------------- destructive

def test_install_refuses_without_the_gate(repos, project, tmp_path) -> None:
    apk = tmp_path / "shop.apk"
    apk.write_bytes(b"PK\x03\x04")

    with pytest.raises(ExecutionNotAuthorized):
        _FakeAdb().install(repos, project.id, apk)


def test_install_targets_the_attested_serial(repos, authorized,
                                             tmp_path) -> None:
    apk = tmp_path / "shop.apk"
    apk.write_bytes(b"PK\x03\x04")
    adb = _FakeAdb(responses={"install": "Success"})

    adb.install(repos, authorized.id, apk)
    install = next(c for c in adb.calls if "install" in c)
    assert install[:3] == ["adb", "-s", SERIAL]


def test_a_failed_install_that_exits_zero_is_still_a_failure(
        repos, authorized, tmp_path) -> None:
    """adb prints Failure and exits 0, which is how a broken install passes."""
    apk = tmp_path / "shop.apk"
    apk.write_bytes(b"PK\x03\x04")
    adb = _FakeAdb(responses={"install": ("Failure [INSTALL_FAILED_OLDER_SDK]", 0)})

    with pytest.raises(AdbError, match="INSTALL_FAILED_OLDER_SDK"):
        adb.install(repos, authorized.id, apk)


def test_installing_a_file_that_is_not_there_is_refused(repos,
                                                        authorized) -> None:
    with pytest.raises(AdbError, match="no such package file"):
        _FakeAdb().install(repos, authorized.id, "does-not-exist.apk")


def test_a_package_name_from_a_hostile_apk_is_validated(repos,
                                                        authorized) -> None:
    adb = _FakeAdb()
    for bad in ("com.example; rm -rf /", "../../etc/passwd", "no-dots",
                "", "com..example"):
        with pytest.raises(AdbError, match="invalid package name"):
            adb.uninstall(repos, authorized.id, bad)


# ------------------------------------------------------------ no escalation

def test_root_and_friends_are_refused_by_name() -> None:
    adb = Adb()
    for verb in ("root", "unroot", "remount", "disable-verity", "reboot",
                 "tcpip", "sideload"):
        with pytest.raises(AdbError, match="does not issue"):
            adb._run([verb], serial=SERIAL)


def test_no_call_ever_goes_through_a_shell(repos, authorized,
                                           tmp_path) -> None:
    apk = tmp_path / "shop.apk"
    apk.write_bytes(b"PK\x03\x04")
    adb = _FakeAdb(responses={"install": "Success"})

    adb.install(repos, authorized.id, apk)
    adb.is_installed(repos, authorized.id, "com.example.shop")

    for call in adb.calls:
        assert isinstance(call, list), "argv, never a string"
        assert all(isinstance(part, str) for part in call)


def test_a_missing_adb_says_how_to_get_one() -> None:
    adb = Adb(adb_bin="definitely-not-a-real-binary")
    assert not adb.is_available()
    with pytest.raises(AdbError, match="platform tools"):
        adb._run(["devices"], serial=None)


# ------------------------------------------------------------------ recording

def test_a_device_is_described_for_the_record() -> None:
    """A finding has to be arguable a year later, so say what ran it."""
    device = Device(serial=SERIAL, state="device", properties={
        "ro.product.manufacturer": "Google", "ro.product.model": "sdk_gphone64",
        "ro.build.version.release": "14", "ro.build.version.sdk": "34",
        "ro.build.type": "userdebug"})
    record = describe(device)

    assert record["serial"] == SERIAL
    assert record["android"] == "14"
    assert record["is_emulator"] is True
    assert "Google sdk_gphone64" in device.label
