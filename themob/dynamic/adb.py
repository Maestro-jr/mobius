"""ADB: talking to the one device the operator attested, and to no other.

ADB is a shell on a phone. It installs packages, reads storage, and forwards
ports, and none of that is undoable by re-running an analyzer. So this module is
narrower than the tool it wraps, on purpose:

**Every call names a serial, and the serial must be the attested one.** The gate
records which device an operator said they were allowed to use. A lab with three
phones plugged in is normal, and "themob picked the wrong one" is a sentence
nobody should ever have to say. There is no default device here: an unattested
serial is refused even when it is the only one connected.

**Nothing runs through a shell.** Every call is an argv list, the serial is
validated against a pattern, and a package name is validated before it can reach
``adb shell``. A device serial arrives from a USB descriptor and a package name
from a hostile APK, so neither is trusted with quoting.

**No privilege escalation.** ``adb root`` and ``adb disable-verity`` are not
here and are refused by name if somebody passes them through. themob asks a
device for what it will give an ordinary client, because a rooted device answers
questions about a rooted device rather than about the app.

**Install is the one destructive verb**, so it is the one that re-checks the
gate rather than trusting a caller to have done it.
"""
from __future__ import annotations

import logging
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .gate import ExecutionNotAuthorized, require_execution

logger = logging.getLogger(__name__)

_DEFAULT_ADB = "adb"

# A serial as adb prints it: alphanumerics, dots, colons and dashes. Covers a
# USB serial, "emulator-5554", and a "host:port" network device.
_SERIAL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

# A Java package name. Validated because it reaches argv and it comes out of
# somebody else's APK.
_PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$")

# Subcommands this module will not issue, whatever a caller asks for. Listed
# rather than merely unimplemented, so adding one is a deliberate act.
_REFUSED = frozenset({
    "root", "unroot", "remount", "disable-verity", "enable-verity",
    "sideload", "reboot", "bugreport", "restore", "tcpip",
})

# Properties worth having on the record: what the device was, so a finding can
# be argued with a year later.
_PROPERTIES = (
    "ro.product.manufacturer", "ro.product.model", "ro.build.version.release",
    "ro.build.version.sdk", "ro.build.type", "ro.build.tags",
    "ro.debuggable", "ro.secure",
)


class AdbError(RuntimeError):
    """adb was unusable, or was asked for something this module will not do."""


@dataclass(frozen=True)
class Device:
    """One device as adb reports it."""

    serial: str
    state: str = ""                       # device / unauthorized / offline
    properties: dict[str, str] = field(default_factory=dict)

    @property
    def usable(self) -> bool:
        return self.state == "device"

    @property
    def is_emulator(self) -> bool:
        return self.serial.startswith("emulator-")

    @property
    def label(self) -> str:
        maker = self.properties.get("ro.product.manufacturer", "").strip()
        model = self.properties.get("ro.product.model", "").strip()
        name = " ".join(x for x in (maker, model) if x)
        return f"{name} ({self.serial})" if name else self.serial

    @property
    def looks_like_a_daily_driver(self) -> bool:
        """A weak hint that this is somebody's actual phone.

        A user build with verified boot intact is what a shop sells; a test
        device is usually userdebug, or an emulator. This is advisory only and
        is never a substitute for the gate's attestation: it exists so the UI
        can say "are you sure" rather than to make the decision.
        """
        if self.is_emulator:
            return False
        build_type = self.properties.get("ro.build.type", "")
        secure = self.properties.get("ro.secure", "")
        return build_type == "user" and secure == "1"


def _validate_serial(serial: str) -> str:
    serial = (serial or "").strip()
    if not _SERIAL_RE.match(serial):
        raise AdbError(f"invalid device serial: {serial!r}")
    return serial


def _validate_package(package: str) -> str:
    package = (package or "").strip()
    if not _PACKAGE_RE.match(package):
        raise AdbError(f"invalid package name: {package!r}")
    return package


class Adb:
    """A deliberately small ADB client, bound to one attested serial."""

    def __init__(self, adb_bin: str = _DEFAULT_ADB,
                 timeout: float = 120.0) -> None:
        self.adb_bin = adb_bin
        self.timeout = timeout

    # ------------------------------------------------------------- availability

    def is_available(self) -> bool:
        if shutil.which(self.adb_bin) is None:
            return False
        return self._run(["version"], serial=None).returncode == 0

    def version(self) -> str:
        probe = self._run(["version"], serial=None)
        first = (probe.stdout or "").strip().splitlines()
        return first[0] if first else ""

    # ------------------------------------------------------------- discovery

    def devices(self, *, with_properties: bool = True) -> list[Device]:
        """Every device adb can see, in whatever state it is in.

        Unusable devices are returned rather than filtered out. "No devices
        found" when a phone is plugged in but unauthorized sends the operator
        looking in the wrong place; "unauthorized" tells them to accept the
        prompt on the screen in front of them.
        """
        probe = self._run(["devices", "-l"], serial=None)
        if probe.returncode != 0:
            raise AdbError(f"adb devices failed: {(probe.stderr or '').strip()}")

        found: list[Device] = []
        for line in (probe.stdout or "").splitlines()[1:]:
            line = line.strip()
            if not line or line.startswith("*"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            serial, state = parts[0], parts[1]
            if not _SERIAL_RE.match(serial):
                logger.warning("ignoring a device with an odd serial: %r", serial)
                continue
            device = Device(serial=serial, state=state)
            if with_properties and device.usable:
                device = Device(serial=serial, state=state,
                                properties=self.properties(serial))
            found.append(device)
        return found

    def properties(self, serial: str) -> dict[str, str]:
        """The handful of properties worth putting on the record."""
        serial = _validate_serial(serial)
        values: dict[str, str] = {}
        for name in _PROPERTIES:
            probe = self._run(["shell", "getprop", name], serial=serial)
            if probe.returncode == 0:
                value = (probe.stdout or "").strip()
                if value:
                    values[name] = value[:200]
        return values

    def get(self, serial: str) -> Device:
        serial = _validate_serial(serial)
        for device in self.devices(with_properties=False):
            if device.serial == serial:
                return Device(serial=serial, state=device.state,
                              properties=self.properties(serial)
                              if device.usable else {})
        raise AdbError(f"no device with serial {serial!r} is connected")

    # ------------------------------------------------------------------ gated

    def bind(self, repos, project_id: str) -> str:
        """The serial this project is allowed to touch, or an explanation.

        Called before anything that reaches a device. Returns the serial rather
        than a boolean so a caller cannot forget to use the attested one.
        """
        detail = require_execution(repos, project_id)
        serial = _validate_serial(str(detail.get("device_id") or ""))

        connected = {d.serial: d for d in self.devices(with_properties=False)}
        device = connected.get(serial)
        if device is None:
            raise ExecutionNotAuthorized(
                f"the attested device {serial!r} is not connected. themob will "
                "not fall back to another one: a lab with three phones in it "
                "is normal, and picking the wrong one is not recoverable")
        if not device.usable:
            raise AdbError(
                f"device {serial!r} is {device.state!r}. If it says "
                "'unauthorized', accept the debugging prompt on the device")
        return serial

    def install(self, repos, project_id: str, apk: str | Path, *,
                reinstall: bool = False) -> str:
        """Install the sample on the attested device.

        The one destructive verb here, so it re-checks the gate itself rather
        than trusting a caller to have done it.
        """
        serial = self.bind(repos, project_id)
        path = Path(apk).expanduser().resolve()
        if not path.is_file():
            raise AdbError(f"no such package file: {path}")

        args = ["install"]
        if reinstall:
            args.append("-r")
        args.append(str(path))

        probe = self._run(args, serial=serial, timeout=max(self.timeout, 300.0))
        output = ((probe.stdout or "") + (probe.stderr or "")).strip()
        # adb install exits 0 while printing Failure, which is how a failed
        # install gets mistaken for a working one.
        if probe.returncode != 0 or "Failure" in output:
            raise AdbError(f"install failed: {output[:500] or 'no output'}")
        return output

    def uninstall(self, repos, project_id: str, package: str) -> str:
        serial = self.bind(repos, project_id)
        package = _validate_package(package)
        probe = self._run(["uninstall", package], serial=serial)
        output = ((probe.stdout or "") + (probe.stderr or "")).strip()
        if probe.returncode != 0 or "Failure" in output:
            raise AdbError(f"uninstall failed: {output[:500] or 'no output'}")
        return output

    def is_installed(self, repos, project_id: str, package: str) -> bool:
        serial = self.bind(repos, project_id)
        package = _validate_package(package)
        probe = self._run(["shell", "pm", "list", "packages", package],
                          serial=serial)
        wanted = f"package:{package}"
        return any(line.strip() == wanted
                   for line in (probe.stdout or "").splitlines())

    # --------------------------------------------------------------- internals

    def _run(self, args: list[str], *, serial: str | None,
             timeout: float | None = None) -> subprocess.CompletedProcess:
        """One adb invocation. argv only, never a shell, never a refused verb."""
        if not args:
            raise AdbError("no adb subcommand given")
        if args[0] in _REFUSED:
            raise AdbError(
                f"themob does not issue 'adb {args[0]}'. It changes the device "
                "rather than observing it, and a rooted phone answers questions "
                "about a rooted phone rather than about the app")

        command = [self.adb_bin]
        if serial is not None:
            command += ["-s", _validate_serial(serial)]
        command += [str(a) for a in args]

        try:
            return subprocess.run(          # noqa: S603, argv list, never a shell
                command, capture_output=True, text=True,
                encoding="utf-8", errors="replace",
                timeout=timeout or self.timeout,
                stdin=subprocess.DEVNULL, shell=False, check=False)
        except FileNotFoundError:
            raise AdbError(
                f"{self.adb_bin!r} is not on PATH. Install the Android platform "
                "tools, or set the adb path in settings") from None
        except (OSError, subprocess.TimeoutExpired) as exc:
            return subprocess.CompletedProcess(command, returncode=124,
                                               stdout="", stderr=str(exc))


def describe(device: Device) -> dict[str, Any]:
    """What goes in the audit record when a device is used."""
    return {
        "serial": device.serial,
        "state": device.state,
        "model": device.properties.get("ro.product.model", ""),
        "android": device.properties.get("ro.build.version.release", ""),
        "sdk": device.properties.get("ro.build.version.sdk", ""),
        "build_type": device.properties.get("ro.build.type", ""),
        "is_emulator": device.is_emulator,
    }
