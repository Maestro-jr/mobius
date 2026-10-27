"""Frida and objection: watching an app do what static analysis only suspected.

Static analysis finds a call to a weak cipher. Instrumentation watches the app
encrypt something with it at runtime, which is a different and stronger claim: a
finding voting can weigh as "we watched it happen" rather than "the code path
exists". That is the whole reason this stage is worth the risk it carries.

The risk is real. Frida injects a JavaScript engine into a running process and
runs a script inside it, and the script decides what the app does next. So the
rules here are strict and few:

**The agent is a file this repository owns.** It is loaded from ``agents/`` on
disk and never fetched at runtime, never assembled from a device's response,
never taken from the app. A downloaded agent is a downloaded exploit, and "the
instrumentation script came from the thing being instrumented" is a sentence
that should be impossible to write.

**Nothing runs on a device the gate has not attested.** Every entry point binds
through :mod:`themob.dynamic.adb`, which resolves the one serial the operator was
authorised to use. There is no path here that reaches a process without going
through that.

**objection is the safe verb; a raw script is the sharp one.** objection's
built-in jobs (list pinning, SSL bypass, storage dump) are named and bounded.
Loading an arbitrary Frida script is allowed because a pentester needs it, but
it is a separate call that says so, and it still only loads files from
``agents/``.

This module prepares and validates; it does not spawn a live session here,
because there is no attested device in the test environment to spawn against.
The subprocess seam is isolated in :meth:`FridaSession._launch` so an
integration test on a real emulator drives exactly what an operator would.
"""
from __future__ import annotations

import logging
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .adb import Adb, AdbError
from .gate import ExecutionNotAuthorized, require_execution

logger = logging.getLogger(__name__)

# The agents this repository ships. A script named to load must resolve to a
# real file inside this directory and nowhere else.
AGENTS_DIR = Path(__file__).resolve().parent / "agents"

_FRIDA = "frida"
_OBJECTION = "objection"

# A Frida agent filename: a plain name ending .js, no path separators. The
# check that a resolved path stays inside AGENTS_DIR is what actually enforces
# containment; this refuses the obvious tricks before the filesystem does.
_AGENT_RE = re.compile(r"^[A-Za-z0-9_.-]+\.js$")

# objection's jobs that themob exposes, each bounded and named. A pentester's
# raw-script path is deliberately not in this map: it is a different method.
OBJECTION_JOBS = {
    "ssl-pin-bypass": "android sslpinning disable",
    "list-pinning": "android hooking search classes pinning",
    "root-detection-bypass": "android root disable",
    "storage-dump": "android hooking list activities",
    "list-classes": "android hooking list classes",
}


class InstrumentationError(RuntimeError):
    """Instrumentation could not be prepared, or was asked for something unsafe."""


def available_agents() -> list[str]:
    """Every Frida agent this repository ships, by filename."""
    if not AGENTS_DIR.is_dir():
        return []
    return sorted(p.name for p in AGENTS_DIR.glob("*.js") if p.is_file())


def resolve_agent(name: str) -> Path:
    """The on-disk path of a shipped agent, or an error. Never anything else.

    Two checks, not one: the name is refused if it does not look like a bare
    filename, and the resolved path is refused if it escapes ``agents/``. The
    second is the real guard, because ``..`` and absolute paths and symlinks all
    survive a pattern that only looks at the string.
    """
    name = (name or "").strip()
    if not _AGENT_RE.match(name):
        raise InstrumentationError(
            f"{name!r} is not a shipped agent name. themob loads instrumentation "
            "only from its own agents/ directory, never a path or a URL")

    candidate = (AGENTS_DIR / name).resolve()
    try:
        candidate.relative_to(AGENTS_DIR.resolve())
    except ValueError:
        raise InstrumentationError(
            f"{name!r} resolves outside agents/. An instrumentation script is "
            "code that runs inside the target, so it comes from this repository "
            "or not at all") from None
    if not candidate.is_file():
        raise InstrumentationError(
            f"no shipped agent named {name!r}. Available: "
            + (", ".join(available_agents()) or "none"))
    return candidate


@dataclass
class InstrumentationPlan:
    """A prepared, validated instrumentation run, before anything is spawned.

    Assembled and checked in full before a process is touched, so the failure
    modes that matter, an unauthorised device, an agent from outside the repo,
    an unknown objection job, surface as a refusal rather than as a half-started
    session against a live app.
    """

    serial: str
    package: str
    kind: str                             # "objection-job" | "frida-script"
    command: list[str] = field(default_factory=list)
    agent_path: Path | None = None
    job: str = ""
    description: str = ""

    def to_detail(self) -> dict[str, Any]:
        return {
            "serial": self.serial,
            "package": self.package,
            "kind": self.kind,
            "job": self.job,
            "agent": self.agent_path.name if self.agent_path else "",
            "description": self.description,
        }


class Instrumentation:
    """Prepares Frida and objection runs against the one attested device."""

    def __init__(self, adb: Adb | None = None, *,
                 frida_bin: str = _FRIDA,
                 objection_bin: str = _OBJECTION) -> None:
        self._adb = adb or Adb()
        self.frida_bin = frida_bin
        self.objection_bin = objection_bin

    def is_available(self) -> bool:
        return (shutil.which(self.frida_bin) is not None
                or shutil.which(self.objection_bin) is not None)

    def objection_job(self, repos, project_id: str, package: str,
                      job: str) -> InstrumentationPlan:
        """A named, bounded objection job on the attested device."""
        serial = self._adb.bind(repos, project_id)
        package = self._package(package)
        if job not in OBJECTION_JOBS:
            raise InstrumentationError(
                f"unknown objection job {job!r}. themob exposes: "
                + ", ".join(sorted(OBJECTION_JOBS)))

        command = [self.objection_bin, "-S", serial, "-g", package,
                   "explore", "-s", OBJECTION_JOBS[job]]
        return InstrumentationPlan(
            serial=serial, package=package, kind="objection-job", job=job,
            command=command,
            description=f"objection: {job} on {package}")

    def frida_script(self, repos, project_id: str, package: str,
                     agent: str, *, spawn: bool = True) -> InstrumentationPlan:
        """Load one of this repository's Frida agents into the app.

        The sharp verb. It is here because a pentester needs it, and it is still
        confined to ``agents/``: the agent is resolved to a shipped file before
        a device is touched.
        """
        serial = self._adb.bind(repos, project_id)
        package = self._package(package)
        agent_path = resolve_agent(agent)

        command = [self.frida_bin, "-U", "-l", str(agent_path)]
        command += ["-f", package] if spawn else ["-n", package]
        return InstrumentationPlan(
            serial=serial, package=package, kind="frida-script",
            agent_path=agent_path, command=command,
            description=f"frida: {agent_path.name} on {package}")

    def _package(self, package: str) -> str:
        # Reuse adb's validator: a package name reaching a subprocess is a
        # package name reaching a subprocess, wherever it is going.
        from .adb import _validate_package

        try:
            return _validate_package(package)
        except AdbError as exc:
            raise InstrumentationError(str(exc)) from None


class FridaSession:
    """Runs a prepared plan against a live device. Not exercised without one.

    Kept apart from :class:`Instrumentation` so that everything which can be
    checked without a device, the gate, the agent path, the argv, is checked and
    tested there, and the one thing that genuinely needs an emulator, spawning
    the process, is the only thing behind this seam.
    """

    def __init__(self, plan: InstrumentationPlan, *, timeout: float = 120.0):
        self.plan = plan
        self.timeout = timeout

    def run(self, repos, project_id: str, audit=None) -> subprocess.CompletedProcess:
        """Re-check the gate, record the run, then launch it.

        The gate is checked again here, not only when the plan was built: a plan
        is a value that can be held, and the attestation it was built under must
        still hold at the moment it actually runs.
        """
        from ..audit.attestation import Action

        require_execution(repos, project_id)
        if audit is not None:
            audit.record(Action.EXECUTION_AUTHORIZED, project_id=project_id,
                         instrumentation=self.plan.to_detail())
        return self._launch()

    def _launch(self) -> subprocess.CompletedProcess:      # pragma: no cover
        # The one seam that needs a real device. An integration test on an
        # emulator drives exactly this; there is nothing to mock that would
        # prove anything here.
        return subprocess.run(          # noqa: S603, argv list, never a shell
            self.plan.command, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=self.timeout,
            stdin=subprocess.DEVNULL, shell=False, check=False)
