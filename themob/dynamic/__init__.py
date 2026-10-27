"""Dynamic analysis: the phase where themob runs the app instead of reading it.

Everything here sits behind :mod:`themob.dynamic.gate`. Static analysis needs
one attestation; execution needs three more, because a package that runs has
victims a package that is read does not.
"""
from __future__ import annotations

from .adb import Adb, AdbError, Device
from .gate import (ACTION_EXECUTION_AUTHORIZED, DeviceAttestation,
                   ExecutionAttestation, ExecutionNotAuthorized, authorize,
                   host_in_scope, require_execution)
from .capture import (CaptureError, CapturePlan, CaptureResult, Flow,
                      delegated_capture, mitmproxy_capture, read_capture)
from .findings import (Observation, from_capture, from_frida,
                       parse_frida_events)
from .instrument import (Instrumentation, InstrumentationError,
                         InstrumentationPlan, OBJECTION_JOBS, available_agents,
                         resolve_agent)

__all__ = [
    "ACTION_EXECUTION_AUTHORIZED", "Adb", "AdbError", "Device",
    "DeviceAttestation", "ExecutionAttestation", "ExecutionNotAuthorized", "host_in_scope",
    "Instrumentation", "InstrumentationError", "InstrumentationPlan",
    "OBJECTION_JOBS", "authorize", "available_agents", "require_execution",
    "resolve_agent",
    "CaptureError", "CapturePlan", "CaptureResult", "Flow",
    "delegated_capture", "mitmproxy_capture", "read_capture",
    "Observation", "from_capture", "from_frida", "parse_frida_events",
]
