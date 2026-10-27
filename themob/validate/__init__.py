"""Credential validation: gated, opt-in, and never done by themob itself.

themob holds a digest and a masked preview of a secret, never the value, so it
cannot test whether a credential is live and would not if it could. This package
prepares the read-only probe an operator runs, behind its own attestation, and
records the result as a verdict. See :mod:`themob.validate.gate` for why it is a
separate authorization.
"""
from __future__ import annotations

from .gate import (ValidationAttestation, ValidationNotAuthorized, authorize,
                   require_validation)
from .planner import ValidationTask, plan, record_result
from .providers import PROBES, Probe, classify, probe_for

__all__ = [
    "PROBES", "Probe", "ValidationAttestation", "ValidationNotAuthorized",
    "ValidationTask", "authorize", "classify", "plan", "probe_for",
    "record_result", "require_validation",
]
