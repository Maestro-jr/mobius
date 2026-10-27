"""The execution gate: reading a package and running it are different acts.

Phases 1 and 2 never execute the sample. Everything they do happens to a file,
inside a container with no route out, and the worst case is a wrong finding.
Phase 3 runs the app, and the worst cases change shape entirely:

* the sample **executes**, so a hostile package gets a CPU, a filesystem and
  whatever the device's accounts can reach;
* the app **talks to production**, so an assessment generates real requests to
  the client's backend and to every third party the app embeds;
* the traffic is **intercepted**, which means terminating TLS for hosts that
  may not belong to anyone in the engagement.

One attestation covered "I may assess this binary". None of the three above are
covered by it, and treating them as covered is how an assessment quietly becomes
an incident. So this gate asks for each separately, refuses to start without all
of them, and writes every one into the same hash-chained trail as the static
attestation.

**The device clause is the one that protects a person rather than a company.**
A test device is a burner. A phone with somebody's mail, banking and photos on
it is not, and running a hostile package beside real data has a victim who never
agreed to anything. The gate cannot verify what a device holds, so it makes the
operator say it, by name, in a record that outlives the project.

**The interception scope is entered by hand, like the TOPRECON handoff's.**
themob knows what an app talks to and not who owns it, so it never assumes. A
host that is not in scope is not intercepted, and the capture says so rather
than silently including it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ..audit.attestation import (Action, AuditTrail, AuthorizationError,
                                 _utcnow_iso)

# Kept as a name here for the modules that import it, but the string itself
# lives in the audit vocabulary, which is the one place it is allowed to.
ACTION_EXECUTION_AUTHORIZED = Action.EXECUTION_AUTHORIZED

# A hostname, or a leading-dot suffix meaning "this domain and anything under
# it". Deliberately strict: this list decides whose TLS gets terminated.
_HOST_RE = re.compile(r"^\.?(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
                      r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$")

# A wildcard here would mean "intercept everything", which is the one thing
# this list exists to prevent somebody typing by accident.
_REFUSED_SCOPES = {"*", ".", "*.*", "all", "any", "0.0.0.0/0", "::/0"}


def host_in_scope(host: str, scope) -> bool:
    """Whether *host* falls within *scope*. The one place this is decided.

    Dependency-free on purpose: the mitmproxy addon imports this same function
    to decide, per live connection, whether to terminate TLS. A second copy of
    the rule living in the proxy is a second place for "which hosts may we
    decrypt" to be answered differently from the attestation, so there is one.

    A leading dot means "this domain and everything under it"; a bare host
    matches only itself. Suffix matching is on a dot boundary, so
    ``example.com.evil.net`` never matches ``.example.com``. An empty scope
    matches nothing, which is the safe default the whole gate turns on.
    """
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return False
    for entry in scope or ():
        entry = (entry or "").strip().lower().rstrip(".")
        if not entry:
            continue
        if entry.startswith("."):
            if host == entry[1:] or host.endswith(entry):
                return True
        elif host == entry:
            return True
    return False


class ExecutionNotAuthorized(AuthorizationError):
    """Dynamic analysis was attempted without the attestations it requires."""


@dataclass
class DeviceAttestation:
    """What the operator says about the machine the app will run on."""

    identifier: str = ""                 # adb serial, or the emulator's name
    description: str = ""                # "Pixel 4a, wiped, lab shelf 2"
    # The clause with a human on the other end of it.
    dedicated_test_device: bool = False
    # An emulator is the safe default and is worth recording separately: a
    # snapshot can be rolled back, a physical device cannot.
    is_emulator: bool = False

    def validate(self) -> None:
        if not self.identifier.strip():
            raise ExecutionNotAuthorized(
                "a device identifier is required: the record has to say which "
                "machine ran the sample")
        if not self.dedicated_test_device:
            raise ExecutionNotAuthorized(
                "the device must be attested as a dedicated test device or "
                "emulator. themob will not run an unknown package beside "
                "somebody's real accounts, and it cannot check that for you")


@dataclass
class ExecutionAttestation:
    """The three statements running an app requires, beyond assessing it.

    Kept apart from the static :class:`~themob.audit.attestation.Attestation`
    rather than folded into it. They authorise different acts, they are often
    granted by different people, and an engagement that covers reading a binary
    frequently does not cover generating traffic to the systems it talks to.
    """

    operator: str = ""
    engagement_ref: str = ""
    device: DeviceAttestation = field(default_factory=DeviceAttestation)
    # "I may cause this app to contact its backends."
    traffic_authorized: bool = False
    # Hosts whose TLS may be terminated. Empty means intercept nothing.
    interception_scope: list[str] = field(default_factory=list)
    scope_note: str = ""
    ts: str = field(default_factory=_utcnow_iso)

    def validate(self) -> None:
        if not self.operator.strip():
            raise ExecutionNotAuthorized(
                "execution requires an operator identity: an unattributed "
                "record answers none of the questions it exists for")
        self.device.validate()
        if not self.traffic_authorized:
            raise ExecutionNotAuthorized(
                "running the app sends live requests to its backends and to "
                "every third party it embeds. That is interaction with "
                "production systems and the engagement has to cover it")
        for host in self.interception_scope:
            _validate_scope_entry(host)

    def may_intercept(self, host: str) -> bool:
        """Whether this host's TLS may be terminated.

        Not a fallback to True. A host nobody listed is a host nobody
        authorised, and an empty scope intercepts nothing at all. The matching
        itself is :func:`host_in_scope`, shared verbatim with the mitmproxy
        addon so the proxy decrypts exactly what this attestation permits and
        the two cannot drift.
        """
        return host_in_scope(host, self.interception_scope)

    def to_detail(self) -> dict[str, Any]:
        return {
            "operator": self.operator,
            "engagement_ref": self.engagement_ref,
            "device_id": self.device.identifier,
            "device_description": self.device.description,
            "dedicated_test_device": self.device.dedicated_test_device,
            "is_emulator": self.device.is_emulator,
            "traffic_authorized": self.traffic_authorized,
            # Recorded in full: "which hosts did you decrypt" is the question a
            # disputed capture turns on, and a count would not answer it.
            "interception_scope": sorted(self.interception_scope),
            "scope_note": self.scope_note,
            "attested_at": self.ts,
        }


def _validate_scope_entry(host: str) -> None:
    entry = (host or "").strip().lower().rstrip(".")
    if not entry:
        raise ExecutionNotAuthorized("an empty host cannot be in scope")
    if entry in _REFUSED_SCOPES:
        raise ExecutionNotAuthorized(
            f"{host!r} would intercept everything. Name the hosts this "
            "engagement covers; there is no wildcard here on purpose")
    if "*" in entry:
        raise ExecutionNotAuthorized(
            f"{host!r}: use a leading dot for a domain and everything under "
            "it, as in '.example.com'. A wildcard is too easy to write wider "
            "than intended")
    if not _HOST_RE.match(entry):
        raise ExecutionNotAuthorized(f"{host!r} is not a hostname")


def authorize(attestation: ExecutionAttestation, project_id: str,
              audit: AuditTrail) -> ExecutionAttestation:
    """Validate the attestation and record it. Raises rather than returning False.

    Recorded before anything runs, not after, so a run that crashes halfway
    still leaves the statement that permitted it.
    """
    attestation.validate()
    audit.record(ACTION_EXECUTION_AUTHORIZED, project_id=project_id,
                 actor=attestation.operator, **attestation.to_detail())
    return attestation


def require_execution(repos, project_id: str) -> dict[str, Any]:
    """The gate the dynamic tools call before touching a device.

    Fails closed on anything unexpected, the same way ``require_authorization``
    does for the static pipeline: a missing record, a malformed one, or a
    record whose clauses no longer hold all raise.
    """
    for entry in repos.audit.list(project_id, limit=10_000):
        if entry.action != ACTION_EXECUTION_AUTHORIZED:
            continue
        detail = entry.detail or {}
        if (detail.get("dedicated_test_device")
                and detail.get("traffic_authorized")
                and str(detail.get("device_id") or "").strip()):
            return detail
    raise ExecutionNotAuthorized(
        "this project has no execution attestation. Dynamic analysis needs "
        "one beyond the assessment attestation: running an app is a different "
        "act from reading it")
