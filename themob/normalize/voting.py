"""Cross-tool voting: what agreement between scanners is actually worth.

Every finding arrives with a confidence its reporting adapter assigned, and the
storage layer keeps the higher of two when they merge. That is enough to avoid
losing information, and it is not enough to be useful: two tools independently
reporting the same weakness at the same place is stronger evidence than either
alone, and ``max()`` throws that away.

The combination rule is noisy-or. If a reporter's confidence is read as "the
probability this finding is real", then the chance every reporter is wrong is
the product of their individual error rates, so::

    combined = 1 - product(1 - c_i)

That rises with each agreeing tool, has diminishing returns, and cannot exceed
1. Two reporters at 0.8 give 0.96 rather than 1.6.

**Agreement only counts when the tools can disagree.** This is the part a naive
implementation gets wrong. gitleaks and apkleaks both match regular expressions
against the same decompiled text: they share their blind spots almost exactly,
so when both fire it is close to one detector reporting twice. Treating that as
two independent votes inflates confidence on precisely the findings most likely
to be a shared false positive.

So reporters are grouped by *method*, the strongest vote within a method is
taken, and only those per-method votes are combined. Two pattern matchers agree
to little effect; a pattern matcher and a manifest reader agreeing is real
corroboration, because nothing about the way one fails makes the other fail too.

Confidence is capped below 1. Static analysis of a package nobody can execute
does not produce certainty, and a report that claims it invites the reader to
skip the validation step that 1.12 exists to provide.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# How each reporter reaches its conclusion. Tools sharing a method share their
# blind spots, so their agreement is discounted.
#
# The value is deliberately not "the tool's name": what matters is the technique,
# and two tools using the same one are not two witnesses.
METHODS: dict[str, str] = {
    # Regular expressions over decompiled text and resources.
    "gitleaks": "pattern",
    "apkleaks": "pattern",
    # Parsed syntax, so it sees structure a regular expression cannot.
    "semgrep": "semantic",
    # Structured facts recovered from the manifest and the resource table.
    "config-audit": "manifest",
    # A published advisory keyed by package coordinates. Not an opinion about
    # the code at all, which is why it stands on its own.
    "grype": "advisory",
    # Derived from what another stage already established.
    "endpoint-extract": "derived",

    # MobSF is not one witness. It is a manifest reader, a pattern matcher over
    # decompiled code and a secret scanner wearing one name, and each of those
    # shares its blind spots with a different tool already here. Reporting it as
    # a single "mobsf" method would inflate confidence exactly where it should
    # be discounted: its manifest findings agree with the config auditor because
    # both read the same manifest, not because two techniques converged.
    #
    # So the adapter qualifies the reporter, and the qualified name is what the
    # report shows. "mobsf/manifest agrees with config-audit" is a weaker claim
    # than "mobsf agrees with config-audit", and it is the true one.
    "mobsf/manifest": "manifest",
    "mobsf/network": "manifest",
    "mobsf/code": "pattern",
    "mobsf/secrets": "pattern",
    "mobsf/certificate": "manifest",

    # Runtime observation: the app was watched doing the thing. It shares a
    # blind spot with nobody, because it is the only method that sees behaviour
    # rather than code, so when it agrees with a static reporter that is two
    # genuinely independent techniques converging, the strongest corroboration
    # themob can express. "semgrep saw the call and we watched it fire" is a
    # different, harder claim than either alone.
    "frida": "runtime",
    "mitmproxy": "runtime",

    # Reads ELF headers, a structural fact about the compiled binary. Shares a
    # blind spot with nobody else here, so it stands as its own method.
    "nativelib": "binary",
}

_DEFAULT_METHOD = "other"

# Nothing static reaches certainty. The cap is what keeps "the tools all agree"
# from reading as "no need to check".
MAX_CONFIDENCE = 0.99

# Floor for a reporter that gave no usable number, low enough that it cannot
# lift a finding on its own.
_FALLBACK_CONFIDENCE = 0.5


@dataclass(frozen=True)
class Vote:
    """One reporter's opinion about one finding."""

    tool: str
    confidence: float

    @property
    def method(self) -> str:
        """The technique behind this vote, not the name on it.

        A reporter may qualify itself as ``tool/part`` when one program uses
        several techniques. An unrecognised section collapses onto the bare tool
        name rather than onto the shared default: two unknown sections of one
        program are still one program, and letting them land in "other" would
        invent the independent corroboration this whole module exists to refuse.
        Sections themob emits are covered by a tripwire test.
        """
        if self.tool in METHODS:
            return METHODS[self.tool]
        bare, sep, _part = self.tool.partition("/")
        if sep:
            return METHODS.get(bare, bare)
        return _DEFAULT_METHOD


@dataclass
class Verdict:
    """The combined opinion, and enough detail to explain it."""

    confidence: float
    tools: list[str] = field(default_factory=list)
    methods: list[str] = field(default_factory=list)

    @property
    def corroborated(self) -> bool:
        """Whether independent methods agree, not merely independent tools."""
        return len(self.methods) > 1


def _clamp(value: float) -> float:
    if value != value:                      # NaN, which no comparison catches
        return _FALLBACK_CONFIDENCE
    return min(max(float(value), 0.0), 1.0)


def combine(votes: list[Vote]) -> Verdict:
    """Fold every reporter's opinion into one confidence.

    Within a method the strongest vote wins; across methods the survivors are
    combined with noisy-or. A single reporter comes back with its own number
    unchanged, so a lone finding is never inflated just for existing.
    """
    if not votes:
        return Verdict(confidence=_FALLBACK_CONFIDENCE)

    strongest: dict[str, float] = {}
    for vote in votes:
        confidence = _clamp(vote.confidence)
        method = vote.method
        if confidence > strongest.get(method, -1.0):
            strongest[method] = confidence

    combined = 1.0
    for confidence in strongest.values():
        combined *= (1.0 - confidence)
    combined = 1.0 - combined

    # Order the trail so the same inputs always explain themselves the same way.
    tools = sorted({v.tool for v in votes})
    methods = sorted(strongest)
    return Verdict(confidence=min(round(combined, 4), MAX_CONFIDENCE),
                   tools=tools, methods=methods)
