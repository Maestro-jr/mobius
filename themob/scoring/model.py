"""Severity in context, and a number to rank by.

A weakness pack gives every finding a default severity. That default answers
"how bad is this kind of problem", which is the right question to ask before
looking at the app and the wrong one to stop at afterwards. Two findings of the
same weakness are not equally urgent when one sits behind an exported Activity
and the other is used by a class nothing outside the app can call.

So this module does two separate things, and keeping them separate is the point.

**Severity is adjusted, once, and only by exposure.** Reachability from an entry
point raises it a single level, never more, and never downward. Anything a
report cannot explain in one sentence is a rating nobody will trust, and "HIGH,
raised from MEDIUM because an exported component reaches it" is a sentence.
Confidence deliberately does not touch severity: how likely a finding is to be
real and how bad it would be are different axes, and multiplying them into one
number destroys both.

**Risk is a separate figure for ordering.** It folds severity, confidence and
exposure into 0 to 100 so a "top findings" list can be sorted without pretending
the number means more than an ordering does.

The scorer never lowers a severity. A weakness pack that says CRITICAL and a
graph that cannot prove reachability is not evidence of safety: themob might
simply not have found the path. Silence is not absence, and downgrading on it
would turn a gap in the analysis into a reassurance.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..model.enums import Severity

# The ladder severity moves along. One step, one direction.
_ORDER: tuple[Severity, ...] = (Severity.INFO, Severity.LOW, Severity.MEDIUM,
                                Severity.HIGH, Severity.CRITICAL)
_RANK = {severity: index for index, severity in enumerate(_ORDER)}

# What each level is worth before confidence and exposure are applied. Spread
# rather than linear: the gap between HIGH and CRITICAL should outweigh a
# confidence difference, or a well-evidenced LOW outranks an uncertain CRITICAL.
_WEIGHT: dict[Severity, float] = {
    Severity.INFO: 5.0,
    Severity.LOW: 20.0,
    Severity.MEDIUM: 45.0,
    Severity.HIGH: 70.0,
    Severity.CRITICAL: 90.0,
}

# Reachable findings sort above unreachable ones of the same severity, without
# letting exposure alone jump a level in the ordering.
_EXPOSURE_BONUS = 10.0


@dataclass(frozen=True)
class Score:
    """A severity, a number to rank by, and why they are what they are."""

    severity: Severity
    risk: float
    base_severity: Severity
    reason: str = ""

    @property
    def adjusted(self) -> bool:
        return self.severity is not self.base_severity


def _clamp(value: float) -> float:
    """Confidence into 0..1, NaN included.

    ``min(max(x, 0), 1)`` passes NaN straight through, because every comparison
    with NaN is false. Tool output is untrusted and that includes its numbers,
    so a NaN reaching the risk figure would make a finding unsortable.
    """
    value = float(value)
    if value != value:                      # NaN, which no comparison catches
        return 0.0
    return min(max(value, 0.0), 1.0)


def raise_one(severity: Severity) -> Severity:
    """One step up the ladder, stopping at the top."""
    return _ORDER[min(_RANK[severity] + 1, len(_ORDER) - 1)]


def score(base: Severity, confidence: float, exposed: bool,
          hops: int | None = None) -> Score:
    """Rate one finding in the context of the app it was found in.

    ``exposed`` is the correlator's answer to "can anything outside the app
    reach the thing this finding is about". ``hops`` is how far, and is used
    only in the explanation, because one hop and three hops are both reachable
    and the difference is not a severity.
    """
    confidence = _clamp(confidence)

    severity = base
    reason = ""
    if exposed and base is not Severity.CRITICAL:
        severity = raise_one(base)
        distance = ("directly" if hops == 0
                    else f"{hops} hop(s) away" if hops is not None else "")
        reason = (f"raised from {base.value} because an exported entry point "
                  f"reaches it{' ' + distance if distance else ''}")
    elif exposed:
        reason = "already at the top of the scale, and externally reachable"

    risk = _WEIGHT[severity] * confidence
    if exposed:
        risk += _EXPOSURE_BONUS * confidence
    return Score(severity=severity, risk=round(min(risk, 100.0), 1),
                 base_severity=base, reason=reason)


def rank(severity: Severity) -> int:
    """Position on the ladder, for callers that need to compare two."""
    return _RANK[severity]
