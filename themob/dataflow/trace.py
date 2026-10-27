"""Does the value a scanner flagged actually reach anywhere that matters.

**This is not dataflow analysis, and calling it that would be a lie.** There is
no SSA form here, no alias analysis, no interprocedural anything. It reads the
decompiled Java jadx already produced, finds the identifier a flagged literal
was assigned to, and looks at where that identifier is used. A tester should
read a result from it as "the identifier appears at a sink", not as "the value
provably flows to a sink", and the notes it writes are worded that way.

It is still worth having, because the question it answers is the one that
separates two findings a scanner reports identically::

    private static final String KEY = "AKIA...";        // never used again
    private static final String KEY = "AKIA...";        // sent as a header

The first is very likely a leftover the detector was over-confident about. The
second is a live credential. Nothing in the voting model can tell them apart,
because both are one pattern matcher firing once.

**The asymmetry is deliberate.** Reaching a sink is corroboration, so it enters
the existing noisy-or model as a vote from an independent method. Never being
used is the *absence* of corroboration, which is not a negative vote and cannot
be one: it is expressed as a modest discount instead, floored so a finding never
disappears because a heuristic could not follow it. A secret that is never
referenced is still compiled into the package and still extractable.

Everything is bounded. The decompiled tree came out of a container that parsed a
hostile file, so file sizes, file counts and match counts all have ceilings, and
crossing one is reported as "undetermined" rather than as "nothing found".
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..model.findings import DataFlowStep, Finding, Location
from . import sinks

logger = logging.getLogger(__name__)

# Verdicts, in the order they are worth anything.
REACHES_SINK = "reaches-sink"
USED = "used"
UNUSED = "unused"
UNDETERMINED = "undetermined"

# Ceilings. A hostile package can decompile to a very large tree, and a pass
# that walks all of it stops being a pass and becomes a hang.
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_FILES_SEARCHED = 200
MAX_USES = 60
MAX_STEPS = 12

# An identifier shorter than this, or in this set, matches so much decompiled
# text that a "use" means nothing. jadx names locals aggressively.
MIN_IDENTIFIER = 4
_NOISY = {
    "this", "true", "false", "null", "value", "data", "name", "type", "item",
    "list", "text", "self", "args", "temp", "result", "input", "output",
    "str2", "str3", "obj2", "obj3",
}

# The identifier being assigned is the name immediately to the left of a single
# `=`, so match exactly that: a token boundary, the identifier, then `=` (not
# `==`). An earlier version consumed the type in front of it with nested
# quantifiers -- `(?:[A-Za-z_$][\w$]*\s*[.<>\[\],\s]*)*?` -- whose overlapping
# whitespace classes backtracked catastrophically on a decompiled line that
# never reached an `=`: a single search ran for minutes, and because the regex
# engine holds the GIL for the whole match, it froze the UI at end of run.
# Written this way there is no nesting to backtrack and the scan is linear.
_DECLARATION = re.compile(
    r"(?<![\w$])([A-Za-z_$][\w$]{%d,63})\s*=(?!=)" % (MIN_IDENTIFIER - 1,))


@dataclass
class Use:
    """One place the identifier appears after its declaration."""

    file: str
    line: int
    text: str
    sink: sinks.Sink | None = None


@dataclass
class Flow:
    """What could be established about one flagged value."""

    verdict: str = UNDETERMINED
    identifier: str = ""
    reason: str = ""
    uses: list[Use] = field(default_factory=list)
    declaration: Location | None = None
    # The assignment chain the taint followed from the source, if it moved
    # through intermediate identifiers before a use. Empty for a direct hit.
    hops: list[Use] = field(default_factory=list)

    @property
    def sink_uses(self) -> list[Use]:
        return [u for u in self.uses if u.sink is not None]

    @property
    def best_category(self) -> str:
        """The strongest sink category reached, for weighting."""
        reached = {u.sink.category for u in self.sink_uses if u.sink}
        if not reached:
            return ""
        return max(reached, key=sinks.weight)

    def steps(self) -> list[DataFlowStep]:
        """The flow as the schema records it: a source, the hops, then the sinks."""
        out: list[DataFlowStep] = []
        if self.declaration is not None:
            out.append(DataFlowStep(
                kind="source", location=self.declaration,
                note=f"{self.identifier} is assigned the flagged value here"))
        # The assignment chain, so a reader can see how the value travelled from
        # the source identifier to the one that reaches the sink.
        for hop in self.hops[:MAX_STEPS - 2]:
            out.append(DataFlowStep(
                kind="propagation",
                location=Location(file=hop.file, line=hop.line),
                note=f"the value is copied into {hop.text}"))
        for use in self.sink_uses[:MAX_STEPS - 1]:
            assert use.sink is not None
            out.append(DataFlowStep(
                kind="sink",
                location=Location(file=use.file, line=use.line),
                # "appears at", not "flows to": this reads text, it does not
                # prove a path, and the report must not say otherwise.
                note=f"the value appears where it is {use.sink.note}"))
        return out


def _read(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _identifier(line: str) -> str:
    """The name the flagged value was assigned to, if the line assigns one."""
    match = _DECLARATION.search(line)
    if match is None:
        return ""
    name = match.group(1)
    if len(name) < MIN_IDENTIFIER or name.lower() in _NOISY:
        return ""
    return name


def _resolve(workspace_root: Path, file: str) -> Path | None:
    """A finding's file, as a path inside the workspace and nowhere else."""
    if not file:
        return None
    candidate = (workspace_root / file).resolve()
    try:
        candidate.relative_to(workspace_root.resolve())
    except ValueError:
        # A traversal out of the workspace. The path came from a tool that read
        # a hostile package, so this is refused rather than clamped.
        logger.warning("dataflow: refusing a path outside the workspace: %r", file)
        return None
    return candidate if candidate.is_file() else None


def java_sources(search_root: Path | None) -> list[Path]:
    """The decompiled .java files, walked once.

    ``_uses_across`` is called for every traceable finding, and rglobbing a
    tree of tens of thousands of files on each call was the end-of-run hang. The
    pass walks the tree once and hands the list down, so the cost is paid a
    single time instead of once per finding.
    """
    if search_root is None or not search_root.is_dir():
        return []
    return sorted(search_root.rglob("*.java"))


def trace(finding: Finding, workspace_root: Path,
          search_root: Path | None = None, *,
          sources: list[Path] | None = None,
          deadline: float | None = None) -> Flow:
    """Follow one finding's value as far as reading the text allows.

    ``sources`` is the pre-walked file list from :func:`java_sources`; passing
    it avoids re-walking the decompiled tree per finding. ``deadline`` is a
    ``time.monotonic`` cutoff for the cross-file search, so a single finding
    cannot run the engine thread for minutes.
    """
    location = finding.location
    if location is None or not location.file:
        return Flow(reason="the finding names no file")

    path = _resolve(workspace_root, location.file)
    if path is None:
        return Flow(reason=f"{location.file} is not in the workspace")

    text = _read(path)
    if text is None:
        return Flow(reason=f"{path.name} is missing or above the size ceiling")

    lines = text.splitlines()
    index = (location.line or 0) - 1
    if not 0 <= index < len(lines):
        return Flow(reason="the finding names no usable line")

    identifier = _identifier(lines[index])
    if not identifier:
        return Flow(reason="no identifier is assigned on that line")

    declaration = Location(file=location.file, line=location.line)

    # Follow the value through assignments, not just the one identifier it was
    # first bound to. A secret copied into a local and then a header is the case
    # the single-hop version missed, and it is exactly the live credential a
    # tester most wants separated from a dead constant.
    tainted, hops = _propagate(text, identifier, skip_line=location.line)
    uses = _uses_of_set(text, tainted, location.file, skip_line=location.line)

    # A constant is usually referenced from another class, so widen the search,
    # but only when the declaring file had nothing to say. Cross-file taint is
    # not followed (the intermediate locals are method-scoped); the source
    # identifier itself is what travels between classes.
    if not uses and search_root is not None and identifier.isupper():
        uses = _uses_across(search_root, workspace_root, identifier, path,
                            sources=sources, deadline=deadline)

    flow = Flow(identifier=identifier, uses=uses, declaration=declaration,
                hops=hops)
    if flow.sink_uses:
        flow.verdict = REACHES_SINK
        flow.reason = (f"{identifier} appears at a sink"
                       if not hops
                       else f"{identifier} reaches a sink through "
                            f"{len(hops)} assignment(s)")
    elif uses:
        flow.verdict = USED
        flow.reason = f"{identifier} is referenced, but not at any known sink"
    else:
        flow.verdict = UNUSED
        flow.reason = f"{identifier} is never referenced after it is assigned"
    return flow


# An assignment jadx emits: an optional type, an identifier, `=` (not `==`), a
# right-hand side up to the semicolon. `+=` propagates too (append). Comparisons
# are excluded by the lookahead, so `a == b` and `a <= b` never match.
_ASSIGNMENT = re.compile(
    r"(?P<lhs>[A-Za-z_$][\w$]*)\s*\+?=(?!=)\s*(?P<rhs>[^;]+);")

# How many identifiers the taint set may grow to. A method that launders one
# value through forty locals is pathological; past this the pass stops rather
# than chase decompiler noise.
MAX_TAINT = 40


def _propagate(text: str, source: str,
               skip_line: int | None) -> tuple[set[str], list[Use]]:
    """The set of identifiers the flagged value flows into, and the hops taken.

    A bounded textual fixpoint: an assignment whose right-hand side names a
    tainted identifier taints its left-hand side, repeated until nothing new is
    tainted or the ceilings are hit. This is not real dataflow, it is co-mention
    on an assignment line, so a hop is worded as "copied into" rather than
    "flows to".
    """
    tainted = {source}
    hops: list[Use] = []
    lines = text.splitlines()

    for _ in range(MAX_STEPS):
        grew = False
        for number, line in enumerate(lines, 1):
            if number == skip_line:
                continue
            match = _ASSIGNMENT.search(line)
            if not match:
                continue
            lhs = match.group("lhs")
            if lhs in tainted or lhs in _NOISY or len(lhs) < MIN_IDENTIFIER:
                continue
            rhs = match.group("rhs")
            if not _mentions_any(rhs, tainted):
                continue
            tainted.add(lhs)
            hops.append(Use(file="", line=number, text=line.strip()[:200],
                            sink=None))
            grew = True
            if len(tainted) >= MAX_TAINT:
                return tainted, hops
        if not grew:
            break
    return tainted, hops


def _mentions_any(text: str, identifiers: set[str]) -> bool:
    for identifier in identifiers:
        if re.search(r"\b" + re.escape(identifier) + r"\b", text):
            return True
    return False


def _uses_of_set(text: str, identifiers: set[str], file: str,
                 skip_line: int | None) -> list[Use]:
    """Every line that mentions any tainted identifier, sink-annotated.

    The declaration line and the assignment hops are not sinks in themselves, so
    a use is recorded for a line only when it is not purely one of those; a line
    that both copies the value and sends it (``header = f(KEY); send(header)`` on
    one decompiled line) still counts, because it does reach the sink.
    """
    patterns = [re.compile(r"\b" + re.escape(i) + r"\b") for i in identifiers]
    out: list[Use] = []
    for number, line in enumerate(text.splitlines(), 1):
        if number == skip_line:
            continue
        if not any(p.search(line) for p in patterns):
            continue
        out.append(Use(file=file, line=number, text=line.strip()[:200],
                       sink=sinks.find(line)))
        if len(out) >= MAX_USES:
            break
    return out


def _uses_in(text: str, identifier: str, file: str,
             skip_line: int | None) -> list[Use]:
    pattern = re.compile(r"\b" + re.escape(identifier) + r"\b")
    out: list[Use] = []
    for number, line in enumerate(text.splitlines(), 1):
        if number == skip_line or not pattern.search(line):
            continue
        out.append(Use(file=file, line=number, text=line.strip()[:200],
                       sink=sinks.find(line)))
        if len(out) >= MAX_USES:
            break
    return out


def _uses_across(search_root: Path, workspace_root: Path, identifier: str,
                 declaring: Path, *, sources: list[Path] | None = None,
                 deadline: float | None = None) -> list[Use]:
    """Look for the identifier in the rest of the decompiled tree.

    ``sources`` is the tree walked once by :func:`java_sources`; without it the
    walk happens here (the standalone path, e.g. tests). ``deadline`` bounds the
    scan so one finding over a huge tree cannot stall the engine thread.
    """
    paths = sources if sources is not None else java_sources(search_root)
    out: list[Use] = []
    searched = 0
    for path in paths:
        if path == declaring:
            continue
        if deadline is not None and time.monotonic() > deadline:
            break
        searched += 1
        if searched > MAX_FILES_SEARCHED:
            break
        text = _read(path)
        if text is None or identifier not in text:
            continue
        try:
            relative = path.relative_to(workspace_root).as_posix()
        except ValueError:
            relative = path.name
        out.extend(_uses_in(text, identifier, relative, skip_line=None))
        if len(out) >= MAX_USES:
            break
    return out[:MAX_USES]
