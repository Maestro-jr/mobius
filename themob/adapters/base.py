"""The ``Analyzer`` interface: every tool integration implements this contract.

Adding a tool to themob means writing one adapter: declare what it applies to,
run it (always at arms length, inside the sandbox), and normalize its output
into entities, edges and findings. The orchestrator knows nothing else about it.

Two rules this interface encodes, both from the build plan:

* **Arms length, always.** ``run`` receives a :class:`SandboxRunner`; it must
  invoke the tool as a subprocess or REST call inside a container, never import
  it. That single boundary is both the malicious-input containment (Sec 9) and
  the copyleft licensing firewall (Sec 6).
* **Nothing trusts tool output.** ``normalize`` parses data produced by a tool
  that just chewed on a hostile binary. Validate shapes, bound sizes, and treat
  every path as untrusted.

Adapters emit entities that have no database identity yet, so edges reference
their endpoints by :class:`EntityRef`, that is ``(type, key)``, and the orchestrator
resolves those to row ids after upserting. This is themob's equivalent of
TOPRECON's ``Emit(entity, edge_kind)``, widened because a mobile analyzer links
arbitrary pairs rather than only "child of the entity I consumed".
"""
from __future__ import annotations

import abc
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

from ..model.entities import Entity
from ..model.enums import EdgeType, EntityType, Platform, Stage
from ..model.findings import Finding

# The operator opt-in for keeping the full value of a hardcoded secret. OFF by
# default: the secret scanners (gitleaks, apkleaks) redact every credential
# inside the sandbox, and only a redacted preview plus a digest leave the
# container. Setting this (in the environment, never in source) tells those
# workers to let the full value out, so the password-gated reveal in the UI can
# show it. It persists a live credential in the local store, which is exactly
# why it is the operator's explicit choice and not the default.
ENV_CAPTURE_SECRETS = "THEMOB_CAPTURE_SECRET_VALUES"


def capture_secret_values() -> bool:
    """Whether the operator opted into keeping full secret values (see above)."""
    return (os.environ.get(ENV_CAPTURE_SECRETS) or "").strip().lower() in (
        "1", "true", "yes", "on")


class Availability:
    """Why an analyzer can or cannot run right now (mirrors TOPRECON's ModuleStatus)."""
    READY = "Ready"
    NO_SANDBOX = "Docker unavailable"
    NO_IMAGE = "Worker image missing"
    NOT_APPLICABLE = "Not applicable"
    DISABLED = "Disabled"


class AnalyzerError(RuntimeError):
    """An adapter could not produce a usable result."""


# ---------------------------------------------------------------------------
# Inputs and outputs
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Target:
    """The sample under analysis. Treated as hostile input everywhere.

    ``app_key`` is filled in by the orchestrator once some analyzer has
    established the App node, and is how a later adapter attaches attributes to
    *that* node instead of forking a second one. jadx, for instance, decompiles
    DEX and never sees the manifest, so it cannot recover the package name on
    its own.
    """
    project_id: str
    platform: Platform
    sample_path: Path            # absolute; the workspace copy, read-only
    sha256: str
    name: str = ""
    app_key: str | None = None
    package: str | None = None

    @property
    def suffix(self) -> str:
        return self.sample_path.suffix.lower()

    @property
    def fallback_app_key(self) -> str:
        """The App key to use before any analyzer has named the package.

        Every adapter falls back to the same value, so they still converge on
        one node when the manifest cannot be read at all.
        """
        return self.app_key or f"sha256:{self.sha256[:16]}"


@dataclass(frozen=True)
class AnalysisContext:
    """What earlier stages have already established, read-only.

    Later stages judge rather than re-parse. The config auditor is the first
    analyzer that needs this: deciding whether an exported Provider is a finding
    means looking at the Component nodes androguard produced, not opening the
    manifest again, and re-parsing attacker-controlled XML in the engine
    process is exactly what the sandbox rule forbids.

    Read-only on purpose. An analyzer contributes through its
    :class:`AnalyzerResult`; nothing writes to the database behind the
    pipeline's back, or the audit log stops describing what happened.
    """

    snapshot: Any = None                    # correlate.graph.GraphSnapshot

    @property
    def app(self) -> Entity | None:
        """The App node, if some earlier stage established one."""
        return getattr(self.snapshot, "root", None)

    def of_type(self, *types: EntityType) -> list[Entity]:
        if self.snapshot is None:
            return []
        return self.snapshot.of_type(*types)

    @property
    def is_empty(self) -> bool:
        return self.snapshot is None or self.snapshot.is_empty


@dataclass
class RawResult:
    """What a tool produced, before interpretation.

    ``payload`` is the parsed structured output (workers emit JSON on stdout).
    ``raw_path`` points at the persisted copy in ``raw/<analyzer>/`` so a finding
    can cite the exact tool output it came from.
    """
    analyzer: str
    ok: bool = False
    payload: dict[str, Any] = field(default_factory=dict)
    raw_path: str | None = None          # workspace-relative
    stderr: str = ""
    exit_code: int | None = None
    duration_s: float = 0.0
    error: str | None = None

    def require_ok(self) -> "RawResult":
        if not self.ok:
            raise AnalyzerError(self.error or f"{self.analyzer} failed")
        return self


@dataclass(frozen=True)
class EntityRef:
    """Points at an entity by its natural key, before it has a database id."""
    type: EntityType
    key: str

    @staticmethod
    def of(entity: Entity) -> "EntityRef":
        return EntityRef(entity.type, entity.key)


@dataclass(frozen=True)
class EdgeSpec:
    """A typed edge between two entities identified by their natural keys."""
    src: EntityRef
    dst: EntityRef
    type: EdgeType
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalyzerResult:
    """Normalized output: what this analyzer contributes to the graph."""
    entities: list[Entity] = field(default_factory=list)
    edges: list[EdgeSpec] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)     # workspace-relative paths

    def extend(self, other: "AnalyzerResult") -> "AnalyzerResult":
        self.entities.extend(other.entities)
        self.edges.extend(other.edges)
        self.findings.extend(other.findings)
        self.artifacts.extend(other.artifacts)
        return self

    @property
    def is_empty(self) -> bool:
        return not (self.entities or self.edges or self.findings)


# ---------------------------------------------------------------------------
# The interface
# ---------------------------------------------------------------------------

class Analyzer(abc.ABC):
    """Base class for every tool adapter.

    Subclasses set the class attributes and implement :meth:`run` and
    :meth:`normalize`. They must not raise for expected conditions (a missing
    image, an inapplicable target): report that through :meth:`availability`
    and :meth:`applies_to` instead, and return a failed :class:`RawResult` for
    a tool that ran but did not succeed.
    """

    name: str = "analyzer"                       # stable machine id
    display: str = "Analyzer"                    # UI label
    stage: Stage = Stage.UNPACK
    platforms: tuple[Platform, ...] = (Platform.ANDROID,)
    suffixes: tuple[str, ...] = ()               # ('.apk',); empty = any
    image: str = ""                              # worker image tag, "" = no container
    timeout: float = 300.0
    # Container memory ceiling. Raise it per-adapter rather than globally: a JVM
    # tool needs far more than a Python one, and an OOM kill is indistinguishable
    # from a corrupt sample from the operator's side.
    memory: str = "2g"

    # Tool identity recorded on every finding this adapter emits; keep it equal
    # to the underlying tool, not the adapter, so cross-tool voting is honest.
    tool: str = ""
    license_note: str = ""                       # why this integration is arms-length

    # Whether :meth:`run` needs the graph earlier stages built. Off by default:
    # assembling the read model is a full graph read, and an adapter that only
    # shells out to a container has nothing to do with it.
    wants_graph: bool = False

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if not cls.tool:
            cls.tool = cls.name

    # -- capability -----------------------------------------------------------

    def applies_to(self, target: Target) -> bool:
        """Whether this analyzer has anything to say about *target*."""
        if target.platform not in self.platforms:
            return False
        if self.suffixes and target.suffix not in self.suffixes:
            return False
        return True

    def availability(self, sandbox: Any = None) -> str:
        """Whether this analyzer could run right now, and if not, why."""
        if not self.image:
            return Availability.READY
        if sandbox is None:
            return Availability.NO_SANDBOX
        try:
            if not sandbox.is_available():
                return Availability.NO_SANDBOX
            if not sandbox.has_image(self.image):
                return Availability.NO_IMAGE
        except Exception:                # noqa: BLE001, availability never raises
            return Availability.NO_SANDBOX
        return Availability.READY

    # -- execution ------------------------------------------------------------

    @abc.abstractmethod
    def run(self, target: Target, workspace: Any, sandbox: Any,
            context: "AnalysisContext | None" = None) -> RawResult:
        """Execute the tool against *target*, inside the sandbox.

        Must not parse the sample in this process. Persist raw output under
        ``workspace.raw_dir(self.name)`` and reference it from the result.

        ``context`` is supplied only when :attr:`wants_graph` is set, building
        the read model costs a full graph read, and the tool adapters that just
        shell out to a container have no use for it.
        """

    @abc.abstractmethod
    def normalize(self, raw: RawResult, target: Target) -> AnalyzerResult:
        """Map raw tool output into entities, edges and findings.

        Called in the engine process on data that came from a container that
        parsed a hostile file: validate everything.
        """

    # -- helpers for subclasses ----------------------------------------------

    def entity(self, etype: EntityType, key: str, target: Target,
               label: str | None = None, **attributes: Any) -> Entity:
        return Entity(type=etype, platform=target.platform, key=key,
                      label=label or key, attributes=attributes)

    def __repr__(self) -> str:                                # pragma: no cover
        return f"<{type(self).__name__} {self.name} stage={self.stage.value}>"


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class AnalyzerRegistry:
    """Holds analyzer instances and answers "what runs at this stage?".

    Mirrors TOPRECON's ``TransformRegistry``: registration is the only wiring
    step, and the orchestrator discovers the pipeline from it.
    """

    def __init__(self) -> None:
        self._by_name: dict[str, Analyzer] = {}
        self._by_stage: dict[Stage, list[Analyzer]] = {}

    def register(self, analyzer: Analyzer) -> Analyzer:
        if analyzer.name in self._by_name:
            raise ValueError(f"analyzer {analyzer.name!r} is already registered")
        self._by_name[analyzer.name] = analyzer
        self._by_stage.setdefault(analyzer.stage, []).append(analyzer)
        return analyzer

    def register_all(self, analyzers: Iterable[Analyzer]) -> None:
        for analyzer in analyzers:
            self.register(analyzer)

    def get(self, name: str) -> Analyzer | None:
        return self._by_name.get(name)

    def all(self) -> list[Analyzer]:
        return list(self._by_name.values())

    def for_stage(self, stage: Stage) -> list[Analyzer]:
        return list(self._by_stage.get(stage, []))

    def applicable(self, target: Target,
                   stages: Sequence[Stage] | None = None) -> list[Analyzer]:
        """Every registered analyzer that applies to *target*, in stage order."""
        wanted = list(stages) if stages else list(Stage)
        out: list[Analyzer] = []
        for stage in wanted:
            for analyzer in self._by_stage.get(stage, []):
                if analyzer.applies_to(target):
                    out.append(analyzer)
        return out

    def stages(self) -> list[Stage]:
        """Stages that have at least one analyzer, in pipeline order."""
        return [s for s in Stage if self._by_stage.get(s)]

    def __len__(self) -> int:
        return len(self._by_name)
