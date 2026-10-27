"""The local corpus: what the operator's own scans add up to.

``build(repos)`` is the testable core: it reads every project's findings and
aggregates them into a :class:`Corpus`, with no database or Qt dependency of its
own. ``summarize(home)`` opens the project store and calls it.

Everything here is descriptive statistics over data themob already produced, kept
deliberately glass-box: counts a tester can see the basis of, not a model whose
ranking nobody can explain. The canonical weakness key is the aggregation unit,
so a row says "this weakness, this often" without naming any app. The severity,
category and Mobile Top 10 come from the knowledge pack (the authoritative,
context-free rating), falling back to what the finding carried.

It never changes a finding. It is read-only over the store, and the figures it
returns are an advisory overlay, the same discipline the REA handoff and the
dataflow heuristic already keep.
"""
from __future__ import annotations

import itertools
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from ..knowledge import get as weakness
from ..storage.db import open_database
from ..storage.repositories import Repositories
from ..storage.workspace import default_root

_UNMAPPED = "(unmapped)"
_MIN_PAIR_APPS = 2          # a co-occurrence is only interesting across >1 app


@dataclass
class WeaknessStat:
    """One canonical weakness, across the whole local corpus."""

    key: str
    title: str
    severity: str
    masvs_category: str | None
    mobile_top10: str | None
    occurrences: int = 0        # total findings carrying this key
    apps: int = 0               # distinct projects it appeared in
    confirmed: int = 0
    false_positive: int = 0
    accepted_risk: int = 0
    new: int = 0

    @property
    def triaged(self) -> int:
        return self.confirmed + self.false_positive + self.accepted_risk

    @property
    def false_positive_rate(self) -> float | None:
        """Share of triaged instances the operator dismissed, or None if none."""
        return (self.false_positive / self.triaged) if self.triaged else None


@dataclass
class Corpus:
    """The operator's scans, summarised. Local, descriptive, advisory."""

    projects: int = 0
    findings: int = 0
    by_platform: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    weaknesses: list[WeaknessStat] = field(default_factory=list)
    co_occurrence: list[tuple[str, str, int]] = field(default_factory=list)
    generated_at: str = ""

    @property
    def is_empty(self) -> bool:
        return self.findings == 0


def _resolve_home(home) -> Path:
    return Path(home).expanduser() if home else default_root()


@contextmanager
def _session(home) -> Iterator[Repositories]:
    database = open_database(_resolve_home(home) / "themob.db")
    try:
        yield Repositories(database)
    finally:
        database.close_all()


def _metadata(key: str, severity: str) -> tuple[str, str, str | None, str | None]:
    """Canonical (title, severity, masvs_category, mobile_top10) for a key.

    Prefers the knowledge pack, the authoritative rating; falls back to the
    finding's own severity when the key is unmapped or not in the pack.
    """
    if key and key != _UNMAPPED:
        try:
            spec = weakness(key)
            return (spec.title, spec.severity.value,
                    spec.masvs_category.value if spec.masvs_category else None,
                    spec.mobile_top10)
        except KeyError:
            pass
    return (key or _UNMAPPED, severity, None, None)


def build(repos: Repositories, *, top: int = 50, pairs: int = 25) -> Corpus:
    """Aggregate every project's findings into a corpus. No app is named."""
    projects = repos.projects.list(limit=100000)
    stats: dict[str, WeaknessStat] = {}
    by_platform: Counter = Counter()
    by_severity: Counter = Counter()
    pair_apps: Counter = Counter()
    total_findings = 0

    for project in projects:
        by_platform[project.target_platform.value] += 1
        keys_here: set[str] = set()
        for finding in repos.findings.list(project.id):
            total_findings += 1
            by_severity[finding.severity.value] += 1
            key = finding.weakness_key or _UNMAPPED
            stat = stats.get(key)
            if stat is None:
                title, sev, cat, top10 = _metadata(key, finding.severity.value)
                stat = WeaknessStat(key=key, title=title, severity=sev,
                                    masvs_category=cat, mobile_top10=top10)
                stats[key] = stat
            stat.occurrences += 1
            # status is one of new / confirmed / false_positive / accepted_risk,
            # and each is a field on the stat, so this records the verdict mix.
            setattr(stat, finding.status.value,
                    getattr(stat, finding.status.value) + 1)
            keys_here.add(key)

        for key in keys_here:
            stats[key].apps += 1
        for a, b in itertools.combinations(sorted(keys_here), 2):
            pair_apps[(a, b)] += 1

    weaknesses = sorted(stats.values(),
                        key=lambda s: (s.apps, s.occurrences), reverse=True)[:top]
    co_occurrence = [(a, b, n) for (a, b), n in pair_apps.most_common(pairs)
                     if n >= _MIN_PAIR_APPS]

    return Corpus(
        projects=len(projects),
        findings=total_findings,
        by_platform=dict(by_platform),
        by_severity=dict(by_severity),
        weaknesses=weaknesses,
        co_occurrence=co_occurrence,
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )


def summarize(home=None, *, top: int = 50, pairs: int = 25) -> Corpus:
    """Open the project store and build the corpus from it."""
    with _session(home) as repos:
        return build(repos, top=top, pairs=pairs)
