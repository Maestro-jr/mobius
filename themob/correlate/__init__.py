"""The attack-surface graph, and the questions asked of it.

``graph`` is the read model: entities and edges loaded into NetworkX once per
refresh. ``sections`` splits it into the tester-facing nav, ``pivots`` answers
what an attacker outside the app can reach, and ``handoff`` exports the backend
subgraph for TOPRECON.

Kept free of Qt on purpose: the report (1.13) needs the same projections the UI
draws, and importing a widget toolkit to produce an HTML file would be absurd.
"""
from .graph import GraphSnapshot, build_snapshot, empty_snapshot
from .handoff import build as build_handoff
from .pivots import (AttackPath, Exposure, attack_paths, entry_points,
                     exposed_findings, exposure)
from .sections import (SECTIONS, Section, SectionView, project,
                       section_for_entity)

__all__ = [
    "AttackPath", "Exposure", "GraphSnapshot", "SECTIONS", "Section",
    "SectionView", "attack_paths", "build_handoff", "build_snapshot",
    "empty_snapshot", "entry_points", "exposed_findings", "exposure",
    "project", "section_for_entity",
]
