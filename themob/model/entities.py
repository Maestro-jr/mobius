"""Entities and edges: the nodes and typed relationships of the attack-surface graph.

Every discovered thing (app, component, endpoint, secret, SDK, ...) is an Entity.
Typed Edges connect them. The tester-facing "sections" and every pivot are just
queries over this graph, so keep type-specific detail in ``attributes`` rather
than proliferating subclasses: the schema stays stable as analyzers grow.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from .enums import EdgeType, EntityType, Platform


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Entity(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    type: EntityType
    platform: Platform

    # Natural identifier, unique per (project, type): package name, endpoint URL,
    # component class name, library coordinate, secret fingerprint, etc. This is
    # what the correlator upserts on, so two analyzers discovering the same thing
    # converge to one node instead of duplicating it.
    key: str

    label: str | None = None                        # human-friendly display name
    attributes: dict[str, Any] = Field(default_factory=dict)   # type-specific fields (JSON in storage)
    created_at: datetime = Field(default_factory=_utcnow)


class Edge(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    src_id: str
    dst_id: str
    type: EdgeType
    attributes: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=_utcnow)
