"""Normalization: canonical weakness identity, dedup, and cross-tool voting.

Dedup already happens in storage: findings collide on ``(project_id,
fingerprint)``, and the fingerprint is built from the canonical weakness key so
two tools reporting the same thing in the same place become one row with two
sources. What lives here is the part that needs every reporter to have finished
first, which is deciding what that agreement is worth.
"""
from .pass_ import NormalizeReport, run
from .voting import METHODS, MAX_CONFIDENCE, Verdict, Vote, combine

__all__ = ["METHODS", "MAX_CONFIDENCE", "NormalizeReport", "Verdict", "Vote",
           "combine", "run"]
