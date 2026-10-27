"""Scoring: severity in the context of the app it was found in.

The weakness pack gives a default severity per class of problem. This turns that
into a rating for one finding in one package, by asking whether anything outside
the app can reach it, and produces a number to rank by.

Severity and confidence stay separate axes throughout. How bad a finding would
be and how likely it is to be real are different questions, and folding them
into one figure loses both.
"""
from .model import Score, rank, raise_one, score
from .pass_ import ScoringReport, run

__all__ = ["Score", "ScoringReport", "rank", "raise_one", "run", "score"]
