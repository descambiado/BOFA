"""
Core Engine de BOFA
===================

Motor central de ejecución del framework.
"""

from .engine import BOFAEngine, get_engine
from ..cancellation import check_cancelled, cooperative_sleep, raise_if_cancelled

__all__ = ["BOFAEngine", "get_engine", "check_cancelled", "cooperative_sleep", "raise_if_cancelled"]
