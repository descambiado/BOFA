"""
Sistema de Logging de BOFA
==========================

Proporciona logging estructurado y consistente para todo el framework.
"""

from .logger import BOFALogger, get_logger, setup_logging

__all__ = ["BOFALogger", "get_logger", "setup_logging"]
