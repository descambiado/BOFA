"""
Sistema de Manejo de Errores de BOFA
====================================

Proporciona manejo centralizado y consistente de errores.
"""

from .exceptions import (
    BOFAError,
    ConfigurationError,
    ModuleNotFoundError,
    ScriptNotFoundError,
    ExecutionError,
    ValidationError,
    SecurityError,
)

__all__ = [
    "BOFAError",
    "ConfigurationError",
    "ModuleNotFoundError",
    "ScriptNotFoundError",
    "ExecutionError",
    "ValidationError",
    "SecurityError",
]
