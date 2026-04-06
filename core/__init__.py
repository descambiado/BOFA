"""
BOFA Core Framework
===================

Core framework para BOFA (Cybersecurity Operations Framework Advanced).

Este módulo proporciona la infraestructura base del framework:
- Engine: Motor central de ejecución
- Config: Sistema de configuración
- Logger: Sistema de logging estructurado
- Errors: Manejo centralizado de errores
- Utils: Utilidades compartidas
"""

__version__ = "1.0.0"
__author__ = "@descambiado"

from .cancellation import check_cancelled, cooperative_sleep, raise_if_cancelled

__all__ = ["check_cancelled", "cooperative_sleep", "raise_if_cancelled"]
