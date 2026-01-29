"""
Sistema de Configuración de BOFA
=================================

Proporciona gestión centralizada de configuración del framework.
"""

from .config_manager import ConfigManager, get_config

__all__ = ["ConfigManager", "get_config"]
