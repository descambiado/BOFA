"""
Utilidades de Rutas
===================

Funciones utilitarias para manejo de rutas y archivos.
"""

from pathlib import Path
from typing import Optional


def ensure_path(path: Path, is_file: bool = False) -> Path:
    """
    Asegurar que una ruta existe (crear directorios si es necesario).
    
    Args:
        path: Ruta a verificar/crear
        is_file: Si True, crear directorio padre; si False, crear el directorio
        
    Returns:
        Path: Ruta verificada
    """
    if is_file:
        path.parent.mkdir(parents=True, exist_ok=True)
    else:
        path.mkdir(parents=True, exist_ok=True)
    
    return path


def get_script_path(
    base_path: Path,
    module: str,
    script: str,
    extension: str = ".py"
) -> Path:
    """
    Obtener ruta completa a un script.
    
    Args:
        base_path: Ruta base del proyecto
        module: Nombre del módulo
        script: Nombre del script (sin extensión)
        extension: Extensión del archivo (default: .py)
        
    Returns:
        Path: Ruta completa al script
    """
    script_name = script
    if not script_name.endswith(extension):
        script_name = f"{script_name}{extension}"
    
    return base_path / "scripts" / module / script_name


def find_config_file(script_path: Path) -> Optional[Path]:
    """
    Buscar archivo de configuración YAML para un script.
    
    Args:
        script_path: Ruta al script
        
    Returns:
        Path al archivo de configuración o None si no existe
    """
    # Buscar script.yaml o script.yml en el mismo directorio
    config_name = script_path.stem
    possible_configs = [
        script_path.parent / f"{config_name}.yaml",
        script_path.parent / f"{config_name}.yml",
    ]
    
    for config_path in possible_configs:
        if config_path.exists():
            return config_path
    
    return None
