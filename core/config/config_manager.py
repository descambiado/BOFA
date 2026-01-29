"""
ConfigManager - Gestor de Configuración Centralizado
=====================================================

Gestiona toda la configuración de BOFA de forma consistente.
"""

import os
import json
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, field


@dataclass
class BOFAConfig:
    """Configuración principal de BOFA"""
    # Rutas
    base_path: Path = field(default_factory=lambda: Path(__file__).parent.parent.parent)
    scripts_path: Path = field(init=False)
    output_path: Path = field(init=False)
    logs_path: Path = field(init=False)
    config_path: Path = field(init=False)
    
    # Configuración de logging
    log_level: str = "INFO"
    log_format: str = "json"  # json, text
    log_file: Optional[str] = None
    
    # Configuración de ejecución
    max_concurrent_executions: int = 5
    execution_timeout: int = 3600  # segundos
    
    # Configuración de módulos
    auto_discover_modules: bool = True
    
    # Configuración de seguridad
    sandbox_enabled: bool = True
    require_authorization: bool = False
    
    def __post_init__(self):
        """Inicializar rutas derivadas"""
        self.scripts_path = self.base_path / "scripts"
        self.output_path = self.base_path / "output"
        self.logs_path = self.base_path / "logs"
        self.config_path = self.base_path / "config"
        
        # Crear directorios si no existen
        self.output_path.mkdir(exist_ok=True)
        self.logs_path.mkdir(exist_ok=True)
        self.config_path.mkdir(exist_ok=True)


class ConfigManager:
    """
    Gestor centralizado de configuración de BOFA.
    
    Carga configuración desde múltiples fuentes en orden de prioridad:
    1. Variables de entorno
    2. Archivo de configuración (config/bofa.yaml o config/bofa.json)
    3. Valores por defecto
    """
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Inicializar el gestor de configuración.
        
        Args:
            config_file: Ruta opcional al archivo de configuración
        """
        self.base_path = Path(__file__).parent.parent.parent
        self.config_file = config_file or self._find_config_file()
        self._config: Optional[BOFAConfig] = None
        
    def _find_config_file(self) -> Optional[Path]:
        """Buscar archivo de configuración en ubicaciones estándar"""
        possible_paths = [
            self.base_path / "config" / "bofa.yaml",
            self.base_path / "config" / "bofa.yml",
            self.base_path / "config" / "bofa.json",
            self.base_path / ".bofa.yaml",
            self.base_path / ".bofa.yml",
        ]
        
        for path in possible_paths:
            if path.exists():
                return path
        return None
    
    def load(self) -> BOFAConfig:
        """
        Cargar configuración desde todas las fuentes disponibles.
        
        Returns:
            BOFAConfig: Configuración cargada
        """
        if self._config is not None:
            return self._config
        
        # Inicializar con valores por defecto
        config = BOFAConfig()
        
        # Cargar desde archivo si existe
        if self.config_file and self.config_file.exists():
            config = self._load_from_file(self.config_file, config)
        
        # Sobrescribir con variables de entorno
        config = self._load_from_env(config)
        
        self._config = config
        return config
    
    def _load_from_file(self, config_file: Path, config: BOFAConfig) -> BOFAConfig:
        """Cargar configuración desde archivo YAML o JSON"""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                if config_file.suffix in ['.yaml', '.yml']:
                    data = yaml.safe_load(f) or {}
                elif config_file.suffix == '.json':
                    data = json.load(f)
                else:
                    return config
                
                # Aplicar configuración desde archivo
                if 'logging' in data:
                    if 'level' in data['logging']:
                        config.log_level = data['logging']['level']
                    if 'format' in data['logging']:
                        config.log_format = data['logging']['format']
                    if 'file' in data['logging']:
                        config.log_file = data['logging']['file']
                
                if 'execution' in data:
                    if 'max_concurrent' in data['execution']:
                        config.max_concurrent_executions = data['execution']['max_concurrent']
                    if 'timeout' in data['execution']:
                        config.execution_timeout = data['execution']['timeout']
                
                if 'modules' in data:
                    if 'auto_discover' in data['modules']:
                        config.auto_discover_modules = data['modules']['auto_discover']
                
                if 'security' in data:
                    if 'sandbox_enabled' in data['security']:
                        config.sandbox_enabled = data['security']['sandbox_enabled']
                    if 'require_authorization' in data['security']:
                        config.require_authorization = data['security']['require_authorization']
                
        except Exception as e:
            # Si hay error, usar valores por defecto
            import warnings
            warnings.warn(f"No se pudo cargar configuración desde {config_file}: {e}")
        
        return config
    
    def _load_from_env(self, config: BOFAConfig) -> BOFAConfig:
        """Cargar configuración desde variables de entorno"""
        # Logging
        if os.getenv("BOFA_LOG_LEVEL"):
            config.log_level = os.getenv("BOFA_LOG_LEVEL", config.log_level)
        if os.getenv("BOFA_LOG_FORMAT"):
            config.log_format = os.getenv("BOFA_LOG_FORMAT", config.log_format)
        if os.getenv("BOFA_LOG_FILE"):
            config.log_file = os.getenv("BOFA_LOG_FILE")
        
        # Ejecución
        if os.getenv("BOFA_MAX_CONCURRENT"):
            config.max_concurrent_executions = int(os.getenv("BOFA_MAX_CONCURRENT", config.max_concurrent_executions))
        if os.getenv("BOFA_EXECUTION_TIMEOUT"):
            config.execution_timeout = int(os.getenv("BOFA_EXECUTION_TIMEOUT", config.execution_timeout))
        
        # Seguridad
        if os.getenv("BOFA_SANDBOX_ENABLED"):
            config.sandbox_enabled = os.getenv("BOFA_SANDBOX_ENABLED", "true").lower() == "true"
        if os.getenv("BOFA_REQUIRE_AUTH"):
            config.require_authorization = os.getenv("BOFA_REQUIRE_AUTH", "false").lower() == "true"
        
        # Rutas
        if os.getenv("BOFA_BASE_PATH"):
            config.base_path = Path(os.getenv("BOFA_BASE_PATH"))
            config.__post_init__()  # Re-inicializar rutas
        
        return config
    
    def get(self) -> BOFAConfig:
        """Obtener configuración actual"""
        return self.load()
    
    def reload(self) -> BOFAConfig:
        """Recargar configuración desde las fuentes"""
        self._config = None
        return self.load()


# Instancia global del gestor de configuración
_config_manager: Optional[ConfigManager] = None


def get_config() -> BOFAConfig:
    """
    Obtener la configuración global de BOFA.
    
    Returns:
        BOFAConfig: Configuración actual
    """
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager.get()
