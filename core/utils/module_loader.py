"""
Cargador de Módulos
===================

Carga y gestiona módulos y scripts de BOFA.
"""

import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from ..config import get_config
from ..errors import ModuleNotFoundError, ScriptNotFoundError
from ..logger import get_logger

logger = get_logger(__name__)


@dataclass
class ScriptInfo:
    """Información sobre un script"""
    name: str
    file: str
    module: str
    description: str = ""
    author: str = ""
    version: str = ""
    parameters: Dict[str, Any] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.parameters is None:
            self.parameters = {}
        if self.metadata is None:
            self.metadata = {}


@dataclass
class ModuleInfo:
    """Información sobre un módulo"""
    name: str
    path: Path
    description: str = ""
    scripts: List[ScriptInfo] = None
    
    def __post_init__(self):
        if self.scripts is None:
            self.scripts = []


class ModuleLoader:
    """
    Cargador de módulos y scripts de BOFA.
    
    Descubre y carga módulos automáticamente desde el directorio de scripts.
    """
    
    def __init__(self, base_path: Optional[Path] = None):
        """
        Inicializar cargador de módulos.
        
        Args:
            base_path: Ruta base del proyecto (opcional)
        """
        self.base_path = base_path or get_config().base_path
        self.scripts_path = self.base_path / "scripts"
        self._modules: Dict[str, ModuleInfo] = {}
    
    def discover_modules(self) -> Dict[str, ModuleInfo]:
        """
        Descubrir todos los módulos disponibles.
        
        Returns:
            Dict con nombre de módulo -> ModuleInfo
        """
        if not self.scripts_path.exists():
            logger.warning(f"Directorio de scripts no encontrado: {self.scripts_path}")
            return {}
        
        modules = {}
        
        for module_dir in self.scripts_path.iterdir():
            if not module_dir.is_dir():
                continue
            
            # Ignorar directorios que empiezan con punto
            if module_dir.name.startswith('.'):
                continue
            
            try:
                module_info = self._load_module(module_dir)
                modules[module_info.name] = module_info
            except Exception as e:
                logger.error(f"Error cargando módulo {module_dir.name}: {e}")
        
        self._modules = modules
        logger.info(f"Descubiertos {len(modules)} módulos")
        return modules
    
    def _load_module(self, module_path: Path) -> ModuleInfo:
        """
        Cargar información de un módulo.
        
        Args:
            module_path: Ruta al directorio del módulo
            
        Returns:
            ModuleInfo: Información del módulo
        """
        module_name = module_path.name
        
        # Buscar metadata.yaml si existe
        metadata_file = module_path / "metadata.yaml"
        description = ""
        
        if metadata_file.exists():
            try:
                with open(metadata_file, 'r', encoding='utf-8') as f:
                    metadata = yaml.safe_load(f) or {}
                    description = metadata.get('description', '')
            except Exception as e:
                logger.warning(f"Error leyendo metadata de {module_name}: {e}")
        
        # Cargar scripts
        scripts = []
        for script_file in module_path.glob("*.py"):
            if script_file.name.startswith('_'):
                continue
            
            try:
                script_info = self._load_script_info(module_name, script_file)
                scripts.append(script_info)
            except Exception as e:
                logger.warning(f"Error cargando script {script_file.name}: {e}")
        
        return ModuleInfo(
            name=module_name,
            path=module_path,
            description=description,
            scripts=scripts
        )
    
    def _load_script_info(self, module_name: str, script_path: Path) -> ScriptInfo:
        """
        Cargar información de un script desde su archivo YAML.
        
        Args:
            module_name: Nombre del módulo
            script_path: Ruta al script Python
            
        Returns:
            ScriptInfo: Información del script
        """
        script_name = script_path.stem
        
        # Buscar archivo YAML de configuración
        config_file = script_path.parent / f"{script_name}.yaml"
        
        metadata = {}
        description = ""
        author = ""
        version = ""
        parameters = {}
        
        if config_file.exists():
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    config = yaml.safe_load(f) or {}
                    metadata = config
                    description = config.get('description', '')
                    author = config.get('author', '')
                    version = config.get('version', '')
                    parameters = config.get('parameters', {})
                    # Normalizar: algunos YAML usan parameters como lista [{name: x, ...}]
                    if isinstance(parameters, list):
                        _params = {}
                        for p in parameters:
                            if isinstance(p, dict) and 'name' in p:
                                spec = dict(p)
                                name = spec.pop('name')
                                _params[name] = spec
                            elif isinstance(p, dict):
                                _params[p.get('name', 'param')] = dict(p)
                        parameters = _params
            except Exception as e:
                logger.warning(f"Error leyendo configuración de {script_name}: {e}")
        
        return ScriptInfo(
            name=script_name,
            file=script_path.name,
            module=module_name,
            description=description,
            author=author,
            version=version,
            parameters=parameters,
            metadata=metadata
        )
    
    def get_module(self, module_name: str) -> ModuleInfo:
        """
        Obtener información de un módulo.
        
        Args:
            module_name: Nombre del módulo
            
        Returns:
            ModuleInfo: Información del módulo
            
        Raises:
            ModuleNotFoundError: Si el módulo no existe
        """
        if not self._modules:
            self.discover_modules()
        
        if module_name not in self._modules:
            raise ModuleNotFoundError(module_name)
        
        return self._modules[module_name]
    
    def get_script(self, module_name: str, script_name: str) -> ScriptInfo:
        """
        Obtener información de un script.
        
        Args:
            module_name: Nombre del módulo
            script_name: Nombre del script
            
        Returns:
            ScriptInfo: Información del script
            
        Raises:
            ScriptNotFoundError: Si el script no existe
        """
        module = self.get_module(module_name)
        
        for script in module.scripts:
            if script.name == script_name:
                return script
        
        raise ScriptNotFoundError(script_name, module_name)
    
    def list_modules(self) -> List[str]:
        """
        Listar nombres de todos los módulos disponibles.
        
        Returns:
            Lista de nombres de módulos
        """
        if not self._modules:
            self.discover_modules()
        
        return list(self._modules.keys())
    
    def list_scripts(self, module_name: Optional[str] = None) -> Dict[str, List[str]]:
        """
        Listar scripts disponibles.
        
        Args:
            module_name: Si se especifica, solo scripts de ese módulo
            
        Returns:
            Dict con módulo -> lista de scripts
        """
        if not self._modules:
            self.discover_modules()
        
        if module_name:
            module = self.get_module(module_name)
            return {module_name: [s.name for s in module.scripts]}
        
        result = {}
        for module_name, module_info in self._modules.items():
            result[module_name] = [s.name for s in module_info.scripts]
        
        return result


def load_module_config(module_name: str, base_path: Optional[Path] = None) -> ModuleInfo:
    """
    Función de conveniencia para cargar un módulo.
    
    Args:
        module_name: Nombre del módulo
        base_path: Ruta base (opcional)
        
    Returns:
        ModuleInfo: Información del módulo
    """
    loader = ModuleLoader(base_path)
    return loader.get_module(module_name)
