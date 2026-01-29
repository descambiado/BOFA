"""
BOFAEngine - Motor Central de BOFA
==================================

Motor central que gestiona módulos, scripts y ejecuciones.
"""

import subprocess
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from datetime import datetime

from ..config import get_config
from ..logger import get_logger
from ..errors import (
    ModuleNotFoundError,
    ScriptNotFoundError,
    ExecutionError,
    ValidationError,
)
from ..utils import ModuleLoader, ScriptValidator, get_script_path

logger = get_logger(__name__)


@dataclass
class ExecutionResult:
    """Resultado de una ejecución de script"""
    execution_id: str
    script_name: str
    module_name: str
    status: str  # success, error, timeout
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    duration: float = 0.0
    timestamp: str = ""
    error: Optional[str] = None
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat()


class BOFAEngine:
    """
    Motor central de BOFA.
    
    Gestiona:
    - Carga de módulos y scripts
    - Validación de scripts
    - Ejecución de scripts
    - Gestión de resultados
    """
    
    def __init__(self, config=None):
        """
        Inicializar el motor de BOFA.
        
        Args:
            config: Configuración de BOFA (opcional)
        """
        self.config = config or get_config()
        self.module_loader = ModuleLoader(self.config.base_path)
        self._modules: Dict[str, Any] = {}
        self._initialized = False
        logger.info("BOFA Engine inicializado", base_path=str(self.config.base_path))
    
    def initialize(self) -> None:
        """
        Inicializar el motor y cargar módulos.
        
        Raises:
            ConfigurationError: Si hay problemas de configuración
        """
        if self._initialized:
            return
        
        try:
            if self.config.auto_discover_modules:
                logger.info("Descubriendo módulos...")
                self._modules = self.module_loader.discover_modules()
                logger.info(
                    f"Módulos cargados: {len(self._modules)}",
                    modules=list(self._modules.keys())
                )
            self._initialized = True
        except Exception as e:
            logger.error(f"Error inicializando motor: {e}")
            raise
    
    
    def get_module(self, module_name: str) -> Any:
        """
        Obtener información de un módulo.
        
        Args:
            module_name: Nombre del módulo
            
        Returns:
            Información del módulo
            
        Raises:
            ModuleNotFoundError: Si el módulo no existe
        """
        return self.module_loader.get_module(module_name)
    
    def get_script(self, module_name: str, script_name: str) -> Any:
        """
        Obtener información de un script.
        
        Args:
            module_name: Nombre del módulo
            script_name: Nombre del script
            
        Returns:
            Información del script
            
        Raises:
            ScriptNotFoundError: Si el script no existe
        """
        return self.module_loader.get_script(module_name, script_name)
    
    def list_modules(self) -> List[str]:
        """
        Listar nombres de módulos disponibles.
        
        Returns:
            Lista de nombres de módulos
        """
        if not self._modules:
            self.initialize()
        
        return self.module_loader.list_modules()
    
    def list_scripts(self, module_name: Optional[str] = None) -> Dict[str, List[str]]:
        """
        Listar scripts disponibles.
        
        Args:
            module_name: Si se especifica, solo scripts de ese módulo
            
        Returns:
            Dict con módulo -> lista de scripts
        """
        return self.module_loader.list_scripts(module_name)
    
    def validate_script(
        self,
        module_name: str,
        script_name: str,
        parameters: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Validar que un script existe y sus parámetros son correctos.
        
        Args:
            module_name: Nombre del módulo
            script_name: Nombre del script
            parameters: Parámetros a validar (opcional)
            
        Returns:
            True si es válido
            
        Raises:
            ScriptNotFoundError: Si el script no existe
            ValidationError: Si los parámetros son inválidos
        """
        script_info = self.get_script(module_name, script_name)
        script_path = get_script_path(
            self.config.base_path,
            module_name,
            script_name
        )
        
        validator = ScriptValidator(script_path)
        
        expected_params = script_info.parameters
        validator.validate_all(parameters, expected_params)
        
        logger.debug(
            f"Script validado: {module_name}/{script_name}",
            module=module_name,
            script=script_name
        )
        
        return True
    
    def execute_script(
        self,
        module_name: str,
        script_name: str,
        parameters: Optional[Dict[str, Any]] = None,
        execution_id: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> ExecutionResult:
        """
        Ejecutar un script.
        
        Args:
            module_name: Nombre del módulo
            script_name: Nombre del script
            parameters: Parámetros del script
            execution_id: ID único de ejecución (opcional)
            timeout: Timeout en segundos (opcional)
            
        Returns:
            ExecutionResult: Resultado de la ejecución
            
        Raises:
            ScriptNotFoundError: Si el script no existe
            ExecutionError: Si hay error durante la ejecución
        """
        import uuid
        
        execution_id = execution_id or str(uuid.uuid4())
        parameters = parameters or {}
        timeout = timeout or self.config.execution_timeout
        
        logger.info(
            f"Ejecutando script: {module_name}/{script_name}",
            execution_id=execution_id,
            module=module_name,
            script=script_name,
            parameters=parameters
        )
        
        # Validar script
        try:
            self.validate_script(module_name, script_name, parameters)
        except (ScriptNotFoundError, ValidationError) as e:
            logger.error("Validación fallida", module=module_name, script=script_name, error=str(e))
            raise
        
        # Obtener ruta del script
        script_path = get_script_path(
            self.config.base_path,
            module_name,
            script_name
        )
        
        # Construir comando
        cmd = ["python3", str(script_path)]
        for key, value in parameters.items():
            if isinstance(value, bool):
                if value:
                    cmd.append(f"--{key}")
            else:
                cmd.extend([f"--{key}", str(value)])
        
        # Ejecutar script
        start_time = datetime.utcnow()
        
        try:
            result = subprocess.run(
                cmd,
                cwd=script_path.parent,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=self._get_execution_env()
            )
            
            duration = (datetime.utcnow() - start_time).total_seconds()
            
            execution_result = ExecutionResult(
                execution_id=execution_id,
                script_name=script_name,
                module_name=module_name,
                status="success" if result.returncode == 0 else "error",
                exit_code=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                duration=duration
            )
            
            if result.returncode != 0:
                execution_result.error = result.stderr or "Script failed"
                logger.warning(
                    f"Script falló: {module_name}/{script_name}",
                    exit_code=result.returncode,
                    error=execution_result.error
                )
            else:
                logger.info(
                    f"Script ejecutado exitosamente: {module_name}/{script_name}",
                    duration=duration
                )
            
            return execution_result
            
        except subprocess.TimeoutExpired:
            duration = (datetime.utcnow() - start_time).total_seconds()
            logger.error(
                f"Timeout ejecutando script: {module_name}/{script_name}",
                timeout=timeout
            )
            raise ExecutionError(
                f"Timeout ejecutando script después de {timeout} segundos",
                script_name=script_name,
                details={"timeout": timeout, "duration": duration}
            )
        
        except Exception as e:
            duration = (datetime.utcnow() - start_time).total_seconds()
            logger.exception(
                "Error ejecutando script (traceback abajo)",
                extra={"module": module_name, "script": script_name, "error": str(e)},
            )
            raise ExecutionError(
                f"Error ejecutando script: {str(e)}",
                script_name=script_name,
                details={"error": str(e), "duration": duration}
            )
    
    def _get_execution_env(self) -> Dict[str, str]:
        """
        Obtener variables de entorno para ejecución de scripts.
        
        Returns:
            Dict con variables de entorno
        """
        import os
        
        env = os.environ.copy()
        env["BOFA_BASE_PATH"] = str(self.config.base_path)
        env["BOFA_SCRIPTS_PATH"] = str(self.config.scripts_path)
        env["BOFA_OUTPUT_PATH"] = str(self.config.output_path)
        env["BOFA_LOGS_PATH"] = str(self.config.logs_path)
        
        return env


# Instancia global del motor
_engine: Optional[BOFAEngine] = None


def get_engine(config=None) -> BOFAEngine:
    """
    Obtener la instancia global del motor de BOFA.
    
    Args:
        config: Configuración (opcional)
        
    Returns:
        BOFAEngine: Instancia del motor
    """
    global _engine
    if _engine is None:
        _engine = BOFAEngine(config)
        _engine.initialize()
    return _engine
