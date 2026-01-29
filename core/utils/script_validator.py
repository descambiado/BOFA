"""
Validador de Scripts
====================

Valida scripts y sus parámetros antes de la ejecución.
"""

from pathlib import Path
from typing import Dict, Any, List, Optional

from ..errors import ValidationError, ScriptNotFoundError
from ..logger import get_logger

logger = get_logger(__name__)


class ScriptValidator:
    """
    Validador de scripts y parámetros.
    
    Valida que los scripts existan y que los parámetros sean correctos.
    """
    
    def __init__(self, script_path: Path):
        """
        Inicializar validador.
        
        Args:
            script_path: Ruta al script a validar
        """
        self.script_path = script_path
    
    def validate_exists(self) -> bool:
        """
        Validar que el script existe.
        
        Returns:
            True si existe
            
        Raises:
            ScriptNotFoundError: Si el script no existe
        """
        if not self.script_path.exists():
            raise ScriptNotFoundError(
                self.script_path.name
            )
        
        if not self.script_path.is_file():
            raise ValidationError(
                f"La ruta no es un archivo: {self.script_path}"
            )
        
        return True
    
    def validate_executable(self) -> bool:
        """
        Validar que el script es ejecutable (extensión .py o tiene shebang).
        
        Returns:
            True si es ejecutable
            
        Raises:
            ValidationError: Si no es ejecutable
        """
        # Si es .py, es válido
        if self.script_path.suffix == '.py':
            return True
        
        # Si no es .py, debe tener shebang
        try:
            with open(self.script_path, 'rb') as f:
                first_bytes = f.read(2)
                if first_bytes != b'#!':
                    raise ValidationError(
                        f"El script debe ser .py o tener shebang: {self.script_path}"
                    )
        except ValidationError:
            raise
        except Exception as e:
            raise ValidationError(f"Error validando script: {e}")
        
        return True
    
    def validate_parameters(
        self,
        parameters: Dict[str, Any],
        expected_parameters: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Validar parámetros del script.
        
        Args:
            parameters: Parámetros proporcionados
            expected_parameters: Parámetros esperados (opcional)
            
        Returns:
            True si son válidos
            
        Raises:
            ValidationError: Si los parámetros son inválidos
        """
        if expected_parameters is None:
            # Sin validación específica, aceptar todos
            return True
        
        # Validar parámetros requeridos
        required = {
            key for key, spec in expected_parameters.items()
            if spec.get('required', False)
        }
        
        missing = required - set(parameters.keys())
        if missing:
            raise ValidationError(
                f"Parámetros requeridos faltantes: {', '.join(missing)}",
                field="parameters"
            )
        
        # Mapeo tipo en YAML (string) -> tipo Python (para validación)
        _YAML_TYPE_MAP = {
            "str": str, "string": str,
            "int": int, "integer": int,
            "bool": bool, "boolean": bool,
        }

        # Validar tipos
        for key, value in parameters.items():
            if key not in expected_parameters:
                # Parámetro desconocido, permitir pero advertir
                logger.warning(f"Parámetro desconocido: {key}")
                continue

            param_spec = expected_parameters[key]
            type_hint = param_spec.get('type')
            if type_hint is None:
                continue

            # Aceptar tipo Python directo o nombre en YAML (str/int/bool)
            if isinstance(type_hint, type):
                expected_type = type_hint
            else:
                expected_type = _YAML_TYPE_MAP.get(
                    (type_hint if isinstance(type_hint, str) else str(type_hint)).lower()
                )

            if expected_type is not None and not isinstance(value, expected_type):
                type_name = getattr(expected_type, '__name__', str(expected_type))
                raise ValidationError(
                    f"Parámetro '{key}' debe ser de tipo {type_name}, "
                    f"recibido {type(value).__name__}",
                    field=key
                )
        return True
    
    def validate_all(
        self,
        parameters: Optional[Dict[str, Any]] = None,
        expected_parameters: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Validar todo: existencia, ejecutabilidad y parámetros.
        
        Args:
            parameters: Parámetros a validar (opcional)
            expected_parameters: Parámetros esperados (opcional)
            
        Returns:
            True si todo es válido
        """
        self.validate_exists()
        self.validate_executable()
        
        if parameters is not None:
            self.validate_parameters(parameters, expected_parameters)
        
        return True
