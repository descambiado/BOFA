"""
Excepciones Personalizadas de BOFA
==================================

Excepciones claras, con mensajes útiles y detalles para debugging.
Todas heredan de BOFAError; no se filtran trazas: el stack trace se preserva.
"""

from typing import Optional, Dict, Any


class BOFAError(Exception):
    """
    Excepción base de BOFA. Mensaje claro + código + detalles para debugging.

    Uso: raise BOFAError("descripción", error_code="XXX", details={...})
    El stack trace completo se preserva; usar str(e) para mensaje amigable.
    """

    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}

    def __str__(self) -> str:
        if self.error_code:
            return f"[{self.error_code}] {self.message}"
        return self.message

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.message!r}, code={self.error_code!r}, details={self.details})"

    def to_dict(self) -> Dict[str, Any]:
        """Para serialización (API, logs). Incluye tipo, mensaje, código y details."""
        return {
            "error": self.__class__.__name__,
            "message": self.message,
            "error_code": self.error_code,
            "details": self.details,
        }


class ConfigurationError(BOFAError):
    """Error en la configuración del framework"""
    
    def __init__(self, message: str, config_key: Optional[str] = None, **kwargs):
        super().__init__(message, error_code="CONFIG_ERROR", **kwargs)
        if config_key:
            self.details["config_key"] = config_key


class ModuleNotFoundError(BOFAError):
    """Error cuando un módulo no se encuentra"""
    
    def __init__(self, module_name: str, **kwargs):
        message = f"Módulo '{module_name}' no encontrado"
        super().__init__(message, error_code="MODULE_NOT_FOUND", **kwargs)
        self.details["module_name"] = module_name


class ScriptNotFoundError(BOFAError):
    """Error cuando un script no se encuentra"""
    
    def __init__(self, script_name: str, module_name: Optional[str] = None, **kwargs):
        if module_name:
            message = f"Script '{script_name}' no encontrado en módulo '{module_name}'"
        else:
            message = f"Script '{script_name}' no encontrado"
        super().__init__(message, error_code="SCRIPT_NOT_FOUND", **kwargs)
        self.details["script_name"] = script_name
        if module_name:
            self.details["module_name"] = module_name


class ExecutionError(BOFAError):
    """Error durante la ejecución de un script"""
    
    def __init__(
        self,
        message: str,
        script_name: Optional[str] = None,
        exit_code: Optional[int] = None,
        **kwargs
    ):
        super().__init__(message, error_code="EXECUTION_ERROR", **kwargs)
        if script_name:
            self.details["script_name"] = script_name
        if exit_code is not None:
            self.details["exit_code"] = exit_code


class ValidationError(BOFAError):
    """Error de validación de parámetros o datos"""
    
    def __init__(self, message: str, field: Optional[str] = None, **kwargs):
        super().__init__(message, error_code="VALIDATION_ERROR", **kwargs)
        if field:
            self.details["field"] = field


class SecurityError(BOFAError):
    """Error relacionado con seguridad (permisos, autorización, etc.)"""
    
    def __init__(self, message: str, reason: Optional[str] = None, **kwargs):
        super().__init__(message, error_code="SECURITY_ERROR", **kwargs)
        if reason:
            self.details["reason"] = reason
