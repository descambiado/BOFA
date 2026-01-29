"""
BOFALogger - Sistema de Logging Estructurado
============================================

Proporciona logging estructurado y consistente para todo el framework.
"""

import logging
import json
import sys
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime

from ..config import get_config


class JSONFormatter(logging.Formatter):
    """Formateador JSON para logs estructurados"""
    
    def format(self, record: logging.LogRecord) -> str:
        """Formatear registro como JSON"""
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        # Añadir contexto adicional si existe
        if hasattr(record, "context"):
            log_data["context"] = record.context
        
        # Añadir excepción si existe
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        return json.dumps(log_data, ensure_ascii=False)


class TextFormatter(logging.Formatter):
    """Formateador de texto legible para logs"""
    
    def __init__(self):
        super().__init__(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )


class BOFAConsoleHandler(logging.StreamHandler):
    """Handler con colores para consola"""
    
    # Colores ANSI
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
        'RESET': '\033[0m',
    }
    
    def emit(self, record: logging.LogRecord):
        """Emitir log con colores si es TTY"""
        if sys.stdout.isatty():
            level = record.levelname
            color = self.COLORS.get(level, self.COLORS['RESET'])
            reset = self.COLORS['RESET']
            
            # Aplicar color al nivel
            record.levelname = f"{color}{level}{reset}"
        
        super().emit(record)


class BOFALogger:
    """
    Logger estructurado para BOFA.
    
    Proporciona logging consistente con soporte para:
    - Formato JSON estructurado
    - Formato de texto legible
    - Colores en consola
    - Archivos de log rotativos
    - Contexto adicional
    """
    
    _loggers: Dict[str, 'BOFALogger'] = {}
    _initialized = False
    
    def __init__(self, name: str):
        """
        Inicializar logger.
        
        Args:
            name: Nombre del logger (típicamente __name__)
        """
        self.name = name
        self._logger = logging.getLogger(name)
        self._context: Dict[str, Any] = {}
    
    @classmethod
    def setup(cls, config=None):
        """
        Configurar el sistema de logging global.
        
        Args:
            config: Configuración de BOFA (opcional)
        """
        if cls._initialized:
            return
        
        if config is None:
            from ..config import get_config
            config = get_config()
        
        # Configurar nivel de log
        log_level = getattr(logging, config.log_level.upper(), logging.INFO)
        root_logger = logging.getLogger()
        root_logger.setLevel(log_level)
        
        # Limpiar handlers existentes
        root_logger.handlers.clear()
        
        # Handler para consola
        console_handler = BOFAConsoleHandler(sys.stdout)
        console_handler.setLevel(log_level)
        
        if config.log_format == "json":
            console_formatter = JSONFormatter()
        else:
            console_formatter = TextFormatter()
        
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)
        
        # Handler para archivo si está configurado
        if config.log_file:
            log_path = Path(config.log_file)
            if not log_path.is_absolute():
                log_path = config.logs_path / log_path
            
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            from logging.handlers import RotatingFileHandler
            file_handler = RotatingFileHandler(
                log_path,
                maxBytes=10 * 1024 * 1024,  # 10MB
                backupCount=5
            )
            file_handler.setLevel(log_level)
            file_handler.setFormatter(JSONFormatter())
            root_logger.addHandler(file_handler)
        
        cls._initialized = True
    
    def debug(self, message: str, **context):
        """Log nivel DEBUG"""
        self._log(logging.DEBUG, message, **context)
    
    def info(self, message: str, **context):
        """Log nivel INFO"""
        self._log(logging.INFO, message, **context)
    
    def warning(self, message: str, **context):
        """Log nivel WARNING"""
        self._log(logging.WARNING, message, **context)
    
    def error(self, message: str, **context):
        """Log nivel ERROR"""
        self._log(logging.ERROR, message, **context)

    def exception(self, message: str, **context):
        """Log nivel ERROR + traceback de la excepción actual (para debugging)."""
        full_context = {**self._context, **context}
        extra = {"context": full_context} if full_context else {}
        self._logger.exception(message, extra=extra)

    def critical(self, message: str, **context):
        """Log nivel CRITICAL"""
        self._log(logging.CRITICAL, message, **context)
    
    def _log(self, level: int, message: str, **context):
        """Log interno con contexto"""
        # Combinar contexto global con contexto local
        full_context = {**self._context, **context}
        
        # Crear registro con contexto
        extra = {}
        if full_context:
            extra["context"] = full_context
        
        self._logger.log(level, message, extra=extra)
    
    def set_context(self, **context):
        """
        Establecer contexto global para este logger.
        
        Args:
            **context: Pares clave-valor de contexto
        """
        self._context.update(context)
    
    def clear_context(self):
        """Limpiar contexto global"""
        self._context.clear()
    
    def with_context(self, **context):
        """
        Crear un nuevo logger con contexto adicional.
        
        Args:
            **context: Contexto adicional
            
        Returns:
            BOFALogger: Nuevo logger con contexto
        """
        new_logger = BOFALogger(self.name)
        new_logger._context = {**self._context, **context}
        return new_logger


def get_logger(name: str) -> BOFALogger:
    """
    Obtener un logger para el módulo especificado.
    
    Args:
        name: Nombre del módulo (típicamente __name__)
        
    Returns:
        BOFALogger: Logger configurado
    """
    # Asegurar que el sistema está inicializado
    if not BOFALogger._initialized:
        BOFALogger.setup()
    
    # Retornar logger existente o crear uno nuevo
    if name not in BOFALogger._loggers:
        BOFALogger._loggers[name] = BOFALogger(name)
    
    return BOFALogger._loggers[name]


def setup_logging(config=None):
    """
    Configurar el sistema de logging.
    
    Args:
        config: Configuración de BOFA (opcional)
    """
    BOFALogger.setup(config)
