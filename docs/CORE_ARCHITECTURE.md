# 🏗️ Arquitectura del Core de BOFA

El **core** es la base estable del framework: descubre módulos en `scripts/`, valida y ejecuta scripts, gestiona configuración y logging. La CLI y la API son solo capas sobre el core; no contienen lógica de negocio.

## Visión General

El core está diseñado para ser:

- **Modular**: Componentes independientes y reutilizables
- **Extensible**: Fácil de extender con nuevas funcionalidades
- **Mantenible**: Código limpio y bien documentado
- **Confiable**: Manejo robusto de errores y logging estructurado

## Estructura del Core

```
core/
├── __init__.py          # Inicialización del módulo core
├── engine/              # Motor central de ejecución
│   ├── __init__.py
│   └── engine.py        # BOFAEngine - Motor principal
├── config/              # Sistema de configuración
│   ├── __init__.py
│   └── config_manager.py # ConfigManager - Gestor de configuración
├── logger/             # Sistema de logging
│   ├── __init__.py
│   └── logger.py        # BOFALogger - Logger estructurado
├── errors/              # Manejo de errores
│   ├── __init__.py
│   └── exceptions.py    # Excepciones personalizadas
└── utils/              # Utilidades compartidas
    ├── __init__.py
    ├── module_loader.py  # Cargador de módulos
    ├── script_validator.py # Validador de scripts
    └── path_utils.py     # Utilidades de rutas
```

## Componentes Principales

### 1. Core Engine (`core/engine/`)

El motor central que gestiona:

- **Carga de módulos**: Descubrimiento automático de módulos y scripts
- **Validación**: Validación de scripts y parámetros antes de ejecutar
- **Ejecución**: Ejecución controlada de scripts con manejo de errores
- **Resultados**: Gestión de resultados de ejecución

**Uso básico:**

```python
from core.engine import get_engine

engine = get_engine()
modules = engine.list_modules()
result = engine.execute_script("blue", "log_guardian", {"-f": "/var/log/auth.log"})
```

### 2. Sistema de Configuración (`core/config/`)

Gestión centralizada de configuración desde múltiples fuentes:

1. Variables de entorno (prioridad más alta)
2. Archivo de configuración (`config/bofa.yaml`)
3. Valores por defecto

**Uso básico:**

```python
from core.config import get_config

config = get_config()
print(config.log_level)  # INFO
print(config.base_path)  # Path al directorio base
```

**Variables de entorno:**

```bash
export BOFA_LOG_LEVEL=DEBUG
export BOFA_LOG_FORMAT=json
export BOFA_MAX_CONCURRENT=10
```

### 3. Sistema de Logging (`core/logger/`)

Logging estructurado con soporte para:

- Formato JSON (para análisis)
- Formato de texto legible (para desarrollo)
- Colores en consola
- Archivos rotativos
- Contexto adicional

**Uso básico:**

```python
from core.logger import get_logger

logger = get_logger(__name__)
logger.info("Script ejecutado", module="blue", script="log_guardian")
logger.error("Error ejecutando script", error=str(e))
```

### 4. Manejo de Errores (`core/errors/`)

Excepciones personalizadas para manejo consistente:

- `BOFAError`: Excepción base
- `ConfigurationError`: Errores de configuración
- `ModuleNotFoundError`: Módulo no encontrado
- `ScriptNotFoundError`: Script no encontrado
- `ExecutionError`: Errores durante ejecución
- `ValidationError`: Errores de validación
- `SecurityError`: Errores de seguridad

**Uso básico:**

```python
from core.errors import ScriptNotFoundError, ExecutionError

try:
    engine.execute_script("blue", "invalid_script")
except ScriptNotFoundError as e:
    print(f"Script no encontrado: {e}")
except ExecutionError as e:
    print(f"Error ejecutando: {e}")
```

### 5. Utilidades (`core/utils/`)

Funciones y clases utilitarias:

- **ModuleLoader**: Carga y descubre módulos
- **ScriptValidator**: Valida scripts y parámetros
- **path_utils**: Utilidades de rutas

## Flujo de Ejecución

```
1. Inicialización
   └─> ConfigManager carga configuración
   └─> BOFALogger se configura
   └─> BOFAEngine se inicializa

2. Descubrimiento de Módulos
   └─> ModuleLoader escanea scripts/
   └─> Carga metadata.yaml de cada módulo
   └─> Carga script.yaml de cada script

3. Ejecución de Script
   └─> Validar que el script existe
   └─> Validar parámetros
   └─> Ejecutar script
   └─> Capturar resultado
   └─> Registrar en log
```

## Crear un Nuevo Módulo

1. Crear directorio en `scripts/`:

```bash
mkdir scripts/mi_modulo
```

2. Crear script Python:

```python
#!/usr/bin/env python3
"""
Mi Script - Descripción
"""
import argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    # ... código del script

if __name__ == "__main__":
    main()
```

3. Crear archivo YAML de configuración:

```yaml
name: mi_script
description: Descripción del script
author: @tu_usuario
version: 1.0.0
parameters:
  target:
    type: str
    required: true
    description: Target a analizar
```

4. El módulo será descubierto automáticamente por el engine.

## Mejores Prácticas

### Logging

- Usa niveles apropiados: DEBUG para desarrollo, INFO para operaciones normales
- Añade contexto relevante: `logger.info("Script ejecutado", module="blue", script="log_guardian")`
- No loguees información sensible

### Manejo de Errores

- Usa excepciones específicas de BOFA
- Proporciona mensajes descriptivos
- Añade detalles útiles en `details`

### Configuración

- Usa variables de entorno para configuración sensible
- Documenta todas las opciones de configuración
- Proporciona valores por defecto razonables

### Scripts

- Siempre incluye un archivo YAML de configuración
- Documenta todos los parámetros
- Usa argparse para parámetros de línea de comandos
- Retorna códigos de salida apropiados (0 = éxito, != 0 = error)

## Extensión del Core

Para extender el core:

1. **Nuevos componentes**: Añade nuevos módulos en `core/`
2. **Nuevas excepciones**: Extiende `BOFAError` en `core/errors/`
3. **Nuevas utilidades**: Añade funciones en `core/utils/`
4. **Nuevas funcionalidades del engine**: Extiende `BOFAEngine`

## Testing

El core está diseñado para ser testeable:

```python
from core.engine import BOFAEngine
from core.config import BOFAConfig

# Configuración de test
test_config = BOFAConfig(base_path=Path("/test/path"))
engine = BOFAEngine(test_config)
```

## Documentación Adicional

- [Guía de Instalación](INSTALLATION.md)
- [Guía de Uso](USAGE.md)
- [API Reference](API.md)
