# 📖 Guía de Uso del Core de BOFA

Uso del **engine**, **config**, **logger** y **errors** desde código o desde la CLI. Todo lo que hace la CLI (descubrir módulos, ejecutar scripts) está en el core.

## Inicio Rápido

### Uso Básico del Engine

```python
from core.engine import get_engine
from core.logger import setup_logging, get_logger

# Configurar logging
setup_logging()

# Obtener el engine
engine = get_engine()

# Listar módulos disponibles
modules = engine.list_modules()
print(f"Módulos disponibles: {modules}")

# Listar scripts de un módulo
scripts = engine.list_scripts("blue")
print(f"Scripts en blue: {scripts['blue']}")

# Ejecutar un script
result = engine.execute_script(
    module_name="blue",
    script_name="log_guardian",
    parameters={"f": "/var/log/auth.log"}
)

print(f"Estado: {result.status}")
print(f"Salida: {result.stdout}")
```

### Configuración

#### Usando Archivo de Configuración

Crea `config/bofa.yaml`:

```yaml
logging:
  level: DEBUG
  format: json
  file: bofa.log

execution:
  max_concurrent: 10
  timeout: 7200

security:
  sandbox_enabled: true
```

#### Usando Variables de Entorno

```bash
export BOFA_LOG_LEVEL=DEBUG
export BOFA_LOG_FORMAT=json
export BOFA_MAX_CONCURRENT=10
export BOFA_EXECUTION_TIMEOUT=7200
```

### Logging

```python
from core.logger import get_logger

logger = get_logger(__name__)

# Diferentes niveles
logger.debug("Información de depuración")
logger.info("Operación completada", module="blue", script="log_guardian")
logger.warning("Advertencia", issue="timeout")
logger.error("Error ejecutando script", error=str(e))
logger.critical("Error crítico", system="down")

# Con contexto
logger.set_context(user="admin", session="abc123")
logger.info("Usuario autenticado")  # Incluirá contexto automáticamente
```

### Manejo de Errores

```python
from core.engine import get_engine
from core.errors import (
    ModuleNotFoundError,
    ScriptNotFoundError,
    ExecutionError,
    ValidationError,
)

engine = get_engine()

try:
    result = engine.execute_script("blue", "log_guardian", {"-f": "/var/log/auth.log"})
except ModuleNotFoundError as e:
    print(f"Módulo no encontrado: {e}")
except ScriptNotFoundError as e:
    print(f"Script no encontrado: {e}")
except ValidationError as e:
    print(f"Error de validación: {e.details}")
except ExecutionError as e:
    print(f"Error ejecutando: {e}")
    print(f"Detalles: {e.details}")
```

### Cargar Información de Módulos

```python
from core.engine import get_engine

engine = get_engine()

# Obtener información de un módulo
module = engine.get_module("blue")
print(f"Descripción: {module.description}")
print(f"Scripts: {[s.name for s in module.scripts]}")

# Obtener información de un script
script = engine.get_script("blue", "log_guardian")
print(f"Descripción: {script.description}")
print(f"Parámetros: {script.parameters}")
```

### Validar Scripts

```python
from core.engine import get_engine

engine = get_engine()

# Validar que un script existe y sus parámetros son correctos
try:
    engine.validate_script(
        module_name="blue",
        script_name="log_guardian",
        parameters={"f": "/var/log/auth.log"}
    )
    print("✅ Script válido")
except ValidationError as e:
    print(f"❌ Error de validación: {e}")
```

## Ejemplos Avanzados

### Crear un Script Personalizado que Use el Core

```python
#!/usr/bin/env python3
"""
Mi Script Personalizado
"""
import sys
from pathlib import Path

# Añadir el directorio raíz al path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.engine import get_engine
from core.logger import get_logger
from core.errors import BOFAError

logger = get_logger(__name__)

def main():
    engine = get_engine()
    
    # Listar todos los módulos y scripts
    modules = engine.list_modules()
    
    for module_name in modules:
        logger.info(f"Procesando módulo: {module_name}")
        scripts = engine.list_scripts(module_name)
        
        for script_name in scripts[module_name]:
            try:
                script_info = engine.get_script(module_name, script_name)
                logger.info(
                    f"Script encontrado: {module_name}/{script_name}",
                    description=script_info.description
                )
            except BOFAError as e:
                logger.error(f"Error obteniendo script: {e}")

if __name__ == "__main__":
    main()
```

### Integración con API

```python
from fastapi import FastAPI, HTTPException
from core.engine import get_engine
from core.errors import BOFAError

app = FastAPI()
engine = get_engine()

@app.post("/execute")
async def execute_script(module: str, script: str, parameters: dict):
    try:
        result = engine.execute_script(module, script, parameters)
        return {
            "status": result.status,
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    except BOFAError as e:
        raise HTTPException(status_code=400, detail=str(e))
```

## Mejores Prácticas

1. **Siempre inicializa el logging**: `setup_logging()` al inicio
2. **Usa el engine global**: `get_engine()` en lugar de crear nuevas instancias
3. **Maneja errores apropiadamente**: Captura excepciones específicas de BOFA
4. **Añade contexto al logging**: Facilita el debugging
5. **Valida antes de ejecutar**: Usa `validate_script()` cuando sea posible

## Troubleshooting

### El engine no encuentra módulos

- Verifica que `scripts/` existe y tiene la estructura correcta
- Revisa los logs para ver errores de carga
- Asegúrate de que los archivos YAML están bien formateados

### Errores de importación

- Asegúrate de que el directorio raíz está en `sys.path`
- Verifica que todas las dependencias están instaladas

### Scripts no se ejecutan

- Verifica permisos de ejecución
- Revisa que Python 3 está disponible
- Comprueba los logs para errores específicos
