# Contrato entre Core y Modulos

Este documento define explícitamente los contratos entre el core de BOFA y los módulos. Estos contratos garantizan que un módulo nuevo puede crearse **sin modificar el core**.

## 🔄 Contrato 1: Qué Espera el Core de un Módulo

### Estructura de Directorios

El core espera que los módulos sigan esta estructura:

```
scripts/
└── <module_name>/          # Nombre del módulo (directorio)
    ├── metadata.yaml       # Opcional: metadata del módulo
    ├── script1.py          # Script Python
    ├── script1.yaml        # Opcional: configuración del script
    ├── script2.py
    └── script2.yaml
```

**Reglas**:
- El nombre del módulo es el nombre del directorio
- Los directorios que empiezan con `.` son ignorados
- Solo se cargan archivos `.py` (los que empiezan con `_` se ignoran)
- Los archivos `.yaml` son opcionales pero recomendados

### Formato de `metadata.yaml` (Opcional)

```yaml
description: "Descripción del módulo"
author: "@autor"           # Opcional
version: "1.0.0"          # Opcional
```

**Campos soportados**:
- `description` (string): Descripción del módulo
- `author` (string, opcional): Autor del módulo
- `version` (string, opcional): Versión del módulo

**Nota**: El core solo lee `description`. Los demás campos son para documentación.

### Formato de `script.yaml` (Opcional pero Recomendado)

```yaml
name: script_name          # Debe coincidir con el nombre del archivo .py
description: "Descripción del script"
author: "@autor"          # Opcional
version: "1.0.0"         # Opcional
parameters:               # Opcional: especificación de parámetros
  target:
    type: str            # str, int, bool
    required: true       # true/false
    default: null        # Valor por defecto (opcional)
    description: "Target a analizar"
  timeout:
    type: int
    required: false
    default: 30
    description: "Timeout en segundos"
  verbose:
    type: bool
    required: false
    default: false
    description: "Modo verbose"
```

**Campos soportados por el core**:
- `name` (string): Nombre del script (debe coincidir con el archivo .py)
- `description` (string): Descripción del script
- `author` (string, opcional): Autor
- `version` (string, opcional): Versión
- `parameters` (dict, opcional): Especificación de parámetros

**Campos adicionales**: El core ignora campos adicionales, pero pueden usarse para documentación.

### Requisitos del Script Python

El script debe:

1. **Ser ejecutable con Python 3**:
   ```python
   #!/usr/bin/env python3
   ```

2. **Aceptar parámetros por línea de comandos** usando **argumentos opcionales** (`--key`), no posicionales:
   - El core siempre pasa parámetros como `--key value` o `--key` (para bool).
   - Si el script usa `parser.add_argument("target", ...)` (posicional), el core no puede pasar `target` correctamente y la ejecución falla.
   - **Recomendado**: definir todos los parámetros como opcionales con `--key`.
   ```python
   import argparse
   
   parser = argparse.ArgumentParser()
   parser.add_argument("--target", required=True)
   parser.add_argument("--timeout", type=int, default=30)
   parser.add_argument("--verbose", action="store_true")
   args = parser.parse_args()
   ```
   Ver [Estado y roadmap](NEXT_STEPS_AND_ROADMAP.md) para la migración de scripts que usan argumentos posicionales.

3. **Retornar códigos de salida apropiados**:
   - `0`: Éxito
   - `!= 0`: Error

4. **Usar variables de entorno del core** (opcional pero recomendado):
   ```python
   import os
   
   output_path = os.getenv("BOFA_OUTPUT_PATH", "./output")
   base_path = os.getenv("BOFA_BASE_PATH", ".")
   ```

### Cómo el Core Pasa Parámetros

El core construye la línea de comandos así:

- **Parámetros string/int**: `--key value`
- **Parámetros bool=True**: `--key` (solo el flag)
- **Parámetros bool=False**: No se añade nada

**Ejemplo**:
```python
parameters = {
    "target": "example.com",
    "timeout": 30,
    "verbose": True
}
```

Se convierte en:
```bash
python3 script.py --target example.com --timeout 30 --verbose
```

### Variables de Entorno Proporcionadas por el Core

El core establece estas variables de entorno antes de ejecutar un script:

- `BOFA_BASE_PATH`: Ruta base del proyecto
- `BOFA_SCRIPTS_PATH`: Ruta al directorio de scripts
- `BOFA_OUTPUT_PATH`: Ruta al directorio de salida
- `BOFA_LOGS_PATH`: Ruta al directorio de logs

## 🔄 Contrato 2: Qué Puede Esperar un Módulo del Core

### Interfaz del Engine

Un módulo puede esperar que el core proporcione:

```python
from core.engine import get_engine

engine = get_engine()

# Listar módulos
modules = engine.list_modules()

# Obtener información de un módulo
module = engine.get_module("module_name")

# Obtener información de un script
script = engine.get_script("module_name", "script_name")

# Listar scripts
scripts = engine.list_scripts("module_name")

# Validar un script
engine.validate_script("module_name", "script_name", parameters={...})

# Ejecutar un script
result = engine.execute_script(
    module_name="module_name",
    script_name="script_name",
    parameters={"target": "example.com", "verbose": True},
    timeout=300
)
```

**Nota importante**: Los parámetros en `execute_script()` deben pasarse **sin el prefijo `--`**. El core añade automáticamente los `--`.

### Información Disponible

El core proporciona objetos estructurados:

**ModuleInfo**:
```python
@dataclass
class ModuleInfo:
    name: str
    path: Path
    description: str = ""
    scripts: List[ScriptInfo] = []
```

**ScriptInfo**:
```python
@dataclass
class ScriptInfo:
    name: str
    file: str
    module: str
    description: str = ""
    author: str = ""
    version: str = ""
    parameters: Dict[str, Any] = {}
    metadata: Dict[str, Any] = {}
```

**ExecutionResult**:
```python
@dataclass
class ExecutionResult:
    execution_id: str
    script_name: str
    module_name: str
    status: str  # "success", "error", "timeout"
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    duration: float = 0.0
    timestamp: str = ""
    error: Optional[str] = None
```

### Excepciones del Core

Un módulo puede capturar estas excepciones:

```python
from core.errors import (
    BOFAError,              # Excepción base
    ModuleNotFoundError,     # Módulo no encontrado
    ScriptNotFoundError,    # Script no encontrado
    ExecutionError,         # Error durante ejecución
    ValidationError,        # Error de validación
    ConfigurationError,     # Error de configuración
    SecurityError,          # Error de seguridad
)
```

### Configuración

Un módulo puede acceder a la configuración:

```python
from core.config import get_config

config = get_config()
print(config.base_path)
print(config.scripts_path)
print(config.output_path)
print(config.logs_path)
print(config.log_level)
```

### Logging

Un módulo puede usar el logger del core:

```python
from core.logger import get_logger

logger = get_logger(__name__)
logger.info("Mensaje informativo", module="mi_modulo")
logger.error("Error", error=str(e))
```

## ✅ Garantías del Contrato

### El Core Garantiza:

1. **Descubrimiento Automático**: Cualquier módulo en `scripts/` será descubierto automáticamente
2. **Sin Modificaciones**: Un módulo nuevo no requiere modificar el core
3. **Ejecución Aislada**: Cada script se ejecuta en su propio proceso
4. **Variables de Entorno**: Siempre disponibles antes de ejecutar
5. **Validación**: Parámetros se validan antes de ejecutar (si hay YAML)
6. **Logging**: Todos los eventos se registran automáticamente
7. **Timeout**: Ejecuciones tienen timeout configurable (default: 3600s)

### Un Módulo Debe Garantizar:

1. **Estructura Correcta**: Seguir la estructura de directorios esperada
2. **Scripts Ejecutables**: Scripts deben ser ejecutables con Python 3
3. **Códigos de Salida**: Retornar códigos apropiados (0 = éxito)
4. **Parámetros**: Aceptar parámetros por línea de comandos si se especifican en YAML

## 🚫 Lo que NO es Parte del Contrato

El core **NO**:
- No modifica scripts
- No requiere registro manual de módulos
- No requiere herencia de clases del core
- No requiere imports específicos del core en los scripts
- No gestiona dependencias de scripts (eso es responsabilidad del script)
- No gestiona permisos de ejecución (debe estar configurado en el sistema)

Los scripts **NO** necesitan:
- Importar el core
- Heredar de clases del core
- Usar APIs específicas del core
- Registrarse manualmente
- Conocer la estructura interna del core

## 📝 Ejemplo de Módulo Mínimo

### Estructura

```
scripts/
└── example/
    ├── hello.py
    └── hello.yaml
```

### `hello.yaml`

```yaml
name: hello
description: "Script de ejemplo que saluda"
parameters:
  name:
    type: str
    required: true
    description: "Nombre a saludar"
```

### `hello.py`

```python
#!/usr/bin/env python3
"""
Script de ejemplo
"""
import argparse
import sys

def main():
    parser = argparse.ArgumentParser(description="Script de ejemplo")
    parser.add_argument("--name", required=True, help="Nombre a saludar")
    args = parser.parse_args()
    
    print(f"¡Hola, {args.name}!")
    return 0

if __name__ == "__main__":
    sys.exit(main())
```

Este módulo será descubierto y ejecutable automáticamente sin tocar el core.

## Validacion del Contrato

Para validar que un módulo cumple el contrato:

1. Coloca el módulo en `scripts/`
2. Ejecuta el engine: `engine.initialize()`
3. Verifica que el módulo aparece: `engine.list_modules()`
4. Verifica que los scripts aparecen: `engine.list_scripts("example")`
5. Ejecuta un script: `engine.execute_script("example", "hello", {"name": "Mundo"})`

Si todo funciona, el módulo cumple el contrato.

## 🔄 Compatibilidad Hacia Atrás

Este contrato es estable. Cualquier cambio que rompa la compatibilidad será:
1. Documentado explícitamente
2. Versioneado (cambios mayores incrementan versión mayor)
3. Anunciado con antelación

Los módulos existentes seguirán funcionando mientras cumplan este contrato.
