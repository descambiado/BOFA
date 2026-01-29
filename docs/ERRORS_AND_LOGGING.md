# Errores y Logging en BOFA

Guía breve: cómo son los errores y el logging en el core.

---

## Errores

### Principios

- **Mensajes claros**: Cada excepción tiene un mensaje que explica qué falló.
- **Trazas completas**: No se filtran trazas; el stack trace se preserva al propagar.
- **Detalles para debugging**: Usa `details` (dict) para datos útiles (módulo, script, exit_code, timeout, etc.).
- **Serialización**: `e.to_dict()` para API o logs (tipo, mensaje, código, details).

### Jerarquía

```
BOFAError (base)
├── ConfigurationError
├── ModuleNotFoundError
├── ScriptNotFoundError
├── ExecutionError
├── ValidationError
└── SecurityError
```

### Uso

```python
from core.errors import ScriptNotFoundError, ExecutionError

try:
    engine.execute_script("blue", "script_inexistente")
except ScriptNotFoundError as e:
    print(str(e))           # Mensaje amigable
    print(e.details)        # script_name, module_name
    print(e.to_dict())      # Para logs/API
    raise                   # Propagar (traceback intacto)
```

### En el engine

- Al fallar validación o ejecución, se hace **log** del error (con contexto) y se **re-lanza** la excepción.
- Para fallos inesperados se usa `logger.exception(...)` para incluir **traceback** en el log.

---

## Logging

### Principios

- **Consistente**: Un solo sistema de logging (`core.logger`), mismos niveles y formato.
- **Sin duplicar**: No se repite el mismo mensaje en log y en stdout; la CLI imprime al usuario, el core solo loguea.
- **Niveles**:
  - **DEBUG**: Detalle para desarrollo.
  - **INFO**: Operaciones normales (inicio, módulos cargados, script ejecutado).
  - **WARNING**: Script falló (exit code != 0), timeout, etc.
  - **ERROR**: Validación fallida, error de ejecución.
  - **CRITICAL**: Fallos graves (no usados por defecto).

### Configuración

- **Nivel/formato**: `config/bofa.yaml` → `logging.level`, `logging.format` (json | text).
- **Variables de entorno**: `BOFA_LOG_LEVEL`, `BOFA_LOG_FORMAT`, `BOFA_LOG_FILE`.

### Uso

```python
from core.logger import get_logger, setup_logging

setup_logging()  # Una vez al inicio
logger = get_logger(__name__)

logger.info("Operación correcta", module="blue", script="hola")
logger.warning("Script falló", exit_code=1)
logger.error("Validación fallida", error=str(e))
logger.exception("Error inesperado")  # Incluye traceback
```

### Formato

- **Texto**: `YYYY-MM-DD HH:MM:SS | LEVEL    | logger.name | message`
- **JSON**: Objeto con `timestamp`, `level`, `logger`, `message`, `context`, `exception` (si hay).

---

## Resumen

| Aspecto | Comportamiento |
|---------|----------------|
| Mensajes de error | Claros, con código y detalles |
| Tracebacks | Preservados; no se filtran |
| Logging | Un solo sistema, niveles correctos |
| Duplicados | Evitados (CLI imprime, core loguea) |
| Debugging | `details`, `to_dict()`, `logger.exception()` |
