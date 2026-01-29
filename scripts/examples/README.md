# 📚 Módulos de Ejemplo de BOFA

Este directorio contiene módulos de ejemplo oficiales que sirven como referencia para crear nuevos módulos en BOFA.

## 🎯 Propósito

Estos ejemplos demuestran:
- Estructura básica de un módulo BOFA
- Cómo recibir parámetros del core
- Cómo manejar errores apropiadamente
- Uso de variables de entorno del core
- Códigos de salida apropiados

## 📦 Módulos Disponibles

### 1. `example_info` - Módulo Simple

**Propósito**: Módulo "hello world" del framework.

**Características**:
- No requiere parámetros
- Muestra información básica del entorno
- Demuestra uso de variables de entorno del core

**Uso**:
```python
from core.engine import get_engine

engine = get_engine()
result = engine.execute_script("examples", "example_info")
```

### 2. `example_params` - Módulo con Parámetros

**Propósito**: Demuestra cómo recibir y validar parámetros.

**Características**:
- Acepta parámetros por línea de comandos
- Valida parámetros (requeridos, tipos, valores por defecto)
- Demuestra diferentes tipos de parámetros (str, int, bool)

**Uso**:
```python
from core.engine import get_engine

engine = get_engine()
result = engine.execute_script(
    "examples",
    "example_params",
    parameters={
        "target": "example.com",
        "timeout": 60,
        "verbose": True
    }
)
```

### 3. `example_fail` - Manejo de Errores

**Propósito**: Demuestra cómo fallar de forma controlada.

**Características**:
- Maneja diferentes tipos de errores
- Proporciona mensajes de error claros
- Retorna códigos de salida apropiados
- Usa stderr para errores

**Uso**:
```python
from core.engine import get_engine

engine = get_engine()

# Caso exitoso
result = engine.execute_script("examples", "example_fail", {"mode": "success"})

# Error de ejecución
result = engine.execute_script("examples", "example_fail", {"mode": "error"})

# Error de validación
result = engine.execute_script("examples", "example_fail", {"mode": "validation"})
```

## 📋 Estructura de un Módulo

Cada módulo debe tener:

```
examples/
├── metadata.yaml          # Opcional: metadata del módulo
├── script_name.py         # Script Python ejecutable
└── script_name.yaml       # Opcional: configuración del script
```

## 🔍 Cómo Usar Estos Ejemplos

1. **Copiar un ejemplo**:
   ```bash
   cp -r scripts/examples/example_info scripts/mi_modulo/
   ```

2. **Modificar el código**:
   - Cambiar el nombre del script
   - Ajustar la lógica según necesidades
   - Actualizar el YAML si es necesario

3. **Probar**:
   ```python
   from core.engine import get_engine
   engine = get_engine()
   engine.initialize()
   print(engine.list_modules())  # Debe incluir 'mi_modulo'
   ```

## ✅ Buenas Prácticas

1. **Siempre usar argparse** para parámetros
2. **Validar parámetros** antes de procesar
3. **Usar códigos de salida apropiados** (0 = éxito, != 0 = error)
4. **Escribir errores a stderr** (`print(..., file=sys.stderr)`)
5. **Usar variables de entorno** del core cuando sea útil
6. **Documentar en el YAML** todos los parámetros

### Nota sobre Validación de Tipos

El campo `type` en el YAML es **solo para documentación**. La validación real de tipos se hace en el script Python usando `argparse` con `type=int`, `type=str`, etc.

El core valida:
- ✅ Parámetros requeridos (si `required: true`)
- ✅ Valores por defecto
- ❌ Tipos de datos (esto se hace en el script con argparse)

Ejemplo correcto en YAML:
```yaml
parameters:
  timeout:
    required: false
    default: 30
    description: "Timeout en segundos (tipo: int)"
```

Y en el script Python:
```python
parser.add_argument("--timeout", type=int, default=30)
```

## 📖 Más Información

- [Contrato Core-Módulos](../docs/MODULE_CONTRACT.md)
- [Arquitectura del Core](../docs/CORE_ARCHITECTURE.md)
- [Guía de Uso](../docs/CORE_USAGE.md)
