# 🚀 Quick Start - Módulos de Ejemplo

Guía rápida para usar los módulos de ejemplo como referencia.

## 📋 Resumen de Ejemplos

| Módulo | Propósito | Complejidad | Parámetros |
|--------|-----------|-------------|------------|
| `example_info` | Hello World | ⭐ Muy Simple | Ninguno |
| `example_params` | Con Parámetros | ⭐⭐ Simple | 3 parámetros |
| `example_fail` | Manejo de Errores | ⭐⭐ Simple | 1 parámetro |

## 🎯 ¿Cuál Usar?

### Si necesitas un script simple sin parámetros
→ **Copia `example_info`**

### Si necesitas recibir parámetros
→ **Copia `example_params`**

### Si necesitas manejar errores
→ **Copia `example_fail`**

## 📝 Pasos para Crear tu Módulo

### 1. Copiar un Ejemplo

```bash
# Copiar ejemplo simple
cp -r scripts/examples/example_info scripts/mi_modulo/

# O copiar ejemplo con parámetros
cp -r scripts/examples/example_params scripts/mi_modulo/
```

### 2. Renombrar Archivos

```bash
cd scripts/mi_modulo/
mv example_info.py mi_script.py
mv example_info.yaml mi_script.yaml
```

### 3. Modificar el Código

- Edita `mi_script.py` con tu lógica
- Actualiza `mi_script.yaml` con tus parámetros
- Ajusta nombres y descripciones

### 4. Probar

```python
from core.engine import get_engine

engine = get_engine()
engine.initialize()

# Verificar que aparece
print(engine.list_modules())  # Debe incluir 'mi_modulo'

# Ejecutar
result = engine.execute_script("mi_modulo", "mi_script")
print(result.status, result.exit_code)
```

## ✅ Checklist de Creación

- [ ] Script tiene shebang `#!/usr/bin/env python3`
- [ ] Script tiene función `main()` que retorna int
- [ ] Script usa `sys.exit(main())` al final
- [ ] YAML tiene `name`, `description` y `parameters` (si aplica)
- [ ] Script funciona ejecutado directamente
- [ ] Script funciona ejecutado por el core
- [ ] Errores van a `stderr`, no a `stdout`
- [ ] Códigos de salida son apropiados (0 = éxito)

## 🔍 Verificación Rápida

```bash
# Probar ejecución directa
python3 scripts/mi_modulo/mi_script.py

# Probar con parámetros (si aplica)
python3 scripts/mi_modulo/mi_script.py --param value

# Verificar que el core lo descubre
python3 -c "
from core.engine import get_engine
engine = get_engine()
print('Módulos:', engine.list_modules())
print('Scripts:', engine.list_scripts('mi_modulo'))
"
```

## 📚 Más Información

- [README.md](README.md) - Documentación completa
- [MODULE_CONTRACT.md](../../docs/MODULE_CONTRACT.md) - Contrato completo
- [CORE_USAGE.md](../../docs/CORE_USAGE.md) - Guía de uso del core
