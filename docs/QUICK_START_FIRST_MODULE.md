# 🚀 Tu primer módulo BOFA en 5 minutos

Crear un módulo nuevo **no requiere tocar el core**. Solo sigue esta guía.

---

## 1. Crear la carpeta del módulo

Desde la raíz del proyecto:

```bash
mkdir -p scripts/mi_modulo
cd scripts/mi_modulo
```

---

## 2. Crear el script Python

Crea `hola.py`:

```python
#!/usr/bin/env python3
"""Mi primer script BOFA."""
import sys

def main():
    print("¡Hola desde BOFA!")
    return 0

if __name__ == "__main__":
    sys.exit(main())
```

---

## 3. Crear el YAML (opcional pero recomendado)

Crea `hola.yaml`:

```yaml
name: hola
description: "Mi primer script BOFA"
parameters: {}
```

---

## 4. Probar

Desde la **raíz del proyecto**:

```bash
# Opción A: CLI
./bofa.sh
# Elige opción E (Ejemplos) o el módulo que corresponda según tu carpeta.
# Si creaste scripts/mi_modulo, aparecerá como módulo "mi_modulo" en el descubrimiento.

# Opción B: Python
python3 -c "
from core.engine import get_engine
engine = get_engine()
print('Módulos:', engine.list_modules())   # debe incluir 'mi_modulo'
print('Scripts:', engine.list_scripts('mi_modulo'))
result = engine.execute_script('mi_modulo', 'hola')
print('Salida:', result.stdout)
print('Estado:', result.status)
"
```

---

## 5. Añadir parámetros (opcional)

En `hola.yaml`:

```yaml
name: hola
description: "Saluda a alguien"
parameters:
  nombre:
    required: true
    description: "Nombre a saludar"
```

En `hola.py`:

```python
#!/usr/bin/env python3
import argparse
import sys

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--nombre", required=True)
    args = p.parse_args()
    print(f"¡Hola, {args.nombre}!")
    return 0

if __name__ == "__main__":
    sys.exit(main())
```

Vuelve a probar con el core o la CLI; el módulo se descubre solo.

---

## ✅ Checklist

- [ ] Carpeta en `scripts/<nombre_modulo>/`
- [ ] Archivo `.py` ejecutable (`python3 script.py` funciona)
- [ ] Opcional: `.yaml` con `name`, `description`, `parameters`
- [ ] Código de salida: `0` = éxito, otro = error
- [ ] Errores a `stderr`: `print(..., file=sys.stderr)`

---

## 📚 Siguiente paso

- [Módulos de ejemplo](../scripts/examples/README.md) — copia `example_info` o `example_params`.
- [Contrato Core–Módulos](MODULE_CONTRACT.md) — qué espera el core de tu módulo.

**No hace falta leer el core.** Con esto puedes crear módulos ilimitados.
