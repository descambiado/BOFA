# Checklist: Módulo certificado BOFA

Lista de comprobación para que un módulo cumpla el estándar BOFA y pueda considerarse **certificado** (listo para uso en flujos, MCP y verificación completa).

Basado en el [Contrato Core–Módulos](MODULE_CONTRACT.md).

---

## Estructura

- [ ] El módulo está en `scripts/<nombre_modulo>/`.
- [ ] No hay archivos `.py` con nombre empezando por `_`.
- [ ] Cada script tiene su archivo `.yaml` homónimo (ej. `script.py` + `script.yaml`).

---

## Script Python

- [ ] Usa **argparse** (o compatible) con argumentos **opcionales** en formato `--key value`.
- [ ] No depende de argumentos posicionales obligatorios; el core pasa `--key value`.
- [ ] Devuelve **código de salida**: `0` = éxito, `!= 0` = error (vía `sys.exit(code)` en `if __name__ == "__main__"`).
- [ ] Funciona con **Python 3.8+** sin dependencias externas no declaradas.
- [ ] Si usa dependencias opcionales (ej. `requests`), falla con mensaje claro si no están instaladas.
- [ ] Si el script puede producir datos estructurados, expone una opción opcional (por ejemplo `--json`) que imprime en stdout un JSON parseable (pensado para flujos y MCP).

---

## Script YAML

- [ ] Tiene `name` (coincide con el nombre del archivo sin `.py`).
- [ ] Tiene `description`.
- [ ] La sección `parameters` está en formato **dict** (no lista): `nombre_param: { type, description, required, default }`.
- [ ] Los tipos usados son compatibles con el validador: `string`, `int`, `bool` (o equivalentes).
- [ ] Parámetros requeridos tienen `required: true`; opcionales tienen `required: false` y opcionalmente `default`.

---

## Comportamiento

- [ ] El script se ejecuta correctamente con parámetros vacíos (si no tiene requeridos) o con los params definidos en el YAML.
- [ ] No deja procesos colgados ni requiere entrada interactiva en modo no interactivo (salvo que se documente).
- [ ] La salida (stdout/stderr) es útil para logs o reportes; opcionalmente sigue la [convención de reportes](REPORTS_CONVENTION.md) (JSON/Markdown).

---

## Documentación (recomendado)

- [ ] El YAML incluye `description` clara y, si aplica, `usage` o ejemplos.
- [ ] Dependencias externas (pip, sistema) están documentadas en el YAML o en un README del módulo.

---

## Verificación

Para comprobar que el módulo pasa el checklist en entorno BOFA:

1. **Verificación rápida**: `python3 tools/verify_bofa.py` (incluye ejemplos; si tu módulo no es `examples`, no se ejecuta aquí).
2. **Verificación completa**: `python3 tools/verify_bofa.py --full` — el core descubre todos los módulos, valida YAML y ejecuta los scripts con parámetros vacíos o con params seguros definidos en `verify_bofa.py`. Si tu script requiere parámetros específicos, añade una entrada en `_safe_params()` en `tools/verify_bofa.py` para que `--full` lo ejecute con params válidos.
3. **Ejecución manual**: desde la CLI (opción del menú) o con `engine.execute_script("modulo", "script", parameters={...})`.

Un módulo **certificado** es el que cumple este checklist y pasa la verificación completa (o está correctamente registrado en `SKIP_FULL` si es interactivo o de larga duración).
