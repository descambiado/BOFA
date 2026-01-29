# Herramientas BOFA

## Verificación: saber que todo funciona

Para comprobar que el core, la CLI y los scripts funcionan correctamente:

```bash
# Desde la raíz del proyecto
python3 tools/verify_bofa.py
```

- **Modo rápido (por defecto)**: Ejecuta el flujo demo y los módulos de ejemplo. Si termina con "Resultado: TODO OK", lo esencial funciona.
- **Modo completo**: `python3 tools/verify_bofa.py --full` — lista todos los módulos/scripts, valida y ejecuta los que aceptan parámetros vacíos o tienen parámetros seguros. Los que necesitan parámetros no se ejecutan (se marcan como "Necesitan parámetros"). Algunos se omiten por ser de larga duración o con dependencias de entorno (no cuentan como fallo).

Código de salida: 0 = todo OK, 1 = hay fallos (revisar la salida).
