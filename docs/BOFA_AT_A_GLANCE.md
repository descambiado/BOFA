# BOFA en una pagina

Por descambiado. Todo lo esencial del framework en un solo lugar.

---

## Qué es BOFA

Framework open-source de ciberseguridad con core estable, CLI profesional y modulos descubiertos automaticamente. 66+ scripts, 19 modulos, 7 flujos. CLI, API, MCP para LLM.

---

## Arrancar en 30 segundos

```bash
git clone https://github.com/descambiado/BOFA
cd BOFA
pip install -r requirements.txt
./bofa.sh
```

---

## Estructura en 3 capas

| Capa | Qué hace |
|------|----------|
| **Core** | Descubre módulos en `scripts/`, valida y ejecuta scripts, config, logging, errores. |
| **CLI** | Menú interactivo sobre el core. No tiene lógica de negocio. |
| **Módulos** | Carpetas en `scripts/<nombre>/` con `.py` y opcionalmente `.yaml`. |

Un **módulo nuevo** = nueva carpeta en `scripts/`. El core lo descubre solo. No se toca el core.

---

## Crear tu primer módulo (5 min)

1. `mkdir scripts/mi_modulo`
2. Crea `hola.py` con `def main(): print("Hola"); return 0` y `if __name__ == "__main__": sys.exit(main())`
3. Opcional: `hola.yaml` con `name`, `description`, `parameters`
4. `./bofa.sh` -> tu modulo aparece. O: `engine.execute_script("mi_modulo", "hola")`

Guía completa: [Tu primer módulo en 5 min](QUICK_START_FIRST_MODULE.md).

---

## Documentación clave

| Necesito... | Documento |
|-----------|-----------|
| Indice de documentacion | [DOCUMENTATION_INDEX](DOCUMENTATION_INDEX.md) |
| Saber en que punto estamos | [Estado actual](STATUS.md) |
| Crear un módulo | [Tu primer módulo en 5 min](QUICK_START_FIRST_MODULE.md) |
| Entender el core | [Arquitectura del Core](CORE_ARCHITECTURE.md) |
| Usar el engine desde código | [Uso del Core](CORE_USAGE.md) |
| Contrato modulo <-> core | [Contrato Core-Modulos](MODULE_CONTRACT.md) |
| Checklist módulo certificado | [MODULE_CHECKLIST](MODULE_CHECKLIST.md) |
| Reportes (flujos y scripts) | [Convención de reportes](REPORTS_CONVENTION.md) |
| Errores y logging | [Errores y Logging](ERRORS_AND_LOGGING.md) |
| Copiar un ejemplo | [Módulos de ejemplo](../scripts/examples/README.md) |
| Usar la CLI | [CLI](../cli/README.md) |

---

## Criterios de listo

- **Usar BOFA sin el autor**: documentación y ejemplos suficientes.
- **Que un tercero entienda el README**: valor claro y enlaces a todo.
- **Crear un módulo sin tocar el core**: descubrimiento automático y contrato claro.
- **CLI estable y predecible**: una sola entrada, capa sobre el core.
- **Proyecto que inspire confianza**: errores claros, logging consistente, código limpio.

---

BOFA - Cybersecurity Operations Framework Advanced. Por [@descambiado](https://github.com/descambiado). [GitHub](https://github.com/descambiado/BOFA)
