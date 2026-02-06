# Indice de documentacion BOFA

Por descambiado. Lista de documentos con descripcion breve. Todo en ASCII.

---

## Estado y uso rapido

| Doc | Contenido |
|-----|-----------|
| [STATUS.md](STATUS.md) | Estado actual: core, CLI, modulos, flujos, MCP, verificacion. Numeros (68 scripts, 20 modulos, 9 flujos). Cerrar proyecto. |
| [ARSENAL_AND_QUALITY.md](ARSENAL_AND_QUALITY.md) | Scripts: funcionan todos, son reales, novedosos o no, como vamos, seguir desarrollando. Honestidad del arsenal. |
| [BOFA_AT_A_GLANCE.md](BOFA_AT_A_GLANCE.md) | Resumen en una pagina: que es BOFA, arrancar, 3 capas, crear modulo, enlaces clave. |
| [README.md](README.md) | Indice de docs, instalacion, CLI, API, web. |

---

## Core y modulos

| Doc | Contenido |
|-----|-----------|
| [CORE_ARCHITECTURE.md](CORE_ARCHITECTURE.md) | Arquitectura del core: engine, config, logger, errors, utils. Estructura de directorios. |
| [CORE_USAGE.md](CORE_USAGE.md) | Uso del engine desde codigo: get_engine(), list_modules, execute_script, etc. |
| [MODULE_CONTRACT.md](MODULE_CONTRACT.md) | Contrato core-modulos: que espera el core de un modulo, formato YAML, requisitos del script. |
| [MODULE_CHECKLIST.md](MODULE_CHECKLIST.md) | Checklist modulo certificado: estructura, argparse, YAML, codigo salida, verificacion. |
| [QUICK_START_FIRST_MODULE.md](QUICK_START_FIRST_MODULE.md) | Crear tu primer modulo en 5 min sin tocar el core. |

---

## Reportes y convenciones

| Doc | Contenido |
|-----|-----------|
| [REPORTS_CONVENTION.md](REPORTS_CONVENTION.md) | Convencion de reportes: flujos (Markdown en reports/), scripts (JSON/Markdown opcional). |
| [ERRORS_AND_LOGGING.md](ERRORS_AND_LOGGING.md) | Errores y logging: BOFAError, codigos, formato logs. |

---

## MCP e IA

| Doc | Contenido |
|-----|-----------|
| [MCP_CURSOR_INTEGRATION.md](MCP_CURSOR_INTEGRATION.md) | Integracion MCP con Cursor: config .cursor/mcp.json, herramientas, troubleshooting. |
| [LLM_CYBERSECURITY.md](LLM_CYBERSECURITY.md) | BOFA + LLM: como funciona, herramientas MCP (incl. capabilities, suggest_tools), dominios/agentes, ejemplo de flujo. |
| [ORCHESTRATION_AND_CHAINING.md](ORCHESTRATION_AND_CHAINING.md) | Orquestacion y encadenamiento: combinar flujos y scripts, salida JSON, ejemplos para la IA. |

---

## Zero-day e instalacion

| Doc | Contenido |
|-----|-----------|
| [ZERO_DAY_AND_REPORTING.md](ZERO_DAY_AND_REPORTING.md) | Zero-day y reporte: que hace BOFA, modulo reporting (report_finding) para disclosure. |
| [INSTALLATION.md](INSTALLATION.md) | Instalacion completa: prerequisitos, Docker, manual, opcionales. |
| [USAGE.md](USAGE.md) | Uso de la plataforma (CLI, web, API). |
| [NEXT_STEPS_AND_ROADMAP.md](NEXT_STEPS_AND_ROADMAP.md) | Roadmap y proximos pasos. |
| [RELEASE.md](RELEASE.md) | Estrategia de versionado y comandos para release. |

---

Verificacion: `python3 tools/verify_bofa.py` (quick) o `--full`. Autor: [@descambiado](https://github.com/descambiado).
