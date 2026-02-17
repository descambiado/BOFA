# Indice de documentacion BOFA

Por descambiado. Lista de documentos con descripcion breve. Todo en ASCII.

---

## Estado y uso rapido

| Doc | Contenido |
|-----|-----------|
| [STATUS.md](STATUS.md) | Estado actual: core, CLI, modulos, flujos, MCP, agente autónomo, verificacion. Numeros (96 scripts, 20 modulos, 25 flujos). Cerrar proyecto. |
| [wiki/](../wiki/README.md) | Contenido para la **Wiki de GitHub**: Home, Status, Roadmap, Installation, Sidebar. Ver wiki/README.md para publicar en la pestaña Wiki del repo. |
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
| [AGENT.md](AGENT.md) | Agente autónomo: loop Observe-Think-Act con LLM (Ollama, OpenAI, Anthropic). run_agent hasta vulnerar. |
| [ORCHESTRATION_AND_CHAINING.md](ORCHESTRATION_AND_CHAINING.md) | Orquestacion y encadenamiento: combinar flujos y scripts, salida JSON, ejemplos para la IA. Bloques destacados: Cloud security (iam_policy_linter, storage_acl_auditor, cloud_config_review), Zero Trust/network, malware_static_recon y bug bounty (bug_bounty_web_full, bug_bounty_full_chain, cve_enricher, exploit_chain_suggester). |

---

## Zero-day e instalacion

| Doc | Contenido |
|-----|-----------|
| [ZERO_DAY_AND_REPORTING.md](ZERO_DAY_AND_REPORTING.md) | Zero-day y reporte: que hace BOFA, modulo reporting (report_finding) para disclosure. |
| [INSTALLATION.md](INSTALLATION.md) | Instalacion completa: prerequisitos, Docker, manual, opcionales. |
| [USAGE.md](USAGE.md) | Uso de la plataforma (CLI, web, API). |
| [NEXT_STEPS_AND_ROADMAP.md](NEXT_STEPS_AND_ROADMAP.md) | Roadmap y proximos pasos. |
| [RELEASE.md](RELEASE.md) | Estrategia de versionado y comandos para release. |
| [CTF_AND_TRAINING.md](CTF_AND_TRAINING.md) | Uso de los scripts y flujos CTF (ctf_string_hunter, pcap_proto_counter, ctf_binary_recon, ctf_network_recon) y malware/forense avanzado (binary_header_inspector, string_yara_like_scanner, packer_heuristics, malware_static_recon) para entrenamiento humano/IA. |

---

Verificacion: `python3 tools/verify_bofa.py` (quick) o `--full`. Autor: [@descambiado](https://github.com/descambiado).
