# BOFA Wiki

Bienvenido a la **Wiki** del proyecto [BOFA](https://github.com/descambiado/BOFA): framework open-source de ciberseguridad con **96 herramientas** y **25 flujos** para penetration testing, bug bounty, forense, cloud security y malware analysis.

---

## ¿Qué es BOFA?

**BOFA** (Cybersecurity Operations Framework Advanced) es un framework unificado con:

- **Core estable** y CLI (`./bofa.sh`) que descubre módulos y scripts automáticamente.
- **20 módulos**, **96 scripts**: recon, web, exploit, cloud, malware, forensics, vulnerability, reporting, zero_trust, etc.
- **25 flujos** predefinidos: `bug_bounty_full_chain`, `vuln_to_action`, `cloud_config_review`, `malware_static_recon`, etc.
- **Agente autónomo** con LLM (Ollama, OpenAI, Claude): loop Observe-Think-Act para pruebas guiadas por IA.
- **Servidor MCP** (opcional): uso desde Cursor, Claude Desktop o cualquier cliente MCP. **Uso 100% local** sin MCP: CLI, flujos y agente funcionan solo con Python.

---

## Estado del proyecto

| Área | Estado |
|------|--------|
| Core, CLI, módulos y scripts | ✅ Listo |
| Flujos (BOFA Flow) e informes | ✅ Listo |
| Servidor MCP | ✅ Listo (opcional) |
| Agente autónomo (LLM) | ✅ Listo |
| Verificación (`verify_bofa.py`) | ✅ Listo |
| Documentación | ✅ Actualizada |

**Conclusión**: BOFA está **production-ready** para uso local y para integración con clientes MCP. Ver [Status](Status) y [Roadmap](Roadmap).

---

## Quick Start

```bash
git clone https://github.com/descambiado/BOFA
cd BOFA
pip install -r requirements.txt
./bofa.sh
```

Ver [Installation](Installation) para más opciones (Docker, MCP, agente).

---

## Enlaces útiles

| Página | Descripción |
|--------|-------------|
| [Status](Status) | Estado actual, números (scripts, flujos, módulos), entregables |
| [Roadmap](Roadmap) | Próximos pasos, fases, innovación |
| [Installation](Installation) | Instalación local, Docker, MCP, agente |

En el repositorio:

- [README](https://github.com/descambiado/BOFA/blob/main/README.md) · [docs/](https://github.com/descambiado/BOFA/tree/main/docs) · [CHANGELOG](https://github.com/descambiado/BOFA/blob/main/CHANGELOG.md)

---

*Por [@descambiado](https://github.com/descambiado). Versión: **v2.6.0**.*
