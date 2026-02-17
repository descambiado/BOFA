# BOFA - Cybersecurity Operations Framework Advanced

![BOFA](https://github.com/descambiado/BOFA/blob/main/public/bofasuitebanner.png?raw=true)

![License](https://img.shields.io/badge/license-MIT-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-green)
![Scripts](https://img.shields.io/badge/scripts-96%2B-orange)
![Flows](https://img.shields.io/badge/flows-25-blue)

Framework open-source de ciberseguridad con core estable, CLI profesional y módulos descubiertos automáticamente. Por [@descambiado](https://github.com/descambiado). **96 herramientas y 25 flujos** para **penetration testing**, **bug bounty**, **forense**, **cloud security** y **malware analysis**, con servidor **MCP** y **agente autónomo con LLM** (Ollama, OpenAI, Claude).

---

## BOFA en 30 segundos

```bash
git clone https://github.com/descambiado/BOFA
cd BOFA
pip install -r requirements.txt
./bofa.sh
```

**Uso 100% local** (sin Cursor ni MCP): el menú CLI, los flujos y el agente (`run_agent`, `self_hack_runner`) funcionan en tu máquina con solo clonar e instalar. Opcional: `pip install .[mcp]` para usar BOFA desde **Cursor, Claude Desktop o cualquier cliente MCP** — ver [Integración MCP](docs/MCP_CURSOR_INTEGRATION.md).

Menu interactivo, modulos descubiertos por el core, sin configuracion extra. Crear modulo propio: [Tu primer modulo en 5 minutos](docs/QUICK_START_FIRST_MODULE.md) (sin tocar el core).

| Qué quieres | Enlace |
|-------------|--------|
| **Todo en una página** | [BOFA en una página](docs/BOFA_AT_A_GLANCE.md) |
| **Usar la CLI** | `./bofa.sh` o [CLI](cli/README.md) |
| **Crear un módulo** | [Tu primer módulo en 5 min](docs/QUICK_START_FIRST_MODULE.md) |
| **Entender el core** | [Arquitectura](docs/CORE_ARCHITECTURE.md) · [Contrato módulos](docs/MODULE_CONTRACT.md) |
| **Estado actual** | [STATUS](docs/STATUS.md) |
| **Indice de documentacion** | [DOCUMENTATION_INDEX](docs/DOCUMENTATION_INDEX.md) |
| **Zero-day y reporte** | [ZERO_DAY_AND_REPORTING](docs/ZERO_DAY_AND_REPORTING.md) |
| **Roadmap y próximos pasos** | [NEXT_STEPS_AND_ROADMAP](docs/NEXT_STEPS_AND_ROADMAP.md) |
| **Ejecutar un flujo** | [BOFA Flows](flows/README.md) (opción F en CLI) |
| **Saber que todo funciona** | `python3 tools/verify_bofa.py` — [tools/README.md](tools/README.md) |
| **IA + ciberseguridad (LLM con BOFA)** | [LLM + BOFA para ciberseguridad](docs/LLM_CYBERSECURITY.md) |
| **Usar BOFA desde Cursor (MCP)** | [Integración MCP con Cursor](docs/MCP_CURSOR_INTEGRATION.md) — [mcp/README.md](mcp/README.md) |
| **Agente autónomo (LLM)** | [Agente Observe-Think-Act](docs/AGENT.md) — `python3 tools/run_agent.py URL --provider ollama` |
| **Copiar un ejemplo** | [Módulos de ejemplo](scripts/examples/README.md) |

---

## Características

### Why BOFA / ¿Qué hace diferente a BOFA?

- **Framework unificado**: 20 módulos y 96 scripts descubiertos automáticamente por el core (recon, web, exploit, blue, purple, osint, cloud, malware, forensics, vulnerability, reporting, zero_trust, etc.).
- **Flujos listos para IA**: 25 flujos (`full_recon`, `bug_bounty_full_chain`, `bug_bounty_web_*`, `cloud_config_review`, `malware_static_recon`, `network_zero_trust_overview`, `vuln_to_action`, …) con informes Markdown orquestables por LLM.
- **Puente CVE → acción**: `vulnerability/exploit_chain_suggester` genera cadenas de herramientas BOFA a partir de CVE o producto.
- **Mapa de ataque unificado**: `recon/attack_surface_mapper` sugiere fases y pasos de recon para URL/host.
- **Zero-Day Disclosure Kit**: `reporting/zero_day_disclosure_kit` genera plantillas CERT/vendor, timeline y checklist para divulgación responsable.
- **Servidor MCP**: `mcp/bofa_mcp.py` expone módulos, scripts y flujos para clientes como Cursor/Claude (Model Context Protocol).

### Plataforma web educativa (labs y UI)
- **Web UI**: Interfaz React/TypeScript (Vite + Tailwind) para explorar scripts y labs (ver `package.json` y `docs/USAGE.md`).
- **Script Library**: Navegar por los scripts y su documentación (`scripts/README.md`).
- **Labs Docker**: Varios labs en `labs/` (`docker-compose.yml`) para practicar SQLi, CTF, AD enum, cloud misconfig, EDR evasion, etc.

### CLI y herramientas (core estable)
- CLI `./bofa.sh` / `cli/bofa_cli.py` sobre el core: lista módulos, scripts y flujos; ejecuta scripts y flujos sin tocar el core.
- 20 módulos, 96 scripts – ver detalle actualizado en [STATUS.md](docs/STATUS.md).
- Scripts enfocados en uso real y educativo (recon web, cloud IAM, malware estático, blue team, CTF, etc.).

### Labs
- **Docker-based Labs**: 8 comprehensive security environments
- **Real Vulnerability Testing**: Hands-on practice with safe environments  
- **Cloud Native Security**: Kubernetes and container security testing
- **IoT/OT Security**: Industrial protocol and device testing
- **Mobile Security**: Android application security analysis

## Casos de uso (Penetration Testing, Bug Bounty, Blue/Forense)

- **Security Training**: Corporate cybersecurity education programs
- **Penetration Testing**: Real-world security assessment tools
- **Incident Response**: Blue team tools for threat hunting and analysis
- **Research & Development**: Cutting-edge security technique exploration
- **CTF Competitions**: Educational capture-the-flag scenarios
- **Academic Programs**: University cybersecurity curriculum support

## Quick Start

### Option 1: Docker (Recommended)
```bash
# Clone the repository
git clone https://github.com/descambiado/BOFA
cd BOFA

# Start the educational web interface
docker-compose up --build

# Access web interface: http://localhost:3000
# API documentation: http://localhost:8000/docs
```

### Option 2: Local Installation
```bash
# Prerequisites: Node.js 18+, Python 3.8+, Git

# Frontend setup
git clone https://github.com/descambiado/BOFA
cd BOFA
npm install
npm run dev

# CLI tools (optional)
pip install -r requirements.txt
./bofa.sh
```

### Option 3: CLI Tools Only
```bash
# For users who only want the command-line tools
git clone https://github.com/descambiado/BOFA
cd BOFA
pip install -r requirements.txt
./bofa.sh  # Interactive CLI menu
```

## Documentacion

### Core & CLI (framework estable)
- **[Tu primer módulo en 5 min](docs/QUICK_START_FIRST_MODULE.md)** — Crear un módulo sin tocar el core
- **[Arquitectura del Core](docs/CORE_ARCHITECTURE.md)** — Engine, config, logger, errors, utils
- **[Uso del Core](docs/CORE_USAGE.md)** — API del engine, configuración, logging
- **[Contrato Core–Módulos](docs/MODULE_CONTRACT.md)** — Qué espera el core de un módulo
- **[CLI](cli/README.md)** — Interfaz de línea de comandos (capa sobre el core)
- **[Módulos de ejemplo](scripts/examples/README.md)** — example_info, example_params, example_fail

### Plataforma
- **[Installation](docs/INSTALLATION.md)** — Instalación completa
- **[Usage](docs/USAGE.md)** — Uso de la plataforma
- **[API](api/README.md)** — Backend API
- **[Scripts](scripts/README.md)** — Documentación de herramientas
- **[Labs](labs/README.md)** — Entornos Docker

## Arquitectura

### Core (estable, sin dependencias de UI)
- **Engine**: Descubre módulos en `scripts/`, valida y ejecuta scripts.
- **Config**: Variables de entorno + `config/bofa.yaml` + valores por defecto.
- **Logger**: Logging estructurado (JSON/texto), niveles estándar.
- **Errors**: Excepciones claras (`BOFAError`, `ModuleNotFoundError`, etc.) con detalles para debugging.
- **Utils**: Carga de módulos, validación de scripts, rutas.

La **CLI** es solo una capa de presentación sobre el core; toda la lógica está en el core.

### Web & API (plataforma educativa)
- **Frontend**: React 18 + TypeScript + Tailwind CSS
- **Backend**: Python FastAPI + SQLite
- **Purpose**: Learning, browsing, and understanding security tools

### Labs
- **Infrastructure**: Docker + Docker Compose
- **Purpose**: Hands-on security practice environments

## Seguridad y uso responsable

- [OK] Uso educativo y autorizado (sistemas propios o con permiso).
- [OK] Pruebas y desarrollo profesional.
- [NO] Uso malicioso o no autorizado.

### Security Features
- **Sandboxed Execution**: Safe isolated script execution
- **Audit Logging**: Complete activity tracking
- **Access Control**: Role-based permissions system
- **Data Encryption**: Secure storage of sensitive information

## Números (referencia)

- **20 módulos** (examples, exploit, red, blue, purple, osint, recon, web, cloud, ai, malware, forensics, vulnerability, reporting, zero_trust, etc.).
- **96 scripts** descubiertos automáticamente por el core.
- **25 flujos** predefinidos (demo, recon, full_recon, bug_bounty_full_chain, vuln_triage, vuln_to_action, bug_bounty_web_*, blue_*, forensics_*, cloud_config_review, malware_static_recon, network_zero_trust_overview…).
- **8 herramientas MCP** (`bofa_list_modules`, `bofa_list_scripts`, `bofa_script_info`, `bofa_execute_script`, `bofa_list_flows`, `bofa_run_flow`, `bofa_capabilities`, `bofa_suggest_tools`).
- **Agente autónomo** (`tools/run_agent.py`): loop Observe-Think-Act con LLM (Ollama, OpenAI, Anthropic) hasta encontrar vulnerabilidades.
- **Labs Docker** listados en [labs/README.md](labs/README.md).

## Valor educativo

### For Students
- Learn from real security tools used by professionals
- Hands-on experience with safe, sandboxed environments
- Progress tracking and skill development metrics
- Comprehensive documentation and learning materials

### For Professionals
- Access to cutting-edge security research and techniques
- Ready-to-use tools for security assessments and operations
- Advanced AI/ML integration for modern threat detection
- Professional reporting and documentation features

### For Educators
- Complete cybersecurity curriculum in one platform
- Easy deployment for classroom environments
- Student progress tracking and assessment tools
- Real-world security scenarios and case studies

## Contribuir

We welcome contributions from the cybersecurity community:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/new-tool`)
3. **Develop** your contribution with proper documentation
4. **Test** thoroughly in multiple environments
5. **Submit** a pull request with detailed description

Tipos: correcciones, nuevas herramientas, documentacion, labs, mejoras de interfaz.

## Soporte

### Getting Help
- **Documentation**: Comprehensive guides for all features
- **GitHub Issues**: [Report bugs and request features](https://github.com/descambiado/BOFA/issues)
- **Email**: david@descambiado.com
- **Discord**: [BOFA Community Server](https://discord.gg/bofa-security)

### Professional Support
- **Training**: Corporate cybersecurity training programs
- **Consulting**: Security assessment and implementation guidance
- **Custom Development**: Tailored security tools and solutions

## Licencia

MIT License. Ver [LICENSE](LICENSE). Uso comercial, modificacion y distribucion permitidos. Sin garantia.

## Agradecimientos

### Technologies
- **Frontend**: React, TypeScript, Tailwind CSS, Vite
- **Backend**: Python, FastAPI, SQLite
- **Security Standards**: OWASP, NIST, MITRE ATT&CK
- **Infrastructure**: Docker, Docker Compose

### Special Thanks
- **MITRE Corporation** - ATT&CK Framework
- **OWASP Foundation** - Security standards and guidelines
- **Open Source Community** - Foundational tools and libraries
- **Cybersecurity Researchers** - Innovative techniques and methodologies

---

BOFA v2.6.0 - [@descambiado](https://github.com/descambiado) | [LICENSE](LICENSE) | Python 3.8+
