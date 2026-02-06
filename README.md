# BOFA - Cybersecurity Operations Framework Advanced

![BOFA](https://github.com/descambiado/BOFA/blob/main/public/bofasuitebanner.png?raw=true)

Framework open-source de ciberseguridad con core estable, CLI profesional y modulos descubiertos automaticamente. Por [@descambiado](https://github.com/descambiado). Plataforma educativa y herramientas reales (66+ scripts, 19 modulos, 7 flujos), CLI, API y servidor MCP para uso con LLM.

---

## BOFA en 30 segundos

```bash
git clone https://github.com/descambiado/BOFA
cd BOFA
pip install -r requirements.txt
./bofa.sh
```

Opcional (integración con Cursor u otros clientes MCP): `pip install .[mcp]` — ver [Integración MCP](docs/MCP_CURSOR_INTEGRATION.md).

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
| **Copiar un ejemplo** | [Módulos de ejemplo](scripts/examples/README.md) |

---

## Caracteristicas

### Plataforma web educativa
- **Interactive Script Library**: Browse and learn from 200+ security tools
- **Code Viewer**: Professional syntax highlighting for all scripts
- **Real-time Dashboard**: Monitor your security operations
- **Study Materials**: Comprehensive cybersecurity lessons and CTF challenges
- **Progress Tracking**: Track your learning journey and skill development

### CLI y herramientas (66+ scripts)
- **Red Team**: 35+ offensive security tools and techniques
- **Blue Team**: 28+ defensive tools with AI-powered threat detection  
- **Purple Team**: 20+ coordinated exercise tools with ML integration
- **OSINT**: 18+ intelligence gathering and analysis tools
- **Malware Analysis**: 15+ static and dynamic analysis tools
- **Social Engineering**: 12+ awareness and training tools
- **Study & Research**: Educational CTF and training tools

### Labs
- **Docker-based Labs**: 8 comprehensive security environments
- **Real Vulnerability Testing**: Hands-on practice with safe environments  
- **Cloud Native Security**: Kubernetes and container security testing
- **IoT/OT Security**: Industrial protocol and device testing
- **Mobile Security**: Android application security analysis

## Casos de uso

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

## Numeros (referencia)

- **200+ Real Security Tools** across 7 specialized modules
- **50+ Innovative 2025 Techniques** with cutting-edge technology
- **8 Professional Lab Environments** for hands-on practice
- **15+ AI/ML Security Algorithms** implemented natively
- **Cross-platform Support** (Linux, macOS, Windows, WSL2)
- **Modern Web Interface** with professional code viewing
- **Complete Documentation** for all tools and techniques

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
