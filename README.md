
# 🛡️ BOFA - Best Of All Cybersecurity Suite v2.2.0

**Desarrollado por @descambiado (David Hernández Jiménez)**

BOFA es una suite completa de ciberseguridad que integra herramientas de Red Team, Blue Team, Purple Team, análisis forense, OSINT y educación en una plataforma unificada y ética.

## 🚀 Características Principales

- **Red Team**: Arsenal ofensivo con técnicas avanzadas de penetración
- **Blue Team**: Herramientas defensivas, monitoreo y análisis forense  
- **Purple Team**: Ejercicios coordinados de ataque y defensa
- **Modo Estudio**: Lecciones interactivas con validación práctica
- **Laboratorios**: Entornos Docker vulnerables para práctica segura
- **Forensics**: Análisis de evidencia digital y artefactos
- **OSINT**: Inteligencia de fuentes abiertas
- **Mobile**: Herramientas para dispositivos móviles

## 📦 Arquitectura del Sistema

```
BOFA/
├── api/              # Backend FastAPI con carga dinámica YAML
├── src/              # Frontend React con Tailwind CSS
├── scripts/          # Scripts organizados por categoría
│   ├── red/          # Red Team (15+ herramientas)
│   ├── blue/         # Blue Team (10+ herramientas)
│   ├── purple/       # Purple Team (6+ herramientas)
│   ├── forensics/    # Análisis forense (8+ herramientas)
│   ├── osint/        # OSINT (5+ herramientas)
│   └── mobile/       # Mobile Stinger (5+ herramientas)
├── labs/             # Laboratorios Docker
├── study/            # Lecciones educativas
└── logs/             # Historial de ejecuciones
```

## 🔧 Instalación Rápida

### Prerequisitos
- Docker & Docker Compose
- Python 3.8+
- Node.js 16+
- Git

### Opción 1: Docker (Recomendado)
```bash
git clone https://github.com/descambiado/bofa
cd bofa
docker-compose up -d
```

### Opción 2: Instalación Manual Linux
```bash
git clone https://github.com/descambiado/bofa
cd bofa
chmod +x install-linux.sh
./install-linux.sh
```

### Opción 3: Instalación Manual Windows
```powershell
git clone https://github.com/descambiado/bofa
cd bofa
powershell -ExecutionPolicy Bypass -File install-windows.ps1
```

## 🌐 Acceso a la Plataforma

Una vez instalado, accede a:

- **Panel Web**: `https://localhost:8443`
- **API REST**: `https://localhost:8443/api`
- **Documentación**: `https://localhost:8443/api/docs`
- **CLI**: `python3 cli/bofa_cli.py --help`

## 🔴 Red Team - Arsenal Ofensivo

### Scripts Destacados
- **ghost_scanner.py**: Escaneo sigiloso sin rastros ARP
- **ad_enum_visualizer.py**: Enumeración de Active Directory
- **reverse_shell_polyglot.py**: Reverse shells multi-protocolo
- **c2_simulator.py**: Simulador de Command & Control
- **bypass_uac_tool.py**: Simulador de técnicas UAC bypass

### Uso Ejemplar
```bash
# Escaneo sigiloso de red
python3 scripts/red/ghost_scanner.py -t 192.168.1.0 --delay 1.0

# Visualizar estructura AD
python3 scripts/red/ad_enum_visualizer.py -d EMPRESA.LOCAL -o /tmp/ad_results
```

## 🔵 Blue Team - Defensa Activa

### Scripts Destacados
- **ioc_matcher.py**: Detección de Indicadores de Compromiso
- **log_timeline_builder.py**: Líneas de tiempo forenses desde logs
- **siem_alert_simulator.py**: Generador de alertas para SIEMs
- **forensic_artifacts_collector.py**: Recopilación de evidencia

### Uso Ejemplar
```bash
# Análisis de IOCs
python3 scripts/blue/ioc_matcher.py -f /var/log/auth.log --format json

# Construcción de timeline
python3 scripts/blue/log_timeline_builder.py -f /var/log/auth.log -o timeline.json
```

## 🟣 Purple Team - Validación Coordinada

### Scripts Destacados
- **threat_emulator.py**: Simulación de amenazas APT
- **purple_attack_orchestrator.py**: Orquestador MITRE ATT&CK
- **attack_response_logger.py**: Validación de respuestas defensivas

### Uso Ejemplar
```bash
# Simular amenaza APT
python3 scripts/purple/threat_emulator.py -t apt -o /tmp/simulation.log

# Validar cadena de detección
python3 scripts/purple/purple_attack_orchestrator.py --technique T1055
```

## 🧪 Laboratorios de Práctica

### Labs Disponibles
- **lab-cloud-misconfig**: Errores de configuración en AWS
- **lab-edr-evasion**: Técnicas de evasión de EDR
- **lab-red-vs-blue-core**: Competencia Red vs Blue
- **lab-phishing-campaign**: Simulación de phishing

### Gestión de Labs
```bash
# Iniciar laboratorio
cd labs/lab-edr-evasion
docker-compose up -d

# Ver estado
docker-compose ps

# Detener laboratorio
docker-compose down
```

## 🎓 Modo Estudio

### Lecciones Disponibles
- **SQL Injection**: Inyección SQL con validación automática
- **XSS**: Cross-Site Scripting con laboratorio integrado
- **Post Exploitation**: Técnicas post-explotación Linux/Windows
- **Privilege Escalation**: Escalada de privilegios práctica

### Uso del Modo Estudio
1. Accede al panel web en `/study`
2. Selecciona una lección
3. Lee el contenido teórico
4. Completa los ejercicios prácticos
5. Valida tu progreso

## 📊 Características Avanzadas v2.2.0

### Carga Dinámica YAML
- Scripts auto-detectados desde archivos `.yaml`
- Metadata completa: autor, riesgo, privilegios, contramedidas
- Sincronización automática Web/CLI/API

### Logging Persistente
- Registro completo de ejecuciones en `logs/executions.log`
- Historial navegable desde `/history`
- Exportación de resultados

### Sistema de Alertas
- Advertencias para herramientas ofensivas
- Badges de riesgo: Educational, High Risk, Defensive
- Confirmación ética antes de ejecutar

## 🔐 Consideraciones de Seguridad

### Uso Ético
- **Solo en entornos autorizados**
- **Fines educativos y de investigación**
- **Cumplimiento de leyes locales**

### Aislamiento
- Ejecución en contenedores Docker
- Red aislada para laboratorios
- Logs detallados para auditoría

## 🤝 Contribución

### Desarrollador Principal
- **David Hernández Jiménez (@descambiado)**
- **Email**: david@descambiado.com
- **GitHub**: https://github.com/descambiado

### Cómo Contribuir
1. Fork del repositorio
2. Crear rama de feature: `git checkout -b feature/nueva-herramienta`
3. Desarrollar con documentación YAML
4. Testing en entorno aislado
5. Pull Request con descripción detallada

### Agregar Nuevos Scripts
```yaml
# scripts/categoria/mi_script.yaml
name: "Mi Script"
description: "Descripción de la herramienta"
category: "red"
author: "@mi_usuario"
version: "1.0"
last_updated: "2025-06-19"
impact_level: "MEDIUM"
educational_value: 5
parameters:
  - name: target
    type: string
    required: true
    description: "IP objetivo"
```

## 📋 Roadmap v2.3.0

- [ ] Integración con Elastic Stack
- [ ] Dashboard de métricas en tiempo real
- [ ] Módulo de Machine Learning para detección
- [ ] Reportes automáticos PDF
- [ ] API GraphQL
- [ ] Integración con Telegram Bot
- [ ] Soporte para Kubernetes

## 📜 Licencia

MIT License - Ver archivo `LICENSE` para detalles completos.

## 🙏 Reconocimientos

- Comunidad de ciberseguridad open source
- Proyectos inspiradores: BloodHound, Metasploit, MITRE ATT&CK
- Todos los contribuidores y testers

---

**BOFA v2.2.0 - UX Consolidation & Intelligence Layer**  
*Desarrollado con ❤️ por @descambiado*

Para soporte técnico: `python3 cli/bofa_cli.py --help` o consulta la documentación en `/docs`
