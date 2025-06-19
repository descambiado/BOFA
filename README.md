
# 🛡️ BOFA - Best Of All
### Suite Profesional de Ciberseguridad Ofensiva y Defensiva
#### 🌐 Compatible con Windows 11, WSL2, Linux y macOS

---

## 📌 Descripción

**BOFA (Best Of All)** es una suite profesional de ciberseguridad multiplataforma que integra herramientas de:
- 🕵️ **Pentesting** y Reconocimiento
- 🔍 **OSINT** (Open Source Intelligence)  
- 🎯 **Ingeniería Social**
- 🛡️ **Blue Team** y Defensa
- 🟣 **Purple Team** y Validación
- 🧪 **Análisis de Malware**
- 🐳 **Docker Labs** y Simulaciones
- 🎓 **Entorno Educativo**

### 👨‍💻 Desarrollado por:
**@descambiado** (David Hernández Jiménez)  
*Administración de Sistemas Informáticos en Red*  
*Ciberseguridad | Pentesting | Consultor IT/CIBERSEC | Estudiante*

---

## 🚀 Instalación Rápida

### 🪟 Windows 11 (PowerShell como Administrador)
```powershell
# Opción 1: Instalador automático
iwr -useb https://raw.githubusercontent.com/descambiado/BOFA/main/install-windows.ps1 | iex

# Opción 2: Manual
git clone https://github.com/descambiado/BOFA
cd BOFA
.\bofa-universal.sh
```

### 🐧 Linux (Ubuntu, Kali, Debian, Fedora, Arch)
```bash
# Opción 1: Instalador automático
curl -sSL https://raw.githubusercontent.com/descambiado/BOFA/main/install-linux.sh | bash

# Opción 2: Manual
git clone https://github.com/descambiado/BOFA
cd BOFA
chmod +x bofa-universal.sh
./bofa-universal.sh
```

### 🔄 WSL2 (Windows Subsystem for Linux)
```bash
# Dentro de WSL2 (Ubuntu/Debian)
curl -sSL https://raw.githubusercontent.com/descambiado/BOFA/main/install-linux.sh | bash
# BOFA detectará automáticamente que está en WSL2
```

### 🍎 macOS
```bash
# Requiere Homebrew
brew install python3 git docker
git clone https://github.com/descambiado/BOFA
cd BOFA
./bofa-universal.sh
```

---

## 🎯 Métodos de Uso

### Método 1: CLI Interactiva (Funciona en todos los sistemas)
```bash
# Linux/WSL2/macOS
./bofa-universal.sh

# Windows (Git Bash)
bash bofa-universal.sh

# Windows (PowerShell)
python cli/bofa_cli.py
```

### Método 2: Docker Compose (Recomendado para desarrollo)
```bash
# Todos los sistemas con Docker
docker-compose up --build

# Acceso:
# • Web: http://localhost:3000
# • API: http://localhost:8000
# • Panel seguro: https://localhost
```

### Método 3: Contenedor Individual
```bash
# Solo CLI
docker run -it --rm -v $(pwd)/scripts:/app/scripts descambiado/bofa-cli

# Solo Web
docker run -p 3000:3000 descambiado/bofa-web
```

---

## 🌐 Compatibilidad de Sistemas

| Sistema | Estado | Método Recomendado | Notas |
|---------|--------|-------------------|-------|
| ![Windows](https://img.shields.io/badge/Windows%2011-0078D4?logo=windows&logoColor=white) | ✅ **Completo** | PowerShell + Docker Desktop | Scripts .ps1 incluidos |
| ![WSL2](https://img.shields.io/badge/WSL2-0078D4?logo=windows&logoColor=white) | ✅ **Completo** | Instalador Linux | Detección automática |
| ![Ubuntu](https://img.shields.io/badge/Ubuntu-E95420?logo=ubuntu&logoColor=white) | ✅ **Completo** | Instalador nativo | Soporte completo |
| ![Kali](https://img.shields.io/badge/Kali%20Linux-557C94?logo=kalilinux&logoColor=white) | ✅ **Completo** | apt + Docker | Optimizado |
| ![Debian](https://img.shields.io/badge/Debian-A81D33?logo=debian&logoColor=white) | ✅ **Completo** | apt + Docker | Estable |
| ![Fedora](https://img.shields.io/badge/Fedora-294172?logo=fedora&logoColor=white) | ✅ **Completo** | dnf + Docker | Soporte RPM |
| ![Arch](https://img.shields.io/badge/Arch%20Linux-1793D1?logo=arch-linux&logoColor=white) | ✅ **Completo** | pacman + Docker | Rolling release |
| ![macOS](https://img.shields.io/badge/macOS-000000?logo=macos&logoColor=white) | ✅ **Beta** | Homebrew + Docker Desktop | En pruebas |

---

## 🔧 Requisitos del Sistema

### Mínimos
- **RAM**: 2GB disponible
- **Disco**: 5GB libres
- **CPU**: x64 (AMD64/Intel64)
- **Python**: 3.8+ 
- **Git**: Para clonado

### Recomendados  
- **RAM**: 8GB+
- **Disco**: 20GB+ (para labs)
- **CPU**: 4+ cores
- **Docker**: 20.10+
- **Sistema**: Actualizado

### Dependencias Automáticas
BOFA instala automáticamente:
- Python packages (colorama, requests, rich, etc.)
- Docker Compose (si no está presente)
- Certificados SSL autofirmados
- Estructura de directorios

---

## 🛠️ Solución Problemas Comunes

### Windows 11
```powershell
# Error de ejecución de scripts
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Python no encontrado
winget install Python.Python.3.11

# Docker Desktop no inicia
# Habilitar virtualización en BIOS + WSL2
wsl --install
```

### Linux
```bash
# Permisos de Docker
sudo usermod -aG docker $USER
# Luego: logout/login

# Python/pip no encontrado (Ubuntu/Debian)
sudo apt update && sudo apt install python3 python3-pip

# Error de certificados
sudo apt install ca-certificates curl gnupg
```

### WSL2
```bash
# Docker desde Windows
export DOCKER_HOST=tcp://localhost:2375

# O instalar Docker nativo en WSL2
curl -fsSL https://get.docker.com | sh
```

---

## 🎯 Módulos Disponibles

### 🕵️ Reconocimiento (5 herramientas)
- `web_discover.py` - Descubrimiento de subdominios
- `port_slayer.sh` - Escaneo de puertos avanzado  
- `reverse_dns_flood.py` - Enumeración DNS masiva
- `wifi_shadow_mapper.sh` - Mapeo de redes WiFi
- Más en desarrollo...

### 💥 Explotación (8 herramientas)
- `reverse_shell_generator.py` - Generador reverse shells
- `kerberoast_scanner.py` - Ataques Kerberoasting
- `av_evasion_engine.py` - Motor evasión antivirus
- `dns_txt_exfil.py` - Exfiltración por DNS
- `post_exploit_enum.py` - Enumeración post-explotación
- `ai_payload_mutator.py` - Mutación de payloads con IA
- `mitre_attack_runner.py` - Simulador MITRE ATT&CK
- Más en desarrollo...

### 🔍 OSINT (3 herramientas)
- `social_profile_mapper.py` - Mapeo de perfiles sociales
- `multi_vector_osint.py` - OSINT multi-vector
- Más en desarrollo...

### 🛡️ Blue Team (6 herramientas)  
- `log_guardian.py` - Guardian de logs avanzado
- `siem_alert_simulator.py` - Simulador de alertas SIEM
- `log_baseliner.py` - Análisis de línea base
- `auth_log_parser.py` - Parser de logs de autenticación
- `defense_break_replicator.py` - Replicador de brechas defensivas
- Más en desarrollo...

### 🟣 Purple Team (2 herramientas)
- `purple_attack_orchestrator.py` - Orquestador de ataques
- Más en desarrollo...

### 🎓 Modo Estudio (4 lecciones)
- **SQL Injection** - Fundamentos e inyección avanzada
- **XSS** - Cross-Site Scripting completo  
- **Privilege Escalation** - Escalada de privilegios
- **Más lecciones** en desarrollo...

### 🐳 Laboratorios Docker (4 labs)
- `lab-web-sqli` - Aplicación web vulnerable
- `lab-ad-enum` - Enumeración Active Directory
- `lab-internal-network` - Red interna vulnerable
- `lab-siem-detection` - Laboratorio Blue Team

---

## 🌐 Servicios Web

Una vez iniciado con Docker, BOFA proporciona:

### 🔒 Panel Seguro (https://localhost)
- **Usuario**: `admin`
- **Contraseña**: `admin`
- Dashboard completo con métricas
- Terminal web integrada
- Gestión de laboratorios

### 🌍 Panel Público (http://localhost:3000)
- Interfaz React moderna
- Navegación por módulos
- Documentación interactiva
- Estado en tiempo real

### 🔗 API REST (http://localhost:8000)
- Documentación Swagger: `/docs`
- Endpoints de módulos: `/modules`  
- Ejecutor de scripts: `/scripts`
- Estado del sistema: `/health`

---

## 📊 Estructura del Proyecto

```
BOFA/
├── 🔧 cli/                    # Terminal interactiva
│   ├── bofa_cli.py           # CLI principal
│   ├── os_detector.py        # Detector de OS
│   └── requirements.txt      # Dependencias Python
├── 🌐 web/                   # Panel web React
├── 🔗 api/                   # Backend FastAPI  
├── 🐳 nginx/                 # Proxy inverso + SSL
├── 📜 scripts/               # Scripts organizados
│   ├── recon/               # Reconocimiento
│   ├── exploit/             # Explotación
│   ├── osint/               # OSINT
│   ├── blue/                # Blue Team
│   ├── purple/              # Purple Team
│   └── social/              # Ingeniería Social
├── 🎓 study/                 # Lecciones educativas
├── 🧪 labs/                  # Laboratorios Docker
├── 📚 docs/                  # Documentación
├── 🚀 install-windows.ps1    # Instalador Windows
├── 🚀 install-linux.sh       # Instalador Linux
├── 🎯 bofa-universal.sh      # Launcher universal
└── 🐳 docker-compose.yml     # Orquestación
```

---

## 🎓 Modo Educativo

BOFA incluye un completo sistema educativo:

### 📚 Lecciones Interactivas
- Teoría + práctica integrada
- Código de ejemplo ejecutable
- Evaluaciones automáticas
- Progreso trackeable

### 🧪 Laboratorios Prácticos
- Entornos aislados y seguros
- Simulaciones realistas
- Métricas de rendimiento
- Retos progresivos

### 🏆 Sistema de Logros
- Puntuación por módulo
- Badges de especialización
- Ranking de progreso
- Certificados de finalización

---

## 🤝 Contribuir al Proyecto

¡Las contribuciones son muy bienvenidas!

### 🔄 Proceso de Contribución
1. **Fork** el repositorio
2. **Crea** una rama feature (`git checkout -b feature/nueva-herramienta`)
3. **Commit** tus cambios (`git commit -am 'Añadir nueva herramienta'`)
4. **Push** a la rama (`git push origin feature/nueva-herramienta`)
5. **Abre** un Pull Request

### 📝 Tipos de Contribución
- **🛠️ Nuevos scripts** de ciberseguridad
- **🐛 Corrección** de bugs
- **📚 Documentación** mejorada
- **🧪 Nuevos laboratorios** Docker
- **🎨 Mejoras** de UI/UX
- **🔧 Optimizaciones** de rendimiento

### 📋 Guidelines
- Código documentado y comentado
- Tests cuando sea aplicable
- Seguir convenciones existentes
- Compatibilidad multiplataforma

---

## 📄 Licencia y Legal

### 📜 Licencia MIT
Este proyecto está bajo la **Licencia MIT**. Ver `LICENSE` para detalles.

### ⚖️ Aviso Legal
- **Solo para fines educativos y de investigación**
- **Uso en entornos autorizados únicamente**
- **El autor no se responsabiliza del mal uso**
- **Cumple las leyes locales de ciberseguridad**

### 🛡️ Uso Ético
BOFA está diseñado para:
- ✅ Educación en ciberseguridad
- ✅ Pentesting autorizado  
- ✅ Investigación de seguridad
- ✅ Fortalecimiento defensivo
- ❌ **NO** para actividades maliciosas

---

## 🔗 Recursos y Contacto

### 📞 Contacto
- **GitHub**: [@descambiado](https://github.com/descambiado)
- **Email**: [david@descambiado.com](mailto:david@descambiado.com)
- **LinkedIn**: [David Hernández Jiménez](https://linkedin.com/in/descambiado)
- **Web**: [descambiado.com](https://descambiado.com)

### 🌐 Enlaces Útiles
- **Documentación**: [docs.bofa.run](https://docs.bofa.run)
- **Issues**: [GitHub Issues](https://github.com/descambiado/BOFA/issues)
- **Discussions**: [GitHub Discussions](https://github.com/descambiado/BOFA/discussions)
- **Releases**: [GitHub Releases](https://github.com/descambiado/BOFA/releases)

### 📊 Estadísticas del Proyecto
![GitHub stars](https://img.shields.io/github/stars/descambiado/BOFA?style=social)
![GitHub forks](https://img.shields.io/github/forks/descambiado/BOFA?style=social)
![GitHub issues](https://img.shields.io/github/issues/descambiado/BOFA)
![GitHub license](https://img.shields.io/github/license/descambiado/BOFA)

---

## 🚀 Roadmap v2.0

### 🎯 Próximas Características
- [ ] 🤖 **IA integrada** para análisis automático
- [ ] 🌍 **API REST** completa para integración
- [ ] 📱 **App móvil** para monitoreo
- [ ] ☁️ **Despliegue cloud** (AWS, Azure, GCP)
- [ ] 🔄 **CI/CD** pipeline automatizado
- [ ] 📊 **Dashboard** de métricas avanzado
- [ ] 🎮 **Gamificación** completa
- [ ] 🌐 **Modo multi-usuario** y colaborativo

### 📅 Timeline
- **Q1 2025**: IA y API REST
- **Q2 2025**: App móvil y cloud
- **Q3 2025**: Gamificación y multi-usuario
- **Q4 2025**: BOFA v2.0 Release

---

*"La ciberseguridad no es un producto, es un proceso"* 🛡️

**¿Listo para dominar la ciberseguridad? ¡Empieza ahora con BOFA!** 🚀

```bash
curl -sSL https://raw.githubusercontent.com/descambiado/BOFA/main/install-linux.sh | bash
```
