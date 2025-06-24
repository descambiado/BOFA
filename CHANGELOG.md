
# 📦 BOFA – CHANGELOG

## v2.3.0 – Sistema de Reportes Profesionales + CVEs Recientes (2025-06-19)

### 🆕 Nuevas Características
- **Sistema de Reportes Profesionales**
  - Generación automática de reportes en PDF, Markdown y JSON
  - Exportación desde Web, CLI y API
  - Contenido completo: metadatos, parámetros, resultados, errores, timing
  - Estructura organizada en `/reports/` con subcarpetas por formato
  
- **Nuevos Scripts de Vulnerabilidades 2024-2025**
  - `cve_2024_springauth_bypass.py` - Simulador de bypass Spring Security
  - `cve_2025_kernel_overlay.py` - Simulador overlayfs kernel Linux
  - `http2_rapid_reset_dos.py` - Simulador DoS HTTP/2 Rapid Reset
  
- **Herramientas OSINT Avanzadas**
  - `telegram_user_scraper.py` - Extractor de usuarios de grupos públicos
  - `public_email_validator.py` - Verificador con HaveIBeenPwned
  - `github_repo_leak_detector.py` - Detector de secretos en repos públicos

### 🚀 Mejoras de API
- Nuevos endpoints `/reports/latest`, `/reports/pdf`, `/reports/markdown`, `/reports/json`
- Sistema de logging persistente mejorado
- Carga dinámica de scripts desde YAML optimizada
- Endpoint `/reports/list` para listar reportes disponibles

### 🎨 Mejoras de Interfaz
- Componente `ReportExporter` integrado en ScriptExecutor
- Modal de selección de formato de exportación
- Vista previa de contenido de reportes
- Descarga directa desde navegador
- Iconografía mejorada para tipos de archivo

### 🏗️ Infraestructura
- Estructura de directorios `/reports/` automatizada
- Documentación completa en `/reports/README.md`
- Soporte para múltiples formatos de exportación
- Manejo de errores mejorado en generación de reportes

### 📚 Laboratorios Nuevos
- `lab-zero-day-scanner` - Emulador de CVEs recientes (Log4Shell, Spring4Shell)
- `lab-android-emulation` - Entorno Android 11 para testing móvil
- `lab-ctf-generator` - Generador automático de retos CTF

### 🔧 Correcciones
- Validación mejorada de parámetros de entrada
- Manejo de caracteres especiales en nombres de archivo
- Optimización de memoria en generación de reportes grandes
- Compatibilidad mejorada entre formatos de exportación

---

## v2.2.0 – Consolidación total + Auto-carga + UX optimizado (2025-06-19)

### 🆕 Nuevas Características
- Carga automática de scripts desde archivos YAML
- Sistema de logging persistente de ejecuciones
- Nuevo endpoint `/history` para historial de ejecuciones
- Interfaz web enriquecida con historial y mejoras visuales
- Documentación automática generada

### 🚀 Mejoras de API
- Reemplazo de MODULES_DATA estático por carga dinámica
- Lectura automática de metadata desde `/scripts/**/*.yaml`
- Reconstrucción automática de estructura de módulos
- Compatibilidad completa entre Web, CLI y API

### 🎨 Mejoras de Interfaz
- Nueva página de Historial de Ejecuciones
- Tooltips informativos en scripts
- Estados de ejecución en tiempo real
- Carga visual mejorada desde metadata YAML
- Navegación optimizada entre secciones

### 🏗️ Infraestructura
- Sistema de logs persistente en `/logs/executions.log`
- Estructura JSON para almacenar ejecuciones
- Endpoints RESTful para consulta de historial
- Validación robusta de rutas y parámetros

---

## v2.1.0 – Plataforma web + Alertas + Nuevos scripts (2025-06-18)

### 🆕 Nuevas Características
- Interfaz web completa con React + TypeScript
- Sistema de alertas y badges de riesgo
- Módulos Blue Team, Purple Team y Forensics
- Consola de ejecución en tiempo real
- Gestión visual de parámetros de script

### 🚀 Nuevos Scripts
- `ioc_matcher.py` - Análisis de Indicadores de Compromiso
- `threat_emulator.py` - Simulador de comportamiento de amenazas
- `log_timeline_builder.py` - Generador de líneas de tiempo desde logs
- `ad_enum_visualizer.py` - Visualizador estilo BloodHound para AD
- `ghost_scanner.py` - Escáner sigiloso con randomización

### 🎨 Interfaz Web
- Dashboard principal con métricas del sistema
- Ejecutor de scripts con parámetros dinámicos
- Consola con logs coloreados y timestamps
- Alertas contextuales por nivel de riesgo
- Modo responsive para móviles y tablets

---

## v2.0.0 – Sistema completo: Red, Blue, Purple, Labs (2025-06-17)

### 🆕 Características Principales
- Arquitectura modular completa (CLI + Web + API)
- Laboratorios Docker para práctica segura
- Scripts organizados por metodología (Red/Blue/Purple Team)
- Sistema de metadatos YAML para cada herramienta
- Modo estudio con lecciones interactivas

### 🛠️ Módulos Implementados
- **Red Team**: Arsenal ofensivo y técnicas de penetración
- **Blue Team**: Herramientas defensivas y análisis forense
- **Purple Team**: Ejercicios coordinados de ataque y defensa
- **Labs**: Entornos vulnerables controlados
- **Study**: Lecciones educativas paso a paso

### 🚀 Infraestructura
- API FastAPI con documentación automática
- Frontend React con Vite y Tailwind CSS
- CLI Python multiplataforma
- Docker Compose para despliegue completo
- Nginx con SSL para acceso seguro

---

## v1.0.0 – Estructura base, CLI, Web, API, Docker (2025-06-15)

### 🎯 Funcionalidades Base
- CLI funcional para ejecutar scripts localmente
- API REST básica para integración
- Interfaz web inicial
- Sistema de contenedores Docker
- Scripts base para reconocimiento y análisis

### 🔧 Herramientas Iniciales
- Port scanner básico
- Analizador de logs de autenticación
- Detector de servicios web
- Validador de configuraciones

### 🏗️ Arquitectura
- Estructura de proyecto organizada
- Sistema de configuración
- Documentación base
- Instaladores para Linux y Windows

---

**Desarrollado por**: @descambiado (David Hernández Jiménez)  
**Licencia**: MIT  
**Repositorio**: BOFA Professional Security Suite
