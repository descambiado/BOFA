
# 🚀 BOFA Professional Suite v2.5.0

## Suite Completa de Ciberseguridad con Enfoque Educativo y Profesional

**BOFA Professional Suite** es una plataforma integral de ciberseguridad que combina herramientas de pentesting, análisis forense, educación en seguridad y laboratorios de práctica en un entorno unificado y profesional.

### ✨ Características Principales v2.5.0

#### 🔧 **150+ Herramientas Especializadas**
- **Red Team**: 25 herramientas ofensivas avanzadas
- **Blue Team**: 18 herramientas defensivas con IA
- **Purple Team**: 12 ejercicios coordinados
- **Análisis Forense**: 15 herramientas de investigación
- **OSINT**: 12 herramientas de inteligencia
- **Malware Analysis**: 10 analizadores estáticos/dinámicos
- **Social Engineering**: 6 herramientas de concienciación
- **Mobile Security**: 8 herramientas para dispositivos móviles

#### 🤖 **Innovaciones 2025**
- **AI Threat Hunter**: ML local + MITRE ATT&CK para detección de amenazas
- **Quantum-Safe Crypto Analyzer**: Preparación para era post-cuántica
- **Supply Chain Scanner**: Seguridad en cadenas de suministro
- **Zero Trust Validator**: Validación de implementaciones Zero Trust
- **Deepfake Detection Engine**: Detección de contenido multimedia sintético
- **Cloud Native Attack Simulator**: Testing de contenedores y Kubernetes
- **IoT Security Mapper**: Mapeo de seguridad en dispositivos IoT

#### 📚 **Sistema Educativo Integrado**
- Lecciones interactivas con markdown
- Evaluaciones prácticas
- Certificaciones BOFA
- Progreso trackeable
- Laboratorios hands-on

#### 🧪 **Laboratorios de Práctica**
- Entornos Docker containerizados
- Aplicaciones vulnerables (DVWA, WebGoat, Juice Shop)
- Redes simuladas
- Ambientes Android
- CTF challenges

### 🏗️ Arquitectura Técnica

```
BOFA Professional Suite v2.5.0
├── Frontend (React + TypeScript + Vite)
│   ├── Dashboard interactivo
│   ├── Ejecución de scripts en tiempo real
│   ├── Sistema de reportes avanzado
│   └── UI/UX profesional con Tailwind + shadcn/ui
├── Backend API (FastAPI + Python)
│   ├── Gestión de scripts y módulos
│   ├── Sistema de ejecución segura
│   ├── Base de datos de resultados
│   └── Autenticación y autorización
├── Scripts Engine (Python + Bash + PowerShell)
│   ├── 150+ herramientas categorizadas
│   ├── Metadata YAML para configuración
│   ├── Sistema de parámetros dinámicos
│   └── Logging y reportes estructurados
├── Labs Infrastructure (Docker + Compose)
│   ├── Entornos aislados por categoría
│   ├── Aplicaciones vulnerables
│   ├── Redes simuladas
│   └── Gestión automática de estado
└── Study System
    ├── Lecciones en Markdown
    ├── Evaluaciones interactivas
    ├── Certificaciones
    └── Progreso personalizado
```

### 🚀 Instalación y Configuración

#### Requisitos del Sistema
- **Docker** y **Docker Compose**
- **Git** para clonado del repositorio
- **8GB RAM** mínimo (16GB recomendado)
- **50GB** espacio en disco
- **Linux/macOS/Windows** con WSL2

#### Instalación Rápida

```bash
# 1. Clonar el repositorio
git clone https://github.com/descambiado/bofa-professional-suite.git
cd bofa-professional-suite

# 2. Configurar variables de entorno
cp .env.example .env
# Editar .env con tu configuración

# 3. Construir y ejecutar todos los servicios
docker-compose up -d

# 4. Verificar el estado de los servicios
docker-compose ps

# 5. Acceder a la aplicación
# Frontend: http://localhost:3000
# API: http://localhost:8000
# NGINX: http://localhost (puerto 80)
```

#### Instalación Manual (Desarrollo)

```bash
# Frontend
cd web
npm install
npm run dev

# Backend API
cd api
pip install -r requirements.txt
uvicorn main:app --reload

# CLI (opcional)
cd cli
pip install -r requirements.txt
python bofa_cli.py --help
```

### 📊 Módulos Disponibles

| Módulo | Scripts | Descripción | Novedad 2025 |
|--------|---------|-------------|--------------|
| **Red Team** | 25 | Arsenal ofensivo + Supply Chain + Cloud Native | ✅ |
| **Blue Team** | 18 | Defensas + AI Threat Hunting + Zero Trust | ✅ |
| **Purple Team** | 12 | Ejercicios + Quantum Crypto + Biometrics | ✅ |
| **Forensics** | 15 | Investigación + Deepfake Detection + Timeline | ✅ |
| **OSINT** | 12 | Inteligencia + IoT Security Mapping | ✅ |
| **Malware** | 10 | Análisis estático/dinámico + ML Detection | ✅ |
| **Social Eng** | 6 | Concienciación + Phishing Training | ✅ |
| **Mobile** | 8 | Android + iOS Testing + Wireless | - |
| **Recon** | 8 | Network Mapping + Advanced Scanning | - |
| **Insight** | 7 | AI Recommendations + Usage Analytics | ✅ |

### 🛠️ Ejemplos de Uso

#### Ejecutar Análisis de Amenazas con IA
```bash
# Interfaz Web
1. Navegar a Scripts > Blue Team > AI Threat Hunter
2. Configurar parámetros (archivo de logs, umbral)
3. Ejecutar y revisar resultados en tiempo real

# CLI
python scripts/blue/ai_threat_hunter.py --log-file security.log --threshold 0.7
```

#### Iniciar Laboratorio de Seguridad Web
```bash
# Desde la interfaz web
1. Ir a Labs > Web Application Security
2. Hacer clic en "Iniciar Laboratorio"
3. Acceder a http://localhost:8080 (DVWA)

# Desde línea de comandos
docker-compose -f labs/web-application-security/docker-compose.yml up -d
```

#### Análisis de Malware
```bash
# Analizar archivo sospechoso
python scripts/malware/malware_analyzer.py \
  --file suspicious.exe \
  --analysis-depth deep \
  --output-format json
```

### 📈 Sistema de Reportes

BOFA genera reportes profesionales en múltiples formatos:

- **JSON**: Datos estructurados para integración
- **CSV**: Análisis en Excel/hojas de cálculo
- **HTML**: Reportes visuales profesionales
- **PDF**: Documentos ejecutivos (próximamente)

Ejemplo de exportación:
```javascript
// Desde la interfaz web
ReportExporter.generate({
  format: 'html',
  execution: executionData,
  includeEvidence: true,
  template: 'professional'
});
```

### 🎓 Sistema Educativo

#### Lecciones Disponibles
- **Seguridad en Aplicaciones Web** (180 min)
- **Penetration Testing de Redes** (240 min)
- **Análisis de Malware** (300 min)
- **Ingeniería Social y Concienciación** (120 min)
- **Forensics Digital** (200 min)

#### Certificaciones BOFA
- **BOFA Web Application Security Specialist**
- **BOFA Network Penetration Tester**
- **BOFA Malware Analysis Expert**
- **BOFA Digital Forensics Investigator**

### 🧪 Laboratorios Incluidos

| Laboratorio | Dificultad | Tiempo | Puertos |
|-------------|------------|--------|---------|
| Web App Security | Intermedio | 240 min | 8080-8083 |
| Red Interna Corp | Intermedio | 180 min | 8100-8110 |
| Android Security | Avanzado | 150 min | 5555 |
| CTF Generator | Variable | 60-180 min | 8200-8220 |
| Cloud Misconfig | Avanzado | 120 min | 8300-8310 |
| SIEM Detection | Avanzado | 200 min | 443, 1514 |

### 🔧 Configuración Avanzada

#### Variables de Entorno
```bash
# .env
API_BASE_URL=http://localhost:8000
FRONTEND_PORT=3000
BACKEND_PORT=8000
MYSQL_ROOT_PASSWORD=secure_password
REDIS_PASSWORD=redis_password
JWT_SECRET=your_jwt_secret_here
ENCRYPTION_KEY=your_encryption_key

# Configuración SSL (Producción)
SSL_CERT_PATH=/path/to/cert.pem
SSL_KEY_PATH=/path/to/key.pem
HTTPS_ENABLED=true
```

#### Personalización de Scripts
```yaml
# scripts/custom/my_tool.yaml
name: "my_custom_tool"
category: "custom"
description: "Mi herramienta personalizada"
parameters:
  target:
    type: "string"
    required: true
  mode:
    type: "select" 
    options: ["scan", "exploit", "report"]
execution:
  timeout: 300
  memory_limit: "512MB"
```

### 📊 Métricas y Monitoreo

#### Dashboard en Tiempo Real
- Estadísticas de ejecución
- Estado de laboratorios
- Progreso educativo
- Métricas de seguridad
- Alertas del sistema

#### Logging Avanzado
```python
# Configuración de logs
LOGGING = {
    'version': 1,
    'handlers': {
        'file': {
            'class': 'logging.FileHandler',
            'filename': 'bofa.log',
            'formatter': 'detailed'
        },
        'elasticsearch': {
            'class': 'elasticsearch_logger.ElasticsearchHandler',
            'hosts': ['localhost:9200']
        }
    }
}
```

### 🔒 Seguridad y Cumplimiento

#### Medidas de Seguridad Implementadas
- **Ejecución Sandboxed**: Scripts ejecutados en contenedores aislados
- **Autenticación JWT**: Tokens seguros para API
- **Rate Limiting**: Prevención de abuso
- **Audit Logging**: Registro completo de actividades
- **Input Validation**: Validación estricta de parámetros
- **HTTPS/TLS**: Cifrado en tránsito
- **Secrets Management**: Gestión segura de credenciales

#### Cumplimiento
- **OWASP Guidelines**: Desarrollo seguro
- **NIST Framework**: Gestión de riesgos
- **ISO 27001**: Gestión de seguridad de información
- **GDPR**: Protección de datos personales

### 🤝 Contribuciones

#### Cómo Contribuir
1. Fork del repositorio
2. Crear rama feature (`git checkout -b feature/nueva-funcionalidad`)
3. Commit de cambios (`git commit -am 'Agregar nueva funcionalidad'`)
4. Push a la rama (`git push origin feature/nueva-funcionalidad`)
5. Crear Pull Request

#### Guidelines
- Código limpio y documentado
- Tests unitarios incluidos
- Documentación actualizada
- Seguir convenciones de naming
- Metadata YAML para nuevos scripts

### 📞 Soporte y Documentación

#### Recursos Oficiales
- **Documentación**: `/docs` en el repositorio
- **Wiki**: Guías detalladas y troubleshooting
- **Issues**: Reportar bugs y solicitar features
- **Discussions**: Comunidad y Q&A

#### Contacto
- **Autor**: @descambiado (David Hernández Jiménez)
- **Email**: [contacto disponible en GitHub]
- **LinkedIn**: Perfil profesional
- **Twitter**: Actualizaciones del proyecto

### 📝 Changelog v2.5.0

#### ✨ Nuevas Características
- Sistema completo de 150+ scripts organizados por categoría
- 7 nuevas herramientas con tecnología 2025 (AI, Quantum, Supply Chain)
- Sistema educativo completo con certificaciones
- 6 laboratorios Docker listos para producción
- Dashboard mejorado con métricas en tiempo real
- Sistema de reportes en 4 formatos
- API robusta con fallback automático
- CLI mejorado para automatización

#### 🔧 Mejoras Técnicas
- Arquitectura refactorizada para escalabilidad
- Sistema de parámetros dinámicos para scripts
- Logging estructurado y centralizado
- Contenedorización completa con Docker
- CI/CD pipeline optimizado
- Testing automatizado
- Documentación técnica completa

#### 🐛 Correcciones
- Resolución de errores de TypeScript
- Mejora en manejo de errores de API
- Optimización de consultas de base de datos
- Corrección de memory leaks en frontend
- Estabilización de laboratorios Docker

### 📄 Licencia

Este proyecto está licenciado bajo la Licencia MIT - ver el archivo [LICENSE](LICENSE) para detalles.

### 🌟 Agradecimientos

- **Comunidad OWASP** por frameworks y guidelines
- **Contribuidores** de herramientas open source utilizadas
- **Comunidad de Ciberseguridad** por feedback y testing
- **Docker Community** por la plataforma de containerización

---

**BOFA Professional Suite v2.5.0** - Suite Profesional de Ciberseguridad

Desarrollado con ❤️ por @descambiado | [GitHub](https://github.com/descambiado) | [LinkedIn](https://linkedin.com/in/descambiado)

---

> ⚠️ **Disclaimer**: Esta herramienta está diseñada únicamente para fines educativos, testing de seguridad autorizado y desarrollo profesional. El uso malintencionado está estrictamente prohibido y es responsabilidad del usuario cumplir con las leyes locales e internacionales.
