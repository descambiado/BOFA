
# 📚 Guía de Uso - BOFA Extended Systems v2.5.0

Esta guía completa te enseñará cómo utilizar todas las características de BOFA v2.5.0.

## 🎯 Primeros Pasos

### 1. Acceso al Sistema
- **URL Principal**: http://localhost:3000
- **Dashboard**: Vista general del sistema
- **Navegación**: Menú superior para acceder a módulos

### 2. Interface Principal
La interfaz está organizada en 5 secciones principales:
- **🏠 Dashboard**: Métricas y estado general
- **⚡ Scripts**: Herramientas y scripts organizados por módulo
- **🧪 Labs**: Laboratorios de práctica interactivos
- **📊 Historial**: Registro de ejecuciones y actividades
- **📚 Estudiar**: Lecciones y material educativo

## 🏠 Dashboard - Centro de Comando

### Métricas en Tiempo Real
- **Scripts Ejecutados**: Contador total de ejecuciones
- **Amenazas Detectadas**: Alertas de seguridad activas
- **Labs Activos**: Laboratorios en funcionamiento
- **Nivel de Seguridad**: Score general del sistema

### Novedades 2025
El dashboard destaca las nuevas herramientas:
- 🤖 **AI Threat Hunter**: Detección con IA
- 🔗 **Supply Chain Scanner**: Análisis de dependencias
- 🔮 **Quantum Crypto Analyzer**: Evaluación post-cuántica
- 🎭 **Deepfake Detection**: Motor de detección IA
- ☁️ **Cloud Native Attacks**: Simulador de ataques cloud
- 🛡️ **Zero Trust Validator**: Validación ZT

### Actividad Reciente
Visualiza las últimas ejecuciones con:
- Timestamp de ejecución
- Módulo utilizado
- Estado del resultado
- Tiempo de ejecución

## ⚡ Scripts - Arsenal de Herramientas

### Navegación por Módulos

#### 🔴 Red Team (25 herramientas)
**Herramientas ofensivas y de penetración**

**Scripts Destacados 2025:**
```bash
# Supply Chain Scanner
- Mapea dependencias NPM, PyPI, Maven
- Detecta vulnerabilidades CVE
- Genera SBOM automático
- Parámetros: project_path, scan_depth, output_format

# Cloud Native Attack Simulator  
- Simula ataques a Kubernetes/Docker
- Container escape scenarios
- Privilege escalation attacks
- Parámetros: target_type, attack_scenarios, intensity_level

# Ghost Scanner
- Escaneo de red sigiloso
- Randomización TTL y MAC
- Evasión de IDS/IPS
- Parámetros: target, delay, stealth_mode
```

#### 🔵 Blue Team (18 herramientas)
**Defensiva avanzada y análisis forense**

**Scripts Destacados 2025:**
```bash
# AI Threat Hunter v2.0
- Machine Learning local
- Integración MITRE ATT&CK
- Análisis comportamental
- Parámetros: log_file, anomaly_threshold, mitre_filter

# Zero Trust Validator
- Validación de implementaciones ZT
- Verificación micro-segmentación
- Análisis least privilege
- Parámetros: environment, scope, compliance_check

# Log Guardian
- Monitoreo en tiempo real
- Detección de patrones maliciosos
- Alertas automáticas
- Parámetros: config_file, alert_threshold, output_format
```

#### 🟣 Purple Team (12 herramientas)
**Ejercicios coordinados y análisis avanzado**

**Scripts Destacados 2025:**
```bash
# Quantum Crypto Analyzer
- Evaluación post-cuántica
- Plan de migración automático
- Análisis SSL/TLS
- Parámetros: analysis_type, target_file, target_host

# Purple Attack Orchestrator
- Coordinación Red vs Blue
- Métricas de detección
- Simulaciones realistas
- Parámetros: scenario, speed_multiplier, metrics_enabled
```

#### 🔍 OSINT (12 herramientas)
**Inteligencia de fuentes abiertas**

**Scripts Destacados 2025:**
```bash
# IoT Security Mapper
- Búsqueda con Shodan API
- Mapeo geográfico
- Protocolos industriales
- Parámetros: search_query, protocols, max_results

# Multi-Vector OSINT
- Correlación multi-fuente
- Perfiles sociales
- Intelligence gathering
- Parámetros: target_email, target_name, output_format
```

### Ejecución de Scripts

#### 1. Selección y Configuración
```
1. Navegar al módulo deseado
2. Seleccionar script específico
3. Configurar parámetros requeridos
4. Revisar información de seguridad
5. Ejecutar con botón "Ejecutar Script"
```

#### 2. Parámetros Comunes
- **target**: Objetivo del análisis
- **output_format**: json, xml, csv, html
- **verbose**: Nivel de detalle en logs
- **timeout**: Tiempo máximo de ejecución
- **config_file**: Archivo de configuración personalizada

#### 3. Monitoreo de Ejecución
- **Console en tiempo real**: Salida del script
- **Progress indicator**: Barra de progreso
- **Status updates**: Estados de ejecución
- **Error handling**: Gestión de errores

## 🧪 Labs - Laboratorios de Práctica

### Laboratorios Disponibles

#### 1. Web Application Security Lab
```yaml
Descripción: OWASP Top 10 completo
Dificultad: Intermedio
Tiempo: 4 horas
Puerto: 8080
URL: http://localhost:8080

Vulnerabilidades incluidas:
- SQL Injection avanzado
- XSS (Stored, Reflected, DOM)
- CSRF con tokens
- XXE (XML External Entity)
- Insecure Deserialization
- SSRF (Server-Side Request Forgery)
```

#### 2. Red Interna Corporativa
```yaml
Descripción: Simulación de red empresarial
Dificultad: Intermedio  
Tiempo: 3 horas
Servicios: AD, SMB, RDP, SSH, HTTP

Escenarios:
- Enumeración de Active Directory
- Lateral movement
- Privilege escalation
- Persistence techniques
```

#### 3. Android Security Lab
```yaml
Descripción: Testing de seguridad móvil
Dificultad: Avanzado
Tiempo: 2.5 horas
Puerto: 5555

Características:
- Apps vulnerables preinstaladas
- Análisis de tráfico HTTPS
- Reverse engineering tools
- Dynamic analysis
```

#### 4. Kubernetes Security Cluster
```yaml
Descripción: Seguridad en contenedores
Dificultad: Avanzado
Tiempo: 5 horas
Puerto: 6443

Vulnerabilidades:
- Privileged containers
- RBAC misconfigurations
- Network policy bypass
- Pod escape scenarios
```

#### 5. IoT/OT Simulation Environment
```yaml
Descripción: Dispositivos industriales
Dificultad: Experto
Tiempo: 6 horas
Puerto: 8502

Protocolos:
- Modbus TCP/RTU
- DNP3
- BACnet
- MQTT
- CoAP
```

### Gestión de Laboratorios

#### Controles Disponibles
- **▶️ Iniciar**: Activar laboratorio
- **⏹️ Detener**: Parar laboratorio
- **🔄 Reiniciar**: Reset completo
- **📊 Monitorear**: Ver métricas
- **📝 Logs**: Acceso a logs del lab

#### Estados del Laboratorio
- **🟢 Running**: Activo y accesible
- **🔴 Stopped**: Detenido
- **🟡 Starting**: Iniciándose
- **🔵 Error**: Error en ejecución

## 📊 Historial - Tracking de Actividades

### Vista de Ejecuciones
El historial muestra todas las ejecuciones con:
- **Timestamp**: Fecha y hora exacta
- **Script**: Herramienta ejecutada
- **Módulo**: Categoría del script
- **Parámetros**: Configuración utilizada
- **Estado**: Success, Warning, Error
- **Tiempo**: Duración de ejecución
- **Output**: Resultado de la ejecución

### Filtros y Búsqueda
```bash
# Filtros disponibles
- Por módulo (Red, Blue, Purple, etc.)
- Por estado (Success, Warning, Error)
- Por rango de fechas
- Por script específico
- Búsqueda por texto libre
```

### Exportación de Datos
- **JSON**: Para análisis programático
- **CSV**: Para análisis en Excel
- **PDF**: Reportes formales
- **HTML**: Reportes visuales

## 📚 Estudiar - Sistema Educativo

### Cursos Disponibles

#### 1. Seguridad en Aplicaciones Web (3h)
```
Módulos:
- OWASP Top 10 2023
- Técnicas de bypass WAF
- Secure coding practices
- Testing automatizado

Evaluación:
- Quizzes interactivos
- Labs prácticos
- CTF challenges
```

#### 2. Penetration Testing de Redes (4h)
```
Contenido:
- Metodología OWASP Testing Guide
- Técnicas de enumeración avanzada
- Post-explotación
- Reporting profesional

Herramientas:
- Nmap scripting
- Metasploit avanzado
- Custom payload creation
```

#### 3. Análisis de Malware Avanzado (5h)
```
Técnicas:
- Static analysis deep dive
- Dynamic analysis sandbox
- Reverse engineering
- IOC extraction
- Threat intelligence

Labs:
- Real malware samples (seguro)
- Analysis workflows
- Reporting techniques
```

### Sistema de Progreso
- **Progress tracking**: % de completitud
- **Badges y logros**: Gamificación
- **Certificados**: Al completar cursos
- **Leaderboard**: Competencia sana

## 🔧 Configuración Avanzada

### Personalización de Scripts

#### Crear Scripts Personalizados
```yaml
# scripts/custom/mi_script.yaml
name: "mi_herramienta_custom"
description: "Mi herramienta personalizada"
category: "custom"
author: "mi_usuario"
version: "1.0"
parameters:
  target:
    type: "string"
    required: true
    description: "Objetivo del análisis"
  depth:
    type: "select" 
    options: ["shallow", "deep", "comprehensive"]
    default: "deep"
```

#### Integración de APIs Externas
```bash
# Variables de entorno para APIs
SHODAN_API_KEY=tu_key_aqui
VIRUSTOTAL_API_KEY=tu_key_aqui
HIBP_API_KEY=tu_key_aqui

# Uso en scripts
export SHODAN_API_KEY
python3 scripts/osint/iot_security_mapper.py --api-key $SHODAN_API_KEY
```

### Configuración de Alertas
```json
{
  "alerts": {
    "email": {
      "enabled": true,
      "smtp_server": "smtp.gmail.com",
      "smtp_port": 587,
      "recipients": ["admin@empresa.com"]
    },
    "webhook": {
      "enabled": true,
      "url": "https://hooks.slack.com/services/...",
      "format": "slack"
    },
    "thresholds": {
      "high_risk_detection": true,
      "failed_executions": 3,
      "unusual_activity": true
    }
  }
}
```

## 📈 Monitoreo y Métricas

### Dashboard Analytics
- **Gráficos en tiempo real**: Uso por módulo
- **Heatmaps**: Actividad por horario
- **Trends**: Tendencias de uso semanal/mensual
- **Performance**: Métricas de rendimiento

### Logs Avanzados
```bash
# Ubicación de logs
/var/log/bofa/
├── app.log                 # Logs de aplicación
├── scripts/                # Logs por script
│   ├── red_team.log
│   ├── blue_team.log
│   └── purple_team.log
├── labs/                   # Logs de laboratorios
└── security.log           # Eventos de seguridad
```

### Integración SIEM
```python
# Ejemplo de envío a SIEM
def send_to_siem(event_data):
    siem_payload = {
        "timestamp": event_data["timestamp"],
        "source": "BOFA",
        "event_type": event_data["type"],
        "severity": event_data["severity"],
        "details": event_data["details"]
    }
    
    requests.post(
        "https://your-siem.com/api/events",
        json=siem_payload,
        headers={"Authorization": f"Bearer {SIEM_TOKEN}"}
    )
```

## 🚨 Mejores Prácticas de Uso

### Seguridad Operacional
1. **Solo en entornos autorizados**
2. **Documentar todas las ejecuciones**
3. **Revisar logs regularmente** 
4. **Mantener actualizaciones**
5. **Backup de configuraciones**

### Flujo de Trabajo Recomendado
```
1. Planning
   ├── Definir objetivos
   ├── Seleccionar herramientas
   └── Configurar parámetros

2. Execution
   ├── Ejecutar en entorno controlado
   ├── Monitorear resultados
   └── Documentar hallazgos

3. Analysis
   ├── Revisar outputs
   ├── Correlacionar datos
   └── Generar reportes

4. Follow-up
   ├── Implementar mejoras
   ├── Actualizar procedimientos
   └── Compartir knowledge
```

### Tips de Rendimiento
- **Ejecutar scripts de forma secuencial** para evitar sobrecarga
- **Usar filtros** para optimizar búsquedas
- **Configurar timeouts** apropiados
- **Monitorear uso de recursos** del sistema
- **Limpiar logs antiguos** periódicamente

## 📞 Soporte y Troubleshooting

### Problemas Comunes

#### 1. Script No Responde
```bash
# Verificar proceso
ps aux | grep python
ps aux | grep node

# Revisar logs
tail -f /var/log/bofa/app.log

# Reiniciar servicio
docker-compose restart
```

#### 2. Laboratorio No Inicia
```bash
# Verificar puertos
netstat -tulpn | grep :8080

# Revisar contenedores
docker ps -a
docker logs lab_container_name

# Limpiar y reiniciar
docker-compose down
docker system prune
docker-compose up -d
```

#### 3. Performance Lento
```bash
# Verificar recursos
htop
df -h
docker stats

# Optimizar
docker system prune -a
npm run build --prod
```

### Contacto de Soporte
- **Discord**: [Comunidad BOFA](https://discord.gg/bofa)
- **Email**: david@descambiado.com
- **GitHub Issues**: [Reportar problemas](https://github.com/descambiado/BOFA/issues)
- **Documentación**: [docs.bofa.dev](https://docs.bofa.dev)

---

¡Ahora estás listo para aprovechar al máximo BOFA v2.5.0! 🚀

Recuerda siempre usar las herramientas de forma ética y responsable.
