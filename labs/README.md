# 🧪 BOFA Labs Collection v2.5.0

Laboratorios de práctica interactivos para aprendizaje de ciberseguridad.

## 🏗️ Laboratorios Disponibles

### 1. 🌐 Web Application Security Lab
**Dificultad**: Intermedio | **Tiempo**: 4 horas | **Puerto**: 8080

Entorno completo con vulnerabilidades del OWASP Top 10:
- **SQL Injection**: Múltiples variantes (blind, time-based, union)
- **XSS**: Stored, Reflected, DOM-based
- **CSRF**: Con y sin tokens de protección
- **XXE**: XML External Entity attacks
- **Insecure Deserialization**: PHP/Java unserialize vulnerabilities
- **SSRF**: Server-Side Request Forgery
- **Path Traversal**: Directory traversal attacks
- **Authentication Bypass**: Múltiples técnicas
- **Session Management**: Vulnerabilidades de sesión
- **File Upload**: Bypass de validaciones

```bash
# Iniciar laboratorio
docker-compose --profile labs up web-security-lab -d

# Acceder
http://localhost:8080
```

### 2. 🏢 Corporate Network Lab
**Dificultad**: Intermedio | **Tiempo**: 3 horas | **Puertos**: 2222, 8081, 4443

Simulación de red empresarial vulnerable:
- **Active Directory**: Domain Controller con vulnerabilidades
- **SMB Shares**: Recursos compartidos mal configurados
- **SSH Services**: Configuraciones débiles
- **Web Applications**: Servicios internos vulnerables
- **Database Services**: MSSQL con credenciales débiles
- **RDP Services**: Remote Desktop con ataques de fuerza bruta

**Servicios Incluidos**:
```
- Windows Server 2019 (Domain Controller)
- Ubuntu 20.04 (Web Server)
- CentOS 8 (Database Server)
- Windows 10 (Workstation)
```

### 3. 📱 Android Security Lab
**Dificultad**: Avanzado | **Tiempo**: 2.5 horas | **Puerto**: 6080

Emulador Android con aplicaciones vulnerables:
- **Android 11 Emulator**: Entorno completo
- **Vulnerable Apps**: 10+ aplicaciones con vulnerabilidades
- **Root Access**: Dispositivo rooteado para análisis avanzado
- **Traffic Analysis**: Burp Suite pre-configurado
- **Dynamic Analysis**: Frida, objection instalados
- **Static Analysis**: apktool, jadx disponibles

**Apps Vulnerables Incluidas**:
- InsecureBankv2
- DIVA (Damn Insecure Vulnerable App)
- VyAPI (Vulnerable Hybrid Mobile App)
- MSTG Hacking Playground

### 4. ☸️ Kubernetes Security Cluster
**Dificultad**: Avanzado | **Tiempo**: 5 horas | **Puerto**: 6443

Cluster K8s intencionalmente vulnerable:
- **Privileged Containers**: Escalada de privilegios
- **RBAC Misconfigurations**: Permisos excesivos
- **Network Policies**: Falta de micro-segmentación
- **Secrets Management**: Secretos expuestos
- **Pod Security**: Políticas de seguridad débiles
- **Ingress Vulnerabilities**: Configuraciones inseguras

**Componentes**:
```
- Master Node: Control plane vulnerable
- Worker Nodes: 2 nodos con vulnerabilidades
- Vulnerable Workloads: Apps con configuraciones inseguras
- Network Plugin: Calico con políticas débiles
```

### 5. 🏭 IoT/OT Security Lab
**Dificultad**: Experto | **Tiempo**: 6 horas | **Puertos**: 8502, 1883, 47808

Simulación de entorno industrial:
- **Modbus TCP/RTU**: Protocolo industrial vulnerable
- **MQTT Broker**: Comunicación IoT sin cifrado
- **BACnet**: Protocolo de automatización de edificios
- **DNP3**: Protocolo de comunicación de servicios públicos
- **CoAP**: Protocolo IoT constrainado
- **SCADA HMI**: Interface de supervisión vulnerable

**Dispositivos Simulados**:
```
- PLC Schneider Electric (Modicon)
- HMI Siemens WinCC
- IoT Sensors (Temperature, Pressure)
- MQTT Gateway
- Industrial Router
```

## 🚀 Gestión de Laboratorios

### Comandos Docker Compose

```bash
# Iniciar todos los laboratorios
docker-compose --profile labs up -d

# Iniciar laboratorio específico
docker-compose --profile labs up web-security-lab -d

# Ver estado de laboratorios
docker-compose --profile labs ps

# Detener laboratorios
docker-compose --profile labs down

# Ver logs de laboratorio
docker-compose --profile labs logs web-security-lab -f

# Reiniciar laboratorio
docker-compose --profile labs restart web-security-lab
```

### Scripts de Gestión

```bash
# Script de gestión de laboratorios
./scripts/dockerlabs/lab_manager.py

# Comandos disponibles:
python3 scripts/dockerlabs/lab_manager.py --list
python3 scripts/dockerlabs/lab_manager.py --start web-security
python3 scripts/dockerlabs/lab_manager.py --stop web-security
python3 scripts/dockerlabs/lab_manager.py --status
python3 scripts/dockerlabs/lab_manager.py --reset web-security
```

## 📋 Guías de Laboratorio

### Web Application Security Lab

#### Objetivos de Aprendizaje
1. Identificar vulnerabilidades web comunes
2. Explotar vulnerabilidades de forma ética
3. Desarrollar técnicas de detección
4. Implementar mitigaciones efectivas

#### Escenarios Incluidos
- **Scenario 1**: E-commerce vulnerable
- **Scenario 2**: Banking application
- **Scenario 3**: Social media platform
- **Scenario 4**: File sharing service

#### Herramientas Recomendadas
- Burp Suite Professional/Community
- OWASP ZAP
- Nikto
- SQLmap
- Gobuster

### Corporate Network Lab

#### Topología de Red
```
Internet
    |
[Firewall] - 192.168.1.1
    |
[Switch] - 192.168.1.0/24
    |
    +-- [DC] - 192.168.1.10 (Domain Controller)
    +-- [WEB] - 192.168.1.20 (Web Server)
    +-- [DB] - 192.168.1.30 (Database Server)
    +-- [WS] - 192.168.1.100 (Workstation)
```

#### Credenciales por Defecto
```
Domain Admin: administrator:P@ssw0rd123
Local Admin: admin:admin123
Web Service: webuser:webpass
DB Service: sa:SqlServer123!
```

## 🔧 Configuración Avanzada

### Networking Personalizado

```yaml
# docker-compose.override.yml
version: '3.8'
services:
  web-security-lab:
    networks:
      lab-network:
        ipv4_address: 172.21.0.10
    extra_hosts:
      - "vulnerable.local:172.21.0.10"
      - "secure.local:172.21.0.11"
```

### Persistencia de Datos

```bash
# Crear volúmenes para persistencia
docker volume create bofa_lab_data
docker volume create bofa_lab_configs

# Usar en docker-compose.yml
volumes:
  - bofa_lab_data:/data
  - bofa_lab_configs:/configs
```

### Monitoreo de Laboratorios

```yaml
# Configuración de Prometheus para labs
- job_name: 'bofa-labs'
  static_configs:
    - targets: 
      - 'web-security-lab:80'
      - 'network-lab:22'
      - 'android-lab:5555'
  scrape_interval: 30s
```

## 📊 Métricas y Logging

### Logs de Laboratorio
Cada laboratorio genera logs estructurados:
```
[2025-01-20 15:30:45] [LAB:web-security] Container started
[2025-01-20 15:30:46] [LAB:web-security] Services initialized
[2025-01-20 15:31:00] [LAB:web-security] User connected from 192.168.1.100
[2025-01-20 15:31:30] [LAB:web-security] SQL injection attempt detected
```

### Métricas Disponibles
- Tiempo de actividad del laboratorio
- Número de conexiones simultáneas
- Intentos de explotación detectados
- Uso de recursos (CPU, RAM, Red)

## 🎓 Integración Educativa

### Cursos Relacionados
Cada laboratorio está integrado con el sistema de estudio:
- **Lecciones teóricas** antes del lab
- **Objetivos específicos** por escenario
- **Evaluaciones automáticas** post-lab
- **Certificados** de completitud

### Sistema de Progreso
```json
{
  "user_id": "12345",
  "lab_name": "web-security",
  "progress": {
    "scenarios_completed": 3,
    "total_scenarios": 4,
    "vulnerabilities_found": 15,
    "time_spent": "2h 30m",
    "score": 85
  }
}
```

## 🔒 Consideraciones de Seguridad

### Aislamiento de Red
- Todos los labs ejecutan en red aislada
- No hay acceso a Internet desde labs
- Tráfico monitoreado y registrado
- Firewall entre lab network y host

### Limpieza Automática
```bash
# Script de limpieza diaria
#!/bin/bash
docker system prune -f
docker volume prune -f
docker-compose --profile labs down
docker-compose --profile labs up -d
```

### Recursos Limitados
```yaml
# Límites de recursos por laboratorio
deploy:
  resources:
    limits:
      cpus: '2.0'
      memory: 4G
    reservations:
      cpus: '0.5'
      memory: 1G
```

## 📞 Soporte y Troubleshooting

### Problemas Comunes

#### Laboratorio No Inicia
```bash
# Verificar imágenes
docker images | grep bofa

# Verificar puertos
netstat -tulpn | grep :8080

# Revisar logs
docker-compose --profile labs logs web-security-lab
```

#### Performance Lento
```bash
# Verificar recursos
docker stats

# Limpiar contenedores antiguos
docker system prune -a

# Reiniciar Docker
sudo systemctl restart docker
```

### Contacto Soporte
- **Discord**: [Canal #labs](https://discord.gg/bofa-labs)
- **Email**: labs@bofa.dev
- **GitHub**: [Issues Lab](https://github.com/descambiado/BOFA/labels/labs)

## 🔄 Desarrollo de Nuevos Labs

### Estructura de Directorio
```
labs/nuevo-lab/
├── README.md
├── docker-compose.yml
├── metadata.yaml
├── Dockerfile
├── configs/
├── scripts/
└── documentation/
```

### Template Base
```yaml
# metadata.yaml
name: "nuevo-lab"
description: "Descripción del laboratorio"
difficulty: "intermediate"
estimated_time: "3h"
category: "web-security"
version: "1.0"
author: "@descambiado"
```

---

**🧪 BOFA Labs - Aprender Haciendo**  
*Desarrollado con ❤️ por @descambiado*