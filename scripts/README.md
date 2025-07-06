# 📚 BOFA Scripts Collection v2.5.0

Este directorio contiene todos los scripts de ciberseguridad organizados por módulos.

## 📁 Estructura de Módulos

### 🔴 Red Team (25 herramientas)
Scripts ofensivos y de penetración:
- **Supply Chain Scanner**: Análisis de dependencias y vulnerabilidades
- **Cloud Native Attack Simulator**: Ataques a Kubernetes/Docker
- **Ghost Scanner**: Escaneo de red sigiloso
- **Reverse Shell Polyglot**: Generador multi-lenguaje
- **C2 Simulator**: Simulador Command & Control

### 🔵 Blue Team (18 herramientas)
Herramientas defensivas y análisis:
- **AI Threat Hunter v2.0**: Detección con Machine Learning
- **Zero Trust Validator**: Validación de implementaciones ZT
- **Log Guardian**: Monitoreo en tiempo real
- **Auth Log Parser**: Análisis de logs de autenticación
- **IOC Matcher**: Correlación de indicadores

### 🟣 Purple Team (12 herramientas)
Ejercicios coordinados:
- **Quantum Crypto Analyzer**: Evaluación post-cuántica
- **Purple Attack Orchestrator**: Coordinación Red vs Blue
- **Threat Emulator**: Simulación de amenazas realistas

### 🔍 OSINT (12 herramientas)
Inteligencia de fuentes abiertas:
- **IoT Security Mapper**: Búsqueda con Shodan
- **Multi-Vector OSINT**: Correlación multi-fuente
- **GitHub Repo Leak Detector**: Detección de filtraciones
- **Telegram User Scraper**: Recopilación de datos

### 🐛 Malware Analysis (10 herramientas)
Análisis de malware:
- **Malware Analyzer**: Análisis estático/dinámico
- **IOC Extractor**: Extracción de indicadores
- **Sandbox Integration**: Análisis automatizado

### 🎭 Social Engineering (6 herramientas)
Ingeniería social educativa:
- **Social Engineering Toolkit**: Framework completo
- **Phishing Simulation**: Campañas controladas
- **Awareness Training**: Módulos educativos

### 🏴‍☠️ Exploit (15 herramientas)
Herramientas de explotación:
- **AI Payload Mutator**: Mutación inteligente
- **AV Evasion Engine**: Evasión de antivirus
- **Reverse Shell Generator**: Generación de shells
- **Post Exploit Enum**: Enumeración post-explotación

### 🕵️ Recon (12 herramientas)
Reconocimiento y enumeración:
- **Advanced Network Mapper**: Mapeo de red avanzado
- **Web Discovery**: Descubrimiento de servicios web
- **WiFi Shadow Mapper**: Redes ocultas
- **Reverse DNS Flood**: Testing defensivo

### 📊 Forensics (8 herramientas)
Análisis forense:
- **Deepfake Detection Engine**: Detección de IA generativa
- **Packet Story Builder**: Análisis de tráfico
- **Timeline Builder**: Construcción de líneas temporales

### 📚 Study (CTF tools)
Herramientas educativas:
- **CTF Flag Planner**: Planificación de CTFs
- **Skill Assessment**: Evaluación de habilidades
- **Training Scenarios**: Escenarios de práctica

## 🎯 Características 2025

### Nuevas Tecnologías Integradas
- **AI/ML Local**: Machine Learning sin dependencias cloud
- **Post-Quantum Crypto**: Evaluación de resistencia cuántica
- **Supply Chain Security**: Análisis SBOM automatizado
- **Zero Trust Validation**: Verificación de implementaciones
- **Cloud Native Security**: Ataques específicos a contenedores
- **IoT/OT Security**: Protocolos industriales y dispositivos

### Integración MITRE ATT&CK
Todos los scripts incluyen mapeo a técnicas MITRE:
- Identificación de tácticas y técnicas
- Detección y mitigación automatizada
- Reporting con contexto ATT&CK

## 📋 Formato de Scripts

### Estructura YAML
Cada script incluye metadatos YAML:
```yaml
name: "script_name"
description: "Descripción detallada"
category: "module_name"
author: "@descambiado"
version: "1.0"
last_updated: "2025-01-20"
risk_level: "LOW|MEDIUM|HIGH"
educational_value: 5
parameters:
  target:
    type: "string"
    required: true
    description: "Objetivo del análisis"
```

### Parámetros Soportados
- **string**: Texto libre
- **integer**: Números enteros
- **boolean**: Verdadero/falso
- **select**: Lista de opciones
- **file**: Selección de archivo
- **multiselect**: Múltiples opciones
- **choice**: Opciones exclusivas

## 🚀 Uso de Scripts

### Desde la Interfaz Web
1. Navegar al módulo correspondiente
2. Seleccionar script específico
3. Configurar parámetros requeridos
4. Ejecutar y monitorear resultados

### Desde CLI
```bash
# Ejecutar script específico
python3 scripts/blue/ai_threat_hunter.py --log-file security.log

# Usar el CLI interactivo
./bofa.sh

# Listar scripts disponibles
./bofa.sh --list
```

## 🔒 Consideraciones de Seguridad

### Uso Responsable
- ✅ **Solo en entornos autorizados**
- ✅ **Documentar todas las ejecuciones**
- ✅ **Seguir principios éticos**
- ❌ **No usar contra sistemas sin autorización**

### Niveles de Riesgo
- **LOW**: Scripts de análisis pasivo
- **MEDIUM**: Herramientas de enumeración activa
- **HIGH**: Scripts de explotación y ataques

## 📊 Métricas y Logging

### Sistema de Logs
Cada script genera logs estructurados:
```
[2025-01-20 15:30:45] [INFO] Script iniciado: ai_threat_hunter
[2025-01-20 15:30:46] [INFO] Parámetros: {"log_file": "security.log"}
[2025-01-20 15:31:02] [SUCCESS] Análisis completado: 15 amenazas detectadas
```

### Métricas de Rendimiento
- Tiempo de ejecución
- Uso de recursos
- Tasa de éxito/fallo
- Indicadores de calidad

## 🔄 Desarrollo y Contribución

### Añadir Nuevos Scripts

1. **Crear el archivo Python**:
```python
#!/usr/bin/env python3
"""
BOFA Extended Systems v2.5.0 - [Script Name]
[Descripción del script]
"""

import yaml
import argparse
from pathlib import Path

def load_config():
    """Cargar configuración desde YAML"""
    config_path = Path(__file__).with_suffix('.yaml')
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)

def main():
    config = load_config()
    # Lógica del script aquí
    pass

if __name__ == "__main__":
    main()
```

2. **Crear archivo YAML correspondiente**:
```yaml
name: "mi_nuevo_script"
description: "Descripción de mi script"
category: "blue"
# ... resto de metadatos
```

3. **Testear funcionamiento**:
```bash
python3 scripts/blue/mi_nuevo_script.py --help
```

### Guías de Desarrollo
- Seguir convenciones PEP 8
- Incluir documentación completa
- Implementar manejo de errores
- Añadir tests cuando sea posible
- Seguir principios de seguridad

## 📞 Soporte

### Contacto
- **GitHub**: [Issues](https://github.com/descambiado/BOFA/issues)
- **Email**: david@descambiado.com
- **Discord**: [Comunidad BOFA](https://discord.gg/bofa)

### Recursos Adicionales
- [Documentación completa](https://docs.bofa.dev)
- [Video tutoriales](https://youtube.com/c/bofa-cybersecurity)
- [Ejemplos de uso](https://github.com/descambiado/BOFA-examples)

---

**Desarrollado con ❤️ por @descambiado**  
*BOFA Extended Systems v2.5.0 - La próxima generación en ciberseguridad*