
# 📚 Documentación BOFA

## Índice
1. [Instalación](#instalación)
2. [Uso del CLI](#uso-del-cli)
3. [Panel Web](#panel-web)
4. [API](#api)
5. [Módulos](#módulos)
6. [Contribuir](#contribuir)

## Instalación

### Requisitos Previos
- Docker y Docker Compose
- Python 3.8+
- Node.js 16+

### Instalación con Docker (Recomendado)
```bash
git clone https://github.com/descambiado/BOFA
cd BOFA
docker-compose up --build
```

### Instalación Manual
```bash
# CLI
cd cli
pip install -r requirements.txt

# API
cd ../api
pip install -r requirements.txt

# Web
cd ../web
npm install
```

## Uso del CLI

El CLI de BOFA proporciona una interfaz interactiva para acceder a todos los módulos:

```bash
./bofa.sh
```

### Navegación
- Use los números para seleccionar módulos
- Presione `0` para salir
- Use `Ctrl+C` para salida de emergencia

## Panel Web

Accesible en `http://localhost:3000`, el panel web incluye:
- Dashboard con estadísticas en tiempo real
- Navegación por módulos
- Terminal integrada
- Documentación interactiva

## API

La API REST está disponible en `http://localhost:8000`:
- `/docs` - Documentación Swagger
- `/modules` - Lista de módulos
- `/scripts` - Lista de scripts
- `/health` - Estado del sistema

## Módulos

### 🕵️ Reconocimiento
Herramientas para la fase de reconocimiento:
- Descubrimiento de servicios
- Enumeración de puertos
- Análisis DNS
- Detección de tecnologías

### 💥 Explotación
Herramientas de explotación:
- Búsqueda de exploits
- Generación de payloads
- Post-explotación

### 🔍 OSINT
Inteligencia de fuentes abiertas:
- Reconocimiento pasivo
- Análisis de redes sociales
- Búsqueda de información filtrada

### 🎭 Ingeniería Social
Herramientas de ingeniería social:
- Campañas de phishing
- Generación de contenido malicioso
- Técnicas de persuasión

### 🛡️ Blue Team
Herramientas defensivas:
- Monitoreo de logs
- Detección de amenazas
- Análisis forense

### 🧪 Análisis de Malware
Herramientas de análisis:
- Análisis estático
- Extracción de IOCs
- Ingeniería inversa

## Contribuir

1. Fork el repositorio
2. Crea una rama para tu feature
3. Desarrolla tu contribución
4. Añade tests si es necesario
5. Envía un pull request

### Añadir Nuevos Scripts

Para añadir un nuevo script:

1. Colócalo en la carpeta del módulo correspondiente
2. Añade la documentación
3. Actualiza la configuración del módulo
4. Añade tests si es aplicable

## Soporte

Para soporte técnico:
- GitHub Issues: [Reportar problema](https://github.com/descambiado/BOFA/issues)
- Email: david@descambiado.com
- Discord: [Comunidad BOFA](#)

---

Desarrollado con ❤️ por @descambiado
