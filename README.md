
# 🛡️ BOFA - Best Of All
### Suite Profesional de Ciberseguridad Ofensiva y Defensiva

---

## 📌 Descripción

**BOFA (Best Of All)** es una suite profesional de ciberseguridad que integra herramientas de:
- 🕵️ **Pentesting** y Reconocimiento
- 🔍 **OSINT** (Open Source Intelligence)
- 🎯 **Ingeniería Social**
- 🛡️ **Blue Team** y Defensa
- 🧪 **Análisis de Malware**
- 🐳 **Docker Labs** y Simulaciones
- 🎓 **Entorno Educativo**

### 👨‍💻 Desarrollado por:
**@descambiado** (David Hernández Jiménez)  
*Administración de Sistemas Informáticos en Red*  
*Ciberseguridad | Pentesting | Consultor IT/CIBERSEC | Estudiante*

---

## 🚀 Instalación y Uso

### Método 1: CLI Directa
```bash
git clone https://github.com/descambiado/BOFA
cd BOFA
chmod +x bofa.sh
./bofa.sh
```

### Método 2: Docker (Recomendado)
```bash
git clone https://github.com/descambiado/BOFA
cd BOFA
docker-compose up --build
```

### Método 3: Desarrollo Local
```bash
# Terminal 1 - API
cd api
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Terminal 2 - Web
cd web
npm install
npm run dev

# Terminal 3 - CLI
cd cli
python3 bofa_cli.py
```

---

## 🌐 Acceso a Servicios

- **🔒 Panel Web Seguro**: https://localhost (requiere autenticación)
- **🖥️ Panel Web Directo**: http://localhost:3000
- **🔗 API Backend**: http://localhost:8000
- **📱 CLI Interactiva**: `./bofa.sh`
- **📚 Documentación API**: http://localhost:8000/docs

### 🔐 Credenciales de Acceso
```
Usuario: admin
Contraseña: admin
```

---

## 🛡️ Configuración de Seguridad

### Certificado HTTPS
BOFA utiliza certificados autofirmados para desarrollo local. Para añadir la excepción en tu navegador:

1. Visita https://localhost
2. Clickea en "Avanzado" o "Advanced"
3. Selecciona "Proceder a localhost (no es seguro)" o "Proceed to localhost (unsafe)"
4. Introduce las credenciales: `admin / admin`

### Cambiar Credenciales
Para modificar el usuario y contraseña:

```bash
# Generar nuevo hash de contraseña
htpasswd -c nginx/.htpasswd nuevo_usuario

# Reconstruir el contenedor nginx
docker-compose up --build nginx
```

### Archivos de Configuración SSL
- **Certificado**: `nginx/ssl/bofa.local.crt`
- **Clave Privada**: `nginx/ssl/bofa.local.key`
- **Configuración NGINX**: `nginx/default.conf`
- **Archivo de Usuarios**: `nginx/.htpasswd`

---

## 📁 Estructura del Proyecto

```
BOFA/
├── nginx/               # Proxy HTTPS y autenticación
│   ├── default.conf    # Configuración NGINX
│   ├── ssl/            # Certificados SSL
│   └── .htpasswd       # Usuarios autorizados
├── cli/                # Terminal interactiva
├── web/                # Panel Web React
├── api/                # Backend FastAPI
├── scripts/            # Scripts organizados por módulos
│   ├── recon/         # Reconocimiento
│   ├── exploit/       # Explotación
│   ├── osint/         # OSINT
│   ├── social/        # Ingeniería Social
│   ├── blue/          # Blue Team
│   ├── malware/       # Análisis Malware
│   └── dockerlabs/    # Labs Docker
├── docs/              # Documentación
├── labs/              # Entornos de práctica
└── docker-compose.yml # Orquestación
```

---

## 🎯 Módulos Disponibles

### 🕵️ Reconocimiento
- Descubrimiento de servicios web
- Escaneo de puertos avanzado
- Enumeración DNS
- Detección de CDN
- Búsqueda de dispositivos IoT

### 🔍 OSINT
- Mapeo de perfiles sociales
- Búsqueda de secretos en GitHub
- Verificación de brechas de email
- Shodan Dorking automático

### 🎯 Explotación
- Auto-fetcher de exploits
- Generador de reverse shells
- Laboratorio de buffer overflow
- Explotación automática de CVEs

### 🎭 Ingeniería Social
- Kit de phishing por email
- Generador de páginas de login falsas
- Constructor de trampas PDF
- Autoloader de payloads USB

### 🛡️ Blue Team
- Guardian de logs
- Simulador SIEM
- Sniffer de red con IA
- Monitor de integridad de archivos

### 🧪 Análisis de Malware
- Extractor de strings
- Escáner estático de malware
- Detector de packers
- Cazador de autoruns

---

## 🎓 Modo Educativo

BOFA incluye un completo entorno de aprendizaje con:
- Tutoriales interactivos
- Laboratorios prácticos
- Simulaciones de ataques
- Desafíos CTF integrados

---

## 🔧 Solución de Problemas

### Error de Certificado SSL
Si tienes problemas con el certificado:
```bash
# Regenerar certificados
openssl req -x509 -newkey rsa:4096 -keyout nginx/ssl/bofa.local.key -out nginx/ssl/bofa.local.crt -days 365 -nodes -subj "/C=ES/ST=Madrid/L=Madrid/O=BOFA/CN=localhost"

# Reconstruir contenedor
docker-compose up --build nginx
```

### Problemas de Autenticación
Si no puedes acceder con admin/admin:
```bash
# Verificar archivo de usuarios
cat nginx/.htpasswd

# Regenerar usuario admin
htpasswd -c nginx/.htpasswd admin
```

---

## 🤝 Contribuir

¡Las contribuciones son bienvenidas! Por favor:

1. Fork el proyecto
2. Crea una rama para tu feature
3. Commit tus cambios
4. Push a la rama
5. Abre un Pull Request

---

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Ver `LICENSE` para más detalles.

---

## 🔗 Contacto

- **GitHub**: [@descambiado](https://github.com/descambiado)
- **Email**: [david@descambiado.com](mailto:david@descambiado.com)
- **LinkedIn**: [David Hernández Jiménez](https://linkedin.com/in/descambiado)

---

*"La ciberseguridad no es un producto, es un proceso"* 🛡️
