
# 📦 Guía de Instalación BOFA v2.5.0

Esta guía te llevará paso a paso a través del proceso de instalación de BOFA Extended Systems v2.5.0.

## 📋 Prerrequisitos

### Sistema Operativo
- **Linux**: Ubuntu 20.04+, Debian 11+, CentOS 8+, Arch Linux
- **macOS**: 10.15+ (Catalina o superior)
- **Windows**: 10/11 con WSL2 (recomendado) o nativo

### Software Requerido
- **Docker**: 20.10+ y Docker Compose 2.0+
- **Node.js**: 18.0+ con npm 8+
- **Python**: 3.8+ con pip
- **Git**: 2.30+

### Hardware Mínimo
- **RAM**: 4GB (8GB recomendado)
- **Almacenamiento**: 10GB libres
- **Procesador**: x64 compatible
- **Red**: Conexión a internet para dependencias

## 🚀 Instalación con Docker (Recomendado)

### 1. Preparar el Entorno
```bash
# Actualizar sistema (Ubuntu/Debian)
sudo apt update && sudo apt upgrade -y

# Instalar Docker y Docker Compose
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
newgrp docker

# Verificar instalación
docker --version
docker-compose --version
```

### 2. Clonar el Repositorio
```bash
# Clonar desde GitHub
git clone https://github.com/descambiado/BOFA.git
cd BOFA

# Verificar archivos
ls -la
```

### 3. Configurar Variables de Entorno
```bash
# Copiar archivo de configuración ejemplo
cp .env.example .env

# Editar configuración (nano, vim, o tu editor favorito)
nano .env
```

### 4. Iniciar con Docker Compose
```bash
# Construir e iniciar todos los servicios
docker-compose up --build -d

# Verificar que todo esté funcionando
docker-compose ps
```

### 5. Acceder a la Aplicación
- **Interfaz Web**: http://localhost:3000
- **API**: http://localhost:8000
- **Documentación API**: http://localhost:8000/docs

## 🛠️ Instalación Manual (Desarrollo)

### 1. Preparar Dependencias del Sistema
```bash
# Ubuntu/Debian
sudo apt install -y python3 python3-pip nodejs npm git curl wget

# macOS (con Homebrew)
brew install python3 node npm git

# Windows (con Chocolatey)
choco install python3 nodejs npm git
```

### 2. Configurar Frontend
```bash
# Instalar dependencias de Node.js
npm install

# Construir para producción (opcional)
npm run build

# Iniciar servidor de desarrollo
npm run dev
```

### 3. Configurar Backend (Opcional)
```bash
# Crear entorno virtual de Python
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# Instalar dependencias de Python
pip install -r requirements.txt

# Iniciar API backend (si está disponible)
python -m uvicorn api.main:app --reload
```

## 🔧 Configuración Avanzada

### Variables de Entorno (.env)
```bash
# Configuración de la aplicación
VITE_APP_NAME=BOFA
VITE_APP_VERSION=2.5.0
VITE_API_URL=http://localhost:8000

# Base de datos (PostgreSQL)
DATABASE_URL=postgresql://bofa:bofa123@localhost:5432/bofa_db

# APIs Externas (opcional)
SHODAN_API_KEY=tu_clave_shodan_aqui
VIRUSTOTAL_API_KEY=tu_clave_virustotal_aqui
HIBP_API_KEY=tu_clave_hibp_aqui

# Seguridad
JWT_SECRET=tu_jwt_secret_muy_seguro_aqui
ENCRYPTION_KEY=tu_clave_cifrado_32_caracteres

# Configuración de logs
LOG_LEVEL=INFO
LOG_FILE=/var/log/bofa/app.log

# Docker específico
COMPOSE_PROJECT_NAME=bofa
COMPOSE_HTTP_TIMEOUT=300
```

### Configuración de Puertos
```yaml
# docker-compose.yml - Puertos personalizados
services:
  frontend:
    ports:
      - "3000:3000"  # Cambiar puerto si es necesario
  
  api:
    ports:
      - "8000:8000"  # Puerto de la API
  
  database:
    ports:
      - "5432:5432"  # PostgreSQL
```

## 🧪 Configuración de Laboratorios

### 1. Laboratorios Docker
```bash
# Iniciar laboratorio específico
docker-compose -f labs/web-security/docker-compose.yml up -d

# Ver laboratorios disponibles
ls labs/
```

### 2. Configuración de Red para Labs
```bash
# Crear red dedicada para laboratorios
docker network create bofa-labs

# Configurar rango de IPs
docker network create --driver bridge \
  --subnet=172.20.0.0/16 \
  --ip-range=172.20.240.0/20 \
  bofa-labs
```

## 🔐 Configuración de Seguridad

### 1. Certificados SSL (Producción)
```bash
# Instalar Let's Encrypt
sudo apt install certbot

# Generar certificados
sudo certbot certonly --standalone -d tu-dominio.com

# Configurar renovación automática
echo "0 3 * * * certbot renew --quiet" | sudo crontab -
```

### 2. Firewall y Seguridad
```bash
# Configurar UFW (Ubuntu)
sudo ufw enable
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw allow 3000/tcp  # BOFA Frontend
sudo ufw allow 8000/tcp  # BOFA API

# Solo permitir conexiones locales para desarrollo
sudo ufw allow from 127.0.0.1 to any port 3000
sudo ufw allow from 127.0.0.1 to any port 8000
```

## 📊 Configuración de Monitoreo

### 1. Logs Centralizados
```bash
# Crear directorio de logs
sudo mkdir -p /var/log/bofa
sudo chown $USER:$USER /var/log/bofa

# Configurar rotación de logs
sudo nano /etc/logrotate.d/bofa
```

### 2. Contenido de logrotate.d/bofa
```
/var/log/bofa/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 644 bofa bofa
    postrotate
        systemctl reload bofa || true
    endscript
}
```

## 🔄 Actualizaciones y Mantenimiento

### 1. Actualizar BOFA
```bash
# Detener servicios
docker-compose down

# Actualizar código
git pull origin main

# Reconstruir y reiniciar
docker-compose up --build -d

# Verificar logs
docker-compose logs -f
```

### 2. Backup y Restauración
```bash
# Backup de base de datos
docker-compose exec postgres pg_dump -U bofa bofa_db > backup_$(date +%Y%m%d).sql

# Backup de configuración
tar -czf bofa_config_$(date +%Y%m%d).tar.gz .env docker-compose.yml

# Restaurar base de datos
docker-compose exec -T postgres psql -U bofa bofa_db < backup_20250120.sql
```

## 🐛 Solución de Problemas Comunes

### 1. Error de Puertos Ocupados
```bash
# Verificar qué está usando el puerto
sudo lsof -i :3000
sudo lsof -i :8000

# Cambiar puertos en docker-compose.yml
nano docker-compose.yml
```

### 2. Problemas de Permisos Docker
```bash
# Agregar usuario al grupo docker
sudo usermod -aG docker $USER
newgrp docker

# Reiniciar servicios Docker
sudo systemctl restart docker
```

### 3. Problemas de Memoria
```bash
# Verificar uso de memoria
free -h
docker system df

# Limpiar contenedores no utilizados
docker system prune -a
```

### 4. Problemas de Red
```bash
# Verificar conectividad de contenedores
docker network ls
docker network inspect bofa_default

# Reiniciar red Docker
docker-compose down
docker network prune
docker-compose up -d
```

## ✅ Verificación de Instalación

### 1. Lista de Comprobación
- [ ] Docker y Docker Compose instalados
- [ ] Repositorio clonado correctamente
- [ ] Variables de entorno configuradas
- [ ] Servicios iniciados correctamente
- [ ] Frontend accesible en http://localhost:3000
- [ ] API respondiendo en http://localhost:8000/docs
- [ ] Base de datos conectada
- [ ] Logs sin errores críticos

### 2. Tests de Funcionalidad
```bash
# Verificar API
curl http://localhost:8000/health

# Verificar frontend
curl http://localhost:3000

# Verificar base de datos
docker-compose exec postgres psql -U bofa -c "SELECT version();"
```

### 3. Scripts de Verificación
```bash
# Ejecutar script de prueba básico
python3 scripts/test/basic_test.py

# Verificar módulos principales
./verify_installation.sh
```

## 📞 Soporte de Instalación

Si encuentras problemas durante la instalación:

1. **Consulta la documentación**: [docs.bofa.dev](https://docs.bofa.dev)
2. **Revisa los issues**: [GitHub Issues](https://github.com/descambiado/BOFA/issues)
3. **Únete al Discord**: [Comunidad BOFA](https://discord.gg/bofa)
4. **Contacta al desarrollador**: david@descambiado.com

## 📝 Notas Adicionales

### Instalación en Producción
- Usa certificados SSL válidos
- Configura firewall apropiadamente
- Implementa backup automatizado
- Monitorea logs regularmente
- Mantén el sistema actualizado

### Instalación para Desarrollo
- Usa modo de desarrollo (`npm run dev`)
- Habilita hot-reload
- Configura debugger
- Instala herramientas de desarrollo adicionales

---

¡Felicidades! 🎉 Ahora tienes BOFA v2.5.0 completamente instalado y funcionando.
