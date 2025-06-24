
# 📱 Android Mobile Security Lab

## Descripción
Laboratorio completo para pruebas de seguridad en aplicaciones móviles Android, incluyendo emulación, análisis de APKs y interceptación de tráfico.

## Objetivos de Aprendizaje
- Análisis estático y dinámico de APKs
- Interceptación de tráfico móvil con mitmproxy
- Detección de secretos hardcodeados
- Análisis de comunicaciones SSL/TLS

## Servicios Incluidos
- **Android Emulator**: Emulador Android 11 con VNC web (puerto 6080)
- **APK Server**: Servidor de APKs vulnerables (puerto 8081)
- **Traffic Analyzer**: Herramientas de análisis Kali (SSH puerto 3333)

## Requisitos del Sistema
- Host Linux con soporte KVM
- Mínimo 8GB RAM
- 20GB espacio libre en disco

## Instrucciones de Uso

### 1. Verificar Soporte KVM
```bash
# Verificar KVM
ls -la /dev/kvm
lscpu | grep Virtualization
```

### 2. Iniciar el Laboratorio
```bash
cd labs/lab-android-emulation
docker-compose up -d
```

### 3. Acceder a los Servicios
- **Android Emulator**: http://localhost:6080 (VNC Web)
- **APK Downloads**: http://localhost:8081
- **Traffic Tools**: `ssh root@localhost -p 3333`

### 4. Ejercicios Prácticos

#### Ejercicio 1: APK Analysis
```bash
# Conectar a herramientas
docker exec -it traffic-analyzer bash

# Descargar APK vulnerable
wget http://vulnerable-app-server/InsecureBank.apk

# Análisis con APKTool
apktool d InsecureBank.apk

# Buscar secretos
grep -r "password\|key\|secret\|token" InsecureBank/
```

#### Ejercicio 2: Traffic Interception
```bash
# Configurar mitmproxy
mitmproxy -s capture_mobile.py --listen-port 8080

# En el emulador Android:
# Settings > Wi-Fi > Proxy: 172.18.0.3:8080
# Instalar certificado mitmproxy
```

#### Ejercicio 3: Dynamic Analysis
1. Instalar APK en emulador desde VNC web
2. Configurar proxy para interceptar tráfico
3. Ejecutar aplicación y capturar requests
4. Analizar datos sensibles transmitidos

### 5. Flags Esperadas
- `MOBILE{apk_hardcoded_secrets}` - Al encontrar secretos en APK
- `MOBILE{traffic_intercept_success}` - Al interceptar comunicaciones

### 6. Detener el Laboratorio
```bash
docker-compose down
```

## Herramientas Incluidas
- **APKTool**: Decompilación de APKs
- **mitmproxy**: Interceptación de tráfico
- **Wireshark**: Análisis de paquetes
- **ADB**: Android Debug Bridge

## Troubleshooting
- Si KVM no está disponible, el emulador será muy lento
- Asegurar que el usuario esté en el grupo `kvm`
- Verificar que la virtualización esté habilitada en BIOS

---
**Desarrollado por @descambiado para BOFA**
