
# 🏆 CTF Challenge Generator Lab

## Descripción
Laboratorio generador automático de retos CTF (Capture The Flag) con múltiples categorías: web, SSH, criptografía y forense. Incluye sistema de validación y puntuación.

## Objetivos de Aprendizaje
- Crear retos CTF personalizados automáticamente
- Resolver challenges de diferentes categorías
- Comprender metodologías de CTF
- Practicar escalada de privilegios y web hacking

## Servicios Incluidos
- **CTF Web**: Challenges web vulnerables (puertos 8082/8443)
- **SSH Server**: Retos de escalada de privilegios (puerto 2223)
- **CTF Generator**: Panel de generación de retos (puerto 5000)
- **Flag Validator**: Sistema de validación Redis (puerto 6379)

## Instrucciones de Uso

### 1. Iniciar el Laboratorio
```bash
cd labs/lab-ctf-generator
docker-compose up -d --build
```

### 2. Acceder a los Servicios
- **CTF Generator Panel**: http://localhost:5000
- **Web Challenges**: http://localhost:8082
- **SSH Challenges**: `ssh ctfuser@localhost -p 2223` (password: challenge123)

### 3. Generar Retos CTF

#### Panel de Generación (http://localhost:5000)
1. Seleccionar categoría: Web, SSH, Crypto, Forensics
2. Configurar dificultad: Easy, Medium, Hard
3. Generar reto automáticamente
4. Descargar package completo (.zip)

#### Ejemplo de Generación Automática
```bash
# Via API
curl -X POST http://localhost:5000/api/generate \
  -H "Content-Type: application/json" \
  -d '{
    "category": "web",
    "difficulty": "easy",
    "title": "Mi Reto SQL",
    "points": 100
  }'
```

### 4. Resolver Challenges

#### Web Challenges
```bash
# SQL Injection básico
curl "http://localhost:8082/challenge1?id=1' OR '1'='1' --"

# XSS Reflected
curl "http://localhost:8082/search?q=<script>alert('XSS')</script>"

# LFI (Local File Inclusion)
curl "http://localhost:8082/view?file=../../../etc/passwd"
```

#### SSH Challenges
```bash
# Conectar al servidor
ssh ctfuser@localhost -p 2223

# Buscar archivos con permisos especiales
find / -perm -4000 2>/dev/null

# Explotar SUID binaries
/usr/bin/custom_binary --help
```

### 5. Validar Flags
```bash
# Via web interface
curl -X POST http://localhost:5000/api/submit \
  -H "Content-Type: application/json" \
  -d '{
    "flag": "CTF{web_sqli_basic_bypass}",
    "challenge_id": "web_001"
  }'
```

### 6. Flags Esperadas
- `CTF{web_sqli_basic_bypass}` - SQL Injection en challenge web
- `CTF{ssh_privesc_success}` - Escalada de privilegios SSH
- `CTF{custom_generated_flag}` - Flag de reto generado automáticamente

### 7. Personalizar Templates

#### Crear Template Personalizado
```python
# En /templates/custom_web.py
def generate_challenge(difficulty):
    if difficulty == "easy":
        return {
            "title": "Custom SQLi Challenge",
            "description": "Find the flag in the database",
            "code": generate_vulnerable_php(),
            "flag": f"CTF{{custom_{random_string()}}}",
            "points": 150
        }
```

### 8. Exportar CTF Completo
El generador puede crear un paquete CTF completo:
- Docker-compose con todos los servicios
- README con instrucciones
- Flags y soluciones
- Sistema de scoring

### 9. Detener el Laboratorio
```bash
docker-compose down
```

## Categorías de Retos Disponibles

### 🌐 Web
- SQL Injection (GET/POST/Blind)
- XSS (Reflected/Stored/DOM)
- LFI/RFI
- Authentication Bypass
- CSRF

### 🖥️ SSH/Linux
- SUID Binary Exploitation
- Cron Job Abuse
- Environment Variables
- File Permissions
- Kernel Exploits

### 🔐 Cryptography
- Caesar Cipher
- Base64 Encoding
- ROT13
- Simple Substitution
- Hash Cracking

### 🔍 Forensics
- Image Steganography
- Memory Dumps
- Network Captures
- File Recovery
- Metadata Analysis

## API Endpoints
- `POST /api/generate` - Generar nuevo reto
- `GET /api/challenges` - Listar retos disponibles
- `POST /api/submit` - Validar flag
- `GET /api/scoreboard` - Ver puntuaciones

---
**Desarrollado por @descambiado para BOFA**
