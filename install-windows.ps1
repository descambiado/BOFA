
# BOFA Universal Installer for Windows 11 + WSL2
# Desarrollado por @descambiado

param(
    [switch]$UseWSL,
    [switch]$SkipDocker,
    [string]$InstallPath = "$env:USERPROFILE\BOFA"
)

Write-Host "🛡️  BOFA Universal Installer para Windows" -ForegroundColor Cyan
Write-Host "Desarrollado por @descambiado" -ForegroundColor Yellow
Write-Host "================================" -ForegroundColor Cyan

# Detectar entorno
$IsWSL = $env:WSL_DISTRO_NAME -ne $null
$HasDocker = Get-Command docker -ErrorAction SilentlyContinue

Write-Host "🖥️  Detectando entorno..." -ForegroundColor Yellow

if ($IsWSL) {
    Write-Host "✅ WSL2 detectado" -ForegroundColor Green
    $UseLinuxPath = $true
} else {
    Write-Host "✅ Windows nativo detectado" -ForegroundColor Green
    $UseLinuxPath = $false
}

# Verificar Docker
if (-not $SkipDocker) {
    if (-not $HasDocker) {
        Write-Host "❌ Docker no encontrado" -ForegroundColor Red
        Write-Host "📥 Instalando Docker Desktop..." -ForegroundColor Yellow
        
        try {
            # Descargar Docker Desktop
            $DockerUrl = "https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe"
            $DockerInstaller = "$env:TEMP\DockerInstaller.exe"
            
            Write-Host "⬇️  Descargando Docker Desktop..." -ForegroundColor Yellow
            Invoke-WebRequest -Uri $DockerUrl -OutFile $DockerInstaller
            
            Write-Host "🚀 Instalando Docker Desktop (requiere reinicio)..." -ForegroundColor Yellow
            Start-Process -FilePath $DockerInstaller -ArgumentList "install", "--quiet" -Wait
            
            Write-Host "✅ Docker Desktop instalado. Por favor reinicia tu PC y ejecuta este script de nuevo." -ForegroundColor Green
            Read-Host "Presiona Enter para continuar..."
            exit
        }
        catch {
            Write-Host "❌ Error instalando Docker: $_" -ForegroundColor Red
            Write-Host "💡 Por favor instala Docker Desktop manualmente desde: https://docker.com/products/docker-desktop" -ForegroundColor Yellow
        }
    } else {
        Write-Host "✅ Docker encontrado" -ForegroundColor Green
    }
}

# Verificar Python
$HasPython = Get-Command python -ErrorAction SilentlyContinue
if (-not $HasPython) {
    Write-Host "❌ Python no encontrado" -ForegroundColor Red
    Write-Host "📥 Instalando Python..." -ForegroundColor Yellow
    
    try {
        # Instalar Python desde Microsoft Store o web
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            winget install Python.Python.3.11
        } else {
            Write-Host "💡 Por favor instala Python desde: https://python.org/downloads" -ForegroundColor Yellow
            Write-Host "   O desde Microsoft Store: ms-windows-store://pdp/?productid=9NRWMJP3717K" -ForegroundColor Yellow
            Read-Host "Presiona Enter después de instalar Python..."
        }
    }
    catch {
        Write-Host "❌ Error instalando Python: $_" -ForegroundColor Red
    }
} else {
    Write-Host "✅ Python encontrado" -ForegroundColor Green
}

# Crear directorio de instalación
Write-Host "📁 Creando directorio de instalación..." -ForegroundColor Yellow
if (-not (Test-Path $InstallPath)) {
    New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
}

Set-Location $InstallPath

# Clonar repositorio
Write-Host "📥 Clonando repositorio BOFA..." -ForegroundColor Yellow
if (Test-Path "BOFA") {
    Write-Host "⚠️  Directorio BOFA ya existe, actualizando..." -ForegroundColor Yellow
    Set-Location "BOFA"
    git pull
} else {
    git clone https://github.com/descambiado/BOFA.git
    Set-Location "BOFA"
}

# Instalar dependencias Python
Write-Host "📦 Instalando dependencias Python..." -ForegroundColor Yellow
if (Test-Path "cli\requirements.txt") {
    python -m pip install -r cli\requirements.txt
}

# Configurar Docker si está disponible
if ($HasDocker -and -not $SkipDocker) {
    Write-Host "🐳 Configurando Docker..." -ForegroundColor Yellow
    
    # Verificar si Docker está corriendo
    try {
        docker info | Out-Null
        Write-Host "✅ Docker está corriendo" -ForegroundColor Green
        
        Write-Host "🚀 Construyendo contenedores BOFA..." -ForegroundColor Yellow
        docker-compose build
        
        Write-Host "✅ BOFA está listo para usar con Docker" -ForegroundColor Green
        Write-Host "🌐 Ejecuta: docker-compose up" -ForegroundColor Cyan
    }
    catch {
        Write-Host "⚠️  Docker no está corriendo. Inicia Docker Desktop primero." -ForegroundColor Yellow
    }
}

# Crear scripts de inicio
Write-Host "📝 Creando scripts de inicio..." -ForegroundColor Yellow

# Script para PowerShell
@"
# BOFA Launcher para Windows
cd "$InstallPath\BOFA"
python cli\bofa_cli.py
"@ | Out-File -FilePath "$InstallPath\start-bofa.ps1" -Encoding UTF8

# Script batch para compatibilidad
@"
@echo off
cd /d "$InstallPath\BOFA"
python cli\bofa_cli.py
pause
"@ | Out-File -FilePath "$InstallPath\start-bofa.bat" -Encoding ASCII

Write-Host "✅ Instalación completada!" -ForegroundColor Green
Write-Host "🚀 Para usar BOFA:" -ForegroundColor Cyan
Write-Host "   CLI: $InstallPath\start-bofa.ps1" -ForegroundColor White
Write-Host "   Docker: cd $InstallPath\BOFA && docker-compose up" -ForegroundColor White
Write-Host "   Web: http://localhost:3000" -ForegroundColor White

Read-Host "Presiona Enter para salir..."
