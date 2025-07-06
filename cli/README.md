# 💻 BOFA CLI v2.5.0

Interfaz de línea de comandos interactiva para BOFA Extended Systems.

## 🚀 Características

### Navegación Interactiva
- **Menús coloridos** con rich terminal UI
- **Navegación por categorías** de scripts
- **Ejecución directa** de herramientas
- **Historial de comandos** integrado
- **Auto-completado** de parámetros

### Módulos Soportados
- 🔴 **Red Team** (25 herramientas)
- 🔵 **Blue Team** (18 herramientas) 
- 🟣 **Purple Team** (12 herramientas)
- 🔍 **OSINT** (12 herramientas)
- 🐛 **Malware Analysis** (10 herramientas)
- 🎭 **Social Engineering** (6 herramientas)
- 🏴‍☠️ **Exploit** (15 herramientas)
- 🕵️ **Recon** (12 herramientas)

## 📦 Instalación

### Desde Código Fuente
```bash
# Clonar repositorio
git clone https://github.com/descambiado/BOFA
cd BOFA/cli

# Instalar dependencias
pip install -r requirements.txt

# Hacer ejecutable
chmod +x bofa_cli.py

# Ejecutar
python3 bofa_cli.py
```

### Con Docker
```bash
# Construir imagen
docker build -t bofa-cli .

# Ejecutar contenedor interactivo
docker run -it --rm bofa-cli

# Con volúmenes para persistencia
docker run -it --rm -v $(pwd)/data:/app/data bofa-cli
```

### Instalación Global
```bash
# Instalar globalmente
pip install -e .

# Usar desde cualquier lugar
bofa-cli
```

## 🎯 Uso Básico

### Menú Principal
```bash
$ python3 bofa_cli.py

██████╗  ██████╗ ███████╗ █████╗     ██████╗██╗     ██╗
██╔══██╗██╔═══██╗██╔════╝██╔══██╗   ██╔════╝██║     ██║
██████╔╝██║   ██║█████╗  ███████║   ██║     ██║     ██║
██╔══██╗██║   ██║██╔══╝  ██╔══██║   ██║     ██║     ██║
██████╔╝╚██████╔╝██║     ██║  ██║   ╚██████╗███████╗██║
╚═════╝  ╚═════╝ ╚═╝     ╚═╝  ╚═╝    ╚═════╝╚══════╝╚═╝

    Extended Systems v2.5.0 - Command Line Interface
    Cybersecurity Tools & Scripts Collection

┌─────────────────────────────────────────────────────────┐
│                    MÓDULOS DISPONIBLES                  │
├─────────────────────────────────────────────────────────┤
│  1. 🔴 Red Team (25 herramientas)                      │
│  2. 🔵 Blue Team (18 herramientas)                     │
│  3. 🟣 Purple Team (12 herramientas)                   │
│  4. 🔍 OSINT (12 herramientas)                         │
│  5. 🐛 Malware Analysis (10 herramientas)              │
│  6. 🎭 Social Engineering (6 herramientas)             │
│  7. 🏴‍☠️ Exploit (15 herramientas)                      │
│  8. 🕵️ Recon (12 herramientas)                         │
│  9. 📊 Forensics (8 herramientas)                      │
│ 10. 📚 Study & Training (CTF tools)                    │
├─────────────────────────────────────────────────────────┤
│  0. Salir                                               │
└─────────────────────────────────────────────────────────┘

Selecciona un módulo [1-10]:
```

### Navegación por Módulo
```bash
# Ejemplo: Red Team
Selecciona un módulo [1-10]: 1

🔴 RED TEAM - Herramientas Ofensivas y Penetración

┌─────────────────────────────────────────────────────────┐
│                  SCRIPTS DISPONIBLES                    │
├─────────────────────────────────────────────────────────┤
│  1. Supply Chain Scanner                               │
│     Análisis de dependencias y vulnerabilidades       │
│                                                        │
│  2. Cloud Native Attack Simulator                     │
│     Ataques específicos a Kubernetes/Docker           │
│                                                        │
│  3. Ghost Scanner                                      │
│     Escaneo de red sigiloso sin ARP                   │
│                                                        │
│  4. Reverse Shell Polyglot                           │
│     Generador multi-lenguaje de shells                │
│                                                        │
│  5. C2 Simulator                                      │
│     Simulador Command & Control                       │
└─────────────────────────────────────────────────────────┘

Selecciona script [1-5] o 'back' para volver:
```

## 🔧 Características Avanzadas

### Modo Comando Directo
```bash
# Ejecutar script directamente
python3 bofa_cli.py --module red --script ghost_scanner --target 192.168.1.0

# Listar scripts de un módulo
python3 bofa_cli.py --list-scripts blue

# Obtener información de un script
python3 bofa_cli.py --info ai_threat_hunter

# Modo batch (sin interacción)
python3 bofa_cli.py --batch --config config.json
```

### Configuración de Parámetros
```bash
# Configuración interactiva
📋 Configuración de Parámetros - Ghost Scanner

┌─────────────────────────────────────────────────────────┐
│ target (string) [REQUERIDO]                           │
│ Rango de red a escanear (ej: 192.168.1.0)            │
│ Ingrese valor: 192.168.1.0                            │
├─────────────────────────────────────────────────────────┤
│ delay (float) [OPCIONAL]                              │
│ Delay entre escaneos para sigilo                      │
│ Valor por defecto: 0.5                               │
│ Ingrese valor [Enter para default]: 1.0               │
├─────────────────────────────────────────────────────────┤
│ output (string) [OPCIONAL]                            │
│ Archivo de salida del reporte                        │
│ Ingrese valor [Enter para skip]:                      │
└─────────────────────────────────────────────────────────┘
```

### Ejecución con Progreso
```bash
🚀 Ejecutando Ghost Scanner...

Parámetros:
  • target: 192.168.1.0
  • delay: 1.0
  • output: scan_results.txt

[████████████████████████████████████████] 100% (45/45 hosts)

⏱️  Tiempo de ejecución: 2m 34s
✅ Completado exitosamente

📊 Resultados:
  • Hosts activos: 12
  • Puertos abiertos: 45
  • Servicios identificados: 23
  • Vulnerabilidades potenciales: 3

📄 Reporte guardado en: scan_results.txt
```

## ⚙️ Configuración

### Archivo de Configuración
```json
// ~/.bofa/config.json
{
  "api_url": "http://localhost:8000",
  "api_key": "your_api_key_here",
  "output_directory": "~/bofa_results",
  "log_level": "INFO",
  "themes": {
    "color_scheme": "monokai",
    "show_banners": true,
    "animation_speed": "fast"
  },
  "modules": {
    "enabled": ["red", "blue", "purple", "osint"],
    "disabled": ["malware", "social"]
  },
  "security": {
    "require_confirmation": true,
    "log_executions": true,
    "timeout_seconds": 300
  }
}
```

### Variables de Entorno
```bash
# Configuración via environment
export BOFA_API_URL="http://localhost:8000"
export BOFA_API_KEY="your_api_key"
export BOFA_OUTPUT_DIR="$HOME/bofa_results"
export BOFA_LOG_LEVEL="DEBUG"
export BOFA_THEME="dark"
```

## 🎨 Personalización

### Temas de Color
```python
# themes.py
THEMES = {
    "default": {
        "primary": "cyan",
        "secondary": "magenta",
        "success": "green",
        "warning": "yellow",
        "error": "red"
    },
    "hacker": {
        "primary": "bright_green",
        "secondary": "green",
        "success": "bright_green",
        "warning": "yellow",
        "error": "bright_red"
    },
    "professional": {
        "primary": "blue",
        "secondary": "cyan",
        "success": "green",
        "warning": "orange3",
        "error": "red"
    }
}
```

### Plugins Personalizados
```python
# plugins/custom_module.py
from bofa_cli.core import BaseModule

class CustomModule(BaseModule):
    name = "custom"
    display_name = "🛠️ Custom Tools"
    
    def get_scripts(self):
        return [
            {
                "name": "my_tool",
                "description": "Mi herramienta personalizada",
                "parameters": {...}
            }
        ]
    
    def execute_script(self, script_name, parameters):
        # Lógica de ejecución
        pass
```

## 📊 Logging y Auditoría

### Sistema de Logs
```python
# Configuración de logging
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('~/.bofa/cli.log'),
        logging.StreamHandler()
    ]
)
```

### Auditoría de Comandos
```bash
# ~/.bofa/audit.log
2025-01-20 15:30:45 - USER:admin - MODULE:red - SCRIPT:ghost_scanner - PARAMS:{"target":"192.168.1.0"}
2025-01-20 15:33:19 - USER:admin - MODULE:blue - SCRIPT:ai_threat_hunter - PARAMS:{"log_file":"security.log"}
2025-01-20 15:35:02 - USER:admin - MODULE:osint - SCRIPT:shodan_search - PARAMS:{"query":"apache"}
```

## 🔒 Seguridad

### Validación de Parámetros
```python
def validate_ip_range(ip_range: str) -> bool:
    """Validar rango IP para evitar escaneos no autorizados"""
    private_ranges = [
        "192.168.0.0/16",
        "10.0.0.0/8", 
        "172.16.0.0/12",
        "127.0.0.0/8"
    ]
    # Lógica de validación
    return True
```

### Confirmaciones de Seguridad
```bash
⚠️  ADVERTENCIA DE SEGURIDAD

El script 'Ghost Scanner' realizará escaneo activo de red.

Objetivo: 192.168.1.0/24
Riesgo: MEDIO
Detección: Posible por IDS/IPS

¿Confirmas que tienes autorización para escanear esta red? [y/N]: y
¿Estás en un entorno de testing autorizado? [y/N]: y

✅ Confirmaciones aceptadas. Ejecutando script...
```

## 🧪 Testing

### Tests Automatizados
```python
# tests/test_cli.py
import pytest
from unittest.mock import patch
from bofa_cli.main import BofaCLI

def test_module_navigation():
    cli = BofaCLI()
    assert len(cli.modules) == 10

def test_script_execution():
    with patch('subprocess.run') as mock_run:
        mock_run.return_value.returncode = 0
        cli = BofaCLI()
        result = cli.execute_script("red", "ghost_scanner", {"target": "127.0.0.1"})
        assert result.success == True
```

### Ejecutar Tests
```bash
# Tests unitarios
pytest tests/

# Tests de integración
pytest tests/integration/

# Tests con coverage
pytest --cov=bofa_cli tests/
```

## 📦 Distribución

### PyPI Package
```bash
# Preparar distribución
python setup.py sdist bdist_wheel

# Subir a PyPI
twine upload dist/*

# Instalar desde PyPI
pip install bofa-cli
```

### Ejecutable Standalone
```bash
# Con PyInstaller
pip install pyinstaller
pyinstaller --onefile --name bofa bofa_cli.py

# Resultado en dist/bofa
./dist/bofa
```

## 🔄 Actualizaciones

### Auto-Update
```python
def check_for_updates():
    """Verificar actualizaciones disponibles"""
    current_version = "2.5.0"
    latest_version = get_latest_version_from_github()
    
    if version_compare(latest_version, current_version) > 0:
        print(f"📦 Nueva versión disponible: {latest_version}")
        if confirm("¿Deseas actualizar ahora?"):
            update_cli()
```

### Manual Update
```bash
# Actualizar CLI
git pull origin main
pip install -r requirements.txt

# Verificar versión
python3 bofa_cli.py --version
```

## 📞 Soporte

### Comandos de Ayuda
```bash
# Ayuda general
python3 bofa_cli.py --help

# Ayuda de módulo específico
python3 bofa_cli.py --help red

# Información de script
python3 bofa_cli.py --info ai_threat_hunter

# Ejemplos de uso
python3 bofa_cli.py --examples ghost_scanner
```

### Troubleshooting
```bash
# Verificar configuración
python3 bofa_cli.py --check-config

# Test de conectividad
python3 bofa_cli.py --test-connection

# Limpiar cache
python3 bofa_cli.py --clear-cache

# Logs de debug
python3 bofa_cli.py --debug --log-file debug.log
```

### Contacto
- **GitHub**: [Issues CLI](https://github.com/descambiado/BOFA/labels/cli)
- **Email**: cli@bofa.dev
- **Discord**: [Canal #cli-support](https://discord.gg/bofa-cli)

---

**💻 BOFA CLI - Tu Terminal de Ciberseguridad**  
*Desarrollado con ❤️ por @descambiado*