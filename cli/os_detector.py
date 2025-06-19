
#!/usr/bin/env python3
"""
OS Detection and Environment Setup for BOFA
Detecta el sistema operativo y configura el entorno apropiado
"""

import os
import sys
import platform
import subprocess
import shutil
from pathlib import Path
from typing import Dict, List, Tuple

class OSDetector:
    def __init__(self):
        self.os_info = self.detect_os()
        self.docker_available = self.check_docker()
        self.python_available = self.check_python()
        
    def detect_os(self) -> Dict[str, str]:
        """Detecta el sistema operativo y entorno"""
        system = platform.system()
        is_wsl = self.is_wsl()
        
        os_info = {
            'system': system,
            'is_wsl': is_wsl,
            'platform': platform.platform(),
            'architecture': platform.architecture()[0],
            'python_version': platform.python_version()
        }
        
        if system == "Windows":
            if is_wsl:
                os_info['environment'] = 'WSL2'
                os_info['shell'] = 'bash'
                os_info['path_separator'] = '/'
            else:
                os_info['environment'] = 'Windows'
                os_info['shell'] = 'powershell'
                os_info['path_separator'] = '\\'
        elif system == "Linux":
            os_info['environment'] = 'Linux'
            os_info['shell'] = 'bash'
            os_info['path_separator'] = '/'
            
            # Detectar distribución específica
            try:
                with open('/etc/os-release', 'r') as f:
                    for line in f:
                        if line.startswith('ID='):
                            os_info['distro'] = line.split('=')[1].strip().strip('"')
                            break
            except:
                os_info['distro'] = 'unknown'
        else:
            os_info['environment'] = 'Unix'
            os_info['shell'] = 'bash'
            os_info['path_separator'] = '/'
            
        return os_info
    
    def is_wsl(self) -> bool:
        """Detecta si está corriendo en WSL"""
        try:
            with open('/proc/version', 'r') as f:
                return 'microsoft' in f.read().lower() or 'wsl' in f.read().lower()
        except:
            return False
    
    def check_docker(self) -> Dict[str, bool]:
        """Verifica disponibilidad de Docker"""
        docker_info = {
            'installed': False,
            'running': False,
            'compose_available': False,
            'desktop_detected': False
        }
        
        # Verificar si docker está instalado
        if shutil.which('docker'):
            docker_info['installed'] = True
            
            # Verificar si está corriendo
            try:
                result = subprocess.run(['docker', 'info'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    docker_info['running'] = True
                    
                    # Detectar Docker Desktop en Windows
                    if 'docker desktop' in result.stdout.lower():
                        docker_info['desktop_detected'] = True
            except:
                pass
        
        # Verificar docker-compose
        if shutil.which('docker-compose') or shutil.which('docker') and docker_info['installed']:
            try:
                # Probar docker compose (nuevo formato)
                result = subprocess.run(['docker', 'compose', 'version'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    docker_info['compose_available'] = True
                else:
                    # Probar docker-compose (formato antiguo)
                    result = subprocess.run(['docker-compose', '--version'], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        docker_info['compose_available'] = True
            except:
                pass
                
        return docker_info
    
    def check_python(self) -> Dict[str, str]:
        """Verifica disponibilidad de Python"""
        python_info = {
            'python3': shutil.which('python3') or '',
            'python': shutil.which('python') or '',
            'pip3': shutil.which('pip3') or '',
            'pip': shutil.which('pip') or '',
            'version': platform.python_version()
        }
        
        # En Windows, python3 a menudo es 'python'
        if self.os_info['system'] == 'Windows' and not python_info['python3']:
            if python_info['python']:
                python_info['python3'] = python_info['python']
                
        return python_info
    
    def get_script_executor(self, script_path: str) -> List[str]:
        """Retorna el comando apropiado para ejecutar un script"""
        script_path = Path(script_path)
        
        if script_path.suffix == '.py':
            python_cmd = self.python_available['python3'] or self.python_available['python']
            if python_cmd:
                return [python_cmd, str(script_path)]
            else:
                raise RuntimeError("Python no encontrado en el sistema")
                
        elif script_path.suffix == '.sh':
            if self.os_info['system'] == 'Windows' and not self.os_info['is_wsl']:
                # En Windows nativo, buscar versión PowerShell
                ps_script = script_path.with_suffix('.ps1')
                if ps_script.exists():
                    return ['powershell', '-ExecutionPolicy', 'Bypass', '-File', str(ps_script)]
                else:
                    # Ejecutar con Git Bash si está disponible
                    git_bash = shutil.which('bash')
                    if git_bash:
                        return [git_bash, str(script_path)]
                    else:
                        raise RuntimeError(f"No se puede ejecutar {script_path} en Windows. Considera usar WSL2 o instalar Git Bash")
            else:
                return ['bash', str(script_path)]
                
        elif script_path.suffix == '.ps1':
            if self.os_info['system'] == 'Windows':
                return ['powershell', '-ExecutionPolicy', 'Bypass', '-File', str(script_path)]
            else:
                # En Linux, intentar con pwsh si está disponible
                pwsh = shutil.which('pwsh')
                if pwsh:
                    return [pwsh, '-File', str(script_path)]
                else:
                    raise RuntimeError("PowerShell Core no encontrado en Linux")
        
        else:
            # Archivo ejecutable directo
            return [str(script_path)]
    
    def get_docker_command(self) -> List[str]:
        """Retorna el comando apropiado para Docker Compose"""
        if self.docker_available['compose_available']:
            # Probar formato nuevo primero
            try:
                result = subprocess.run(['docker', 'compose', 'version'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    return ['docker', 'compose']
            except:
                pass
            
            # Fallback al formato antiguo
            if shutil.which('docker-compose'):
                return ['docker-compose']
        
        raise RuntimeError("Docker Compose no encontrado")
    
    def normalize_path(self, path: str) -> str:
        """Normaliza rutas según el sistema operativo"""
        path = Path(path)
        
        if self.os_info['is_wsl']:
            # En WSL, convertir rutas de Windows a Linux si es necesario
            if str(path).startswith('/mnt/c/'):
                return str(path)
            elif str(path).startswith('C:\\'):
                return str(path).replace('C:\\', '/mnt/c/').replace('\\', '/')
        
        return str(path.resolve())
    
    def print_environment_info(self):
        """Imprime información del entorno detectado"""
        print(f"🖥️  Sistema: {self.os_info['environment']}")
        print(f"🐍 Python: {self.os_info['python_version']}")
        print(f"🐳 Docker: {'✅' if self.docker_available['running'] else '❌'}")
        print(f"📦 Docker Compose: {'✅' if self.docker_available['compose_available'] else '❌'}")
        
        if self.os_info['system'] == 'Linux' and 'distro' in self.os_info:
            print(f"🐧 Distribución: {self.os_info['distro'].title()}")
        
        if self.docker_available['desktop_detected']:
            print(f"🖥️  Docker Desktop detectado")

# Instancia global para uso en otros módulos
os_detector = OSDetector()
