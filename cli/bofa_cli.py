
#!/usr/bin/env python3
"""
BOFA CLI - Best Of All Command Line Interface
Desarrollado por @descambiado (David Hernández Jiménez)
Versión multiplataforma compatible con Windows 11, WSL2, y Linux
"""

import os
import sys
import time
import subprocess
import shlex
from pathlib import Path
from colorama import Fore, Back, Style, init

# Importar detector de OS
try:
    from os_detector import os_detector
except ImportError:
    print("❌ Error: No se pudo importar os_detector.py")
    print("💡 Asegúrate de que os_detector.py esté en el mismo directorio")
    sys.exit(1)

# Inicializar colorama
init(autoreset=True)

class BOFAcli:
    def __init__(self):
        self.version = "v1.0.0"
        self.author = "@descambiado"
        self.base_path = Path(__file__).parent.parent
        self.scripts_path = self.base_path / "scripts"
        self.output_path = self.base_path / "output"
        
        # Crear directorio de salida si no existe
        self.output_path.mkdir(exist_ok=True)
        
        # Detectar entorno
        self.os_info = os_detector.os_info
        self.docker_available = os_detector.docker_available
        
    def clear_screen(self):
        if self.os_info['system'] == 'Windows' and not self.os_info['is_wsl']:
            os.system('cls')
        else:
            os.system('clear')
        
    def print_banner(self):
        # Información del sistema en el banner
        os_emoji = {
            'Windows': '🪟',
            'WSL2': '🐧',
            'Linux': '🐧',
            'Unix': '🖥️'
        }
        
        env_emoji = os_emoji.get(self.os_info['environment'], '🖥️')
        
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║  {Fore.RED}██████╗  ██████╗ ███████╗ █████╗     {Fore.CYAN}Best Of All Suite          ║
║  {Fore.RED}██╔══██╗██╔═══██╗██╔════╝██╔══██╗    {Fore.CYAN}Ciberseguridad Profesional ║
║  {Fore.RED}██████╔╝██║   ██║█████╗  ███████║    {Fore.CYAN}                           ║
║  {Fore.RED}██╔══██╗██║   ██║██╔══╝  ██╔══██║    {Fore.CYAN}Versión: {self.version}            ║
║  {Fore.RED}██████╔╝╚██████╔╝██║     ██║  ██║    {Fore.CYAN}Por: {self.author}       ║
║  {Fore.RED}╚═════╝  ╚═════╝ ╚═╝     ╚═╝  ╚═╝                            ║
║                                                                  ║
║  {env_emoji} {Fore.YELLOW}Sistema: {self.os_info['environment']:<12} {Fore.YELLOW}🐳 Docker: {'✅' if self.docker_available['running'] else '❌':<3}        ║
╚══════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)
        
    def print_menu(self):
        # ... keep existing code (menu display)
        menu = f"""
{Fore.YELLOW}┌─────────────────────────────────────────────────────────────────┐
│                        MENÚ PRINCIPAL                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  {Fore.GREEN}[1]{Fore.WHITE} 🕵️  Reconocimiento        {Fore.GREEN}[2]{Fore.WHITE} 💥 Explotación          │
│  {Fore.GREEN}[3]{Fore.WHITE} 🔍 OSINT                  {Fore.GREEN}[4]{Fore.WHITE} 🎭 Ingeniería Social    │
│  {Fore.GREEN}[5]{Fore.WHITE} 🛡️  Blue Team             {Fore.GREEN}[6]{Fore.WHITE} 🧪 Análisis Malware     │
│  {Fore.GREEN}[7]{Fore.WHITE} 🐳 Docker Labs            {Fore.GREEN}[8]{Fore.WHITE} 🎓 Modo Estudio         │
│  {Fore.GREEN}[9]{Fore.WHITE} 🟣 Purple Team            {Fore.GREEN}[A]{Fore.WHITE} ⚙️  Información Sistema │
│                                                                 │
│  {Fore.CYAN}[C]{Fore.WHITE} ⚙️  Configuración          {Fore.RED}[0]{Fore.WHITE} 🚪 Salir                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘{Style.RESET_ALL}
"""
        print(menu)
        
    def execute_script(self, module, script_info):
        """Ejecuta un script usando el detector de OS"""
        print(f"\n{Fore.CYAN}🚀 Ejecutando: {script_info['name']}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}📁 Módulo: {module}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}📝 Descripción: {script_info['description']}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}🖥️  Sistema: {self.os_info['environment']}{Style.RESET_ALL}")
        
        # Construir ruta del script
        script_path = self.scripts_path / module / script_info['file']
        
        if not script_path.exists():
            print(f"{Fore.RED}❌ Error: Script no encontrado en {script_path}{Style.RESET_ALL}")
            input(f"\n{Fore.CYAN}Presiona Enter para continuar...{Style.RESET_ALL}")
            return
        
        # Pedir parámetros si el script los necesita
        params = self.get_script_parameters(script_info['name'])
        
        try:
            print(f"{Fore.MAGENTA}⏳ Ejecutando script...{Style.RESET_ALL}")
            
            # Usar el detector de OS para obtener el comando apropiado
            cmd = os_detector.get_script_executor(str(script_path)) + params
            
            print(f"{Fore.CYAN}💻 Comando: {' '.join(cmd)}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}📁 Directorio de trabajo: {script_path.parent}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}📤 Salida en: {self.output_path}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
            
            # Configurar entorno
            env = os.environ.copy()
            env['BOFA_OUTPUT_PATH'] = str(self.output_path)
            env['BOFA_BASE_PATH'] = str(self.base_path)
            
            # Ejecutar script
            result = subprocess.run(
                cmd, 
                cwd=script_path.parent,
                env=env,
                capture_output=False, 
                text=True
            )
            
            print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
            if result.returncode == 0:
                print(f"{Fore.GREEN}✅ Script ejecutado exitosamente (código: {result.returncode}){Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}⚠️  Script finalizado con código: {result.returncode}{Style.RESET_ALL}")
                
        except FileNotFoundError as e:
            print(f"{Fore.RED}❌ Error: Comando no encontrado: {e}{Style.RESET_ALL}")
            self.show_installation_help()
        except PermissionError:
            print(f"{Fore.RED}❌ Error: Sin permisos para ejecutar el script{Style.RESET_ALL}")
            if self.os_info['system'] != 'Windows':
                print(f"{Fore.YELLOW}💡 Intenta: chmod +x {script_path}{Style.RESET_ALL}")
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}⚠️  Ejecución interrumpida por el usuario{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}❌ Error durante la ejecución: {str(e)}{Style.RESET_ALL}")
        
        input(f"\n{Fore.CYAN}Presiona Enter para continuar...{Style.RESET_ALL}")
    
    def show_installation_help(self):
        """Muestra ayuda de instalación según el sistema"""
        print(f"\n{Fore.YELLOW}💡 Ayuda de instalación para {self.os_info['environment']}:{Style.RESET_ALL}")
        
        if self.os_info['system'] == 'Windows':
            if self.os_info['is_wsl']:
                print(f"{Fore.CYAN}   • Instala Python: sudo apt install python3 python3-pip{Style.RESET_ALL}")
                print(f"{Fore.CYAN}   • Instala dependencias: pip3 install -r cli/requirements.txt{Style.RESET_ALL}")
            else:
                print(f"{Fore.CYAN}   • Instala Python desde: https://python.org/downloads{Style.RESET_ALL}")
                print(f"{Fore.CYAN}   • O desde Microsoft Store: Python 3.11{Style.RESET_ALL}")
                print(f"{Fore.CYAN}   • Instala Git Bash para scripts .sh{Style.RESET_ALL}")
        elif self.os_info['system'] == 'Linux':
            distro = self.os_info.get('distro', 'linux')
            if distro in ['ubuntu', 'debian', 'kali']:
                print(f"{Fore.CYAN}   • sudo apt update && sudo apt install python3 python3-pip{Style.RESET_ALL}")
            elif distro in ['fedora', 'centos']:
                print(f"{Fore.CYAN}   • sudo dnf install python3 python3-pip{Style.RESET_ALL}")
            elif distro in ['arch', 'manjaro']:
                print(f"{Fore.CYAN}   • sudo pacman -S python python-pip{Style.RESET_ALL}")
    
    def get_script_parameters(self, script_name):
        # ... keep existing code (parameter gathering)
        params = []
        
        if script_name == "web_discover.py":
            domain = input(f"{Fore.YELLOW}🌐 Introduce el dominio objetivo: {Style.RESET_ALL}")
            if domain.strip():
                params.extend(['-d', domain.strip()])
                
                timeout = input(f"{Fore.YELLOW}⏱️  Timeout en segundos (default: 5): {Style.RESET_ALL}")
                if timeout.strip() and timeout.isdigit():
                    params.extend(['-t', timeout])
                    
                threads = input(f"{Fore.YELLOW}🧵 Número de threads (default: 50): {Style.RESET_ALL}")
                if threads.strip() and threads.isdigit():
                    params.extend(['--threads', threads])
        
        elif script_name == "port_slayer.sh":
            target = input(f"{Fore.YELLOW}🎯 Introduce el target (IP/dominio): {Style.RESET_ALL}")
            if target.strip():
                params.append(target.strip())
                
                mode = input(f"{Fore.YELLOW}🔍 Modo (f=fast, s=stealth, a=all): {Style.RESET_ALL}")
                if mode.lower() in ['f', 's', 'a']:
                    params.insert(0, f'-{mode.lower()}')
        
        elif script_name == "social_profile_mapper.py":
            username = input(f"{Fore.YELLOW}👤 Introduce el nombre de usuario: {Style.RESET_ALL}")
            if username.strip():
                params.extend(['-u', username.strip()])
                
                variations = input(f"{Fore.YELLOW}🔄 ¿Buscar variaciones? (y/n): {Style.RESET_ALL}")
                if variations.lower() == 'y':
                    params.append('--variations')
        
        elif script_name == "reverse_shell_generator.py":
            ip = input(f"{Fore.YELLOW}🌐 IP del atacante: {Style.RESET_ALL}")
            port = input(f"{Fore.YELLOW}🔌 Puerto: {Style.RESET_ALL}")
            if ip.strip() and port.strip():
                params.extend(['--ip', ip.strip(), '--port', port.strip()])
        
        elif script_name == "log_guardian.py":
            log_file = input(f"{Fore.YELLOW}📋 Archivo de log (default: /var/log/auth.log): {Style.RESET_ALL}")
            if log_file.strip():
                params.extend(['-f', log_file.strip()])
            else:
                params.extend(['-f', '/var/log/auth.log'])
        
        return params
        
    def show_module_menu(self, module_name, scripts):
        # ... keep existing code (module menu display)
        self.clear_screen()
        self.print_banner()
        
        print(f"{Fore.CYAN}═══════════════════════════════════════════════════════════════════")
        print(f"                        MÓDULO: {module_name.upper()}")
        print(f"═══════════════════════════════════════════════════════════════════{Style.RESET_ALL}")
        
        if not scripts:
            print(f"{Fore.YELLOW}⚠️  No hay scripts disponibles en este módulo todavía.{Style.RESET_ALL}")
            print(f"{Fore.CYAN}💡 Próximamente se añadirán herramientas avanzadas.{Style.RESET_ALL}")
        else:
            for i, script in enumerate(scripts, 1):
                print(f"{Fore.GREEN}[{i}]{Fore.WHITE} {script['display_name']}")
                
        print(f"\n{Fore.RED}[0]{Fore.WHITE} ← Volver al menú principal")
        
        choice = input(f"\n{Fore.YELLOW}Selecciona una opción: {Style.RESET_ALL}")
        
        if choice == "0":
            return
        elif choice.isdigit() and 1 <= int(choice) <= len(scripts):
            self.execute_script(module_name.lower(), scripts[int(choice)-1])
        else:
            print(f"{Fore.RED}❌ Opción inválida.{Style.RESET_ALL}")
            time.sleep(1)
    
    def show_system_info(self):
        """Muestra información detallada del sistema"""
        self.clear_screen()
        self.print_banner()
        
        print(f"{Fore.CYAN}═══════════════════════════════════════════════════════════════════")
        print(f"                    INFORMACIÓN DEL SISTEMA")
        print(f"═══════════════════════════════════════════════════════════════════{Style.RESET_ALL}")
        
        # Información del sistema operativo
        print(f"{Fore.GREEN}🖥️  Sistema Operativo:{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}• Entorno: {self.os_info['environment']}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}• Sistema: {self.os_info['system']}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}• Plataforma: {self.os_info['platform']}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}• Arquitectura: {self.os_info['architecture']}{Style.RESET_ALL}")
        
        if 'distro' in self.os_info:
            print(f"  {Fore.YELLOW}• Distribución: {self.os_info['distro'].title()}{Style.RESET_ALL}")
        
        if self.os_info['is_wsl']:
            print(f"  {Fore.YELLOW}• WSL2: ✅ Detectado{Style.RESET_ALL}")
        
        # Información de Python
        print(f"\n{Fore.GREEN}🐍 Python:{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}• Versión: {self.os_info['python_version']}{Style.RESET_ALL}")
        python_info = os_detector.python_available
        print(f"  {Fore.YELLOW}• Ejecutable: {python_info.get('python3', 'No encontrado')}{Style.RESET_ALL}")
        
        # Información de Docker
        print(f"\n{Fore.GREEN}🐳 Docker:{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}• Instalado: {'✅' if self.docker_available['installed'] else '❌'}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}• Corriendo: {'✅' if self.docker_available['running'] else '❌'}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}• Compose: {'✅' if self.docker_available['compose_available'] else '❌'}{Style.RESET_ALL}")
        
        if self.docker_available['desktop_detected']:
            print(f"  {Fore.YELLOW}• Docker Desktop: ✅ Detectado{Style.RESET_ALL}")
        
        # Información de rutas
        print(f"\n{Fore.GREEN}📁 Rutas BOFA:{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}• Base: {self.base_path}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}• Scripts: {self.scripts_path}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}• Salida: {self.output_path}{Style.RESET_ALL}")
        
        # Conteo de scripts
        script_count = self.count_available_scripts()
        print(f"\n{Fore.GREEN}📊 Scripts Disponibles:{Style.RESET_ALL}")
        for module, count in script_count.items():
            print(f"  {Fore.YELLOW}• {module.title()}: {count}{Style.RESET_ALL}")
        
        input(f"\n{Fore.CYAN}Presiona Enter para volver...{Style.RESET_ALL}")
    
    def count_available_scripts(self):
        """Cuenta scripts disponibles por módulo"""
        modules = {
            'reconocimiento': self.get_scripts_for_module("reconocimiento"),
            'explotacion': self.get_scripts_for_module("explotacion"), 
            'osint': self.get_scripts_for_module("osint"),
            'social': self.get_scripts_for_module("social"),
            'blue': self.get_scripts_for_module("blue"),
            'malware': self.get_scripts_for_module("malware"),
            'purple': self.get_scripts_for_module("purple"),
            'dockerlabs': self.get_scripts_for_module("dockerlabs"),
            'estudio': self.get_scripts_for_module("estudio")
        }
        
        return {module: len(scripts) for module, scripts in modules.items()}

    def get_scripts_for_module(self, module):
        # ... keep existing code (script mapping)
        scripts_map = {
            "reconocimiento": [
                {
                    "name": "web_discover.py",
                    "file": "web_discover.py", 
                    "display_name": "🌐 web_discover.py - Descubrimiento web automático",
                    "description": "Herramienta de descubrimiento de subdominios y servicios web"
                },
                {
                    "name": "port_slayer.sh",
                    "file": "port_slayer.sh",
                    "display_name": "🔍 port_slayer.sh - Escaneo de puertos avanzado", 
                    "description": "Escaneo avanzado TCP/UDP usando nmap"
                }
            ],
            "explotacion": [
                {
                    "name": "reverse_shell_generator.py",
                    "file": "reverse_shell_generator.py",
                    "display_name": "🐚 reverse_shell_generator.py - Generador reverse shells",
                    "description": "Generador de reverse shells en múltiples lenguajes"
                },
                {
                    "name": "kerberoast_scanner.py",
                    "file": "kerberoast_scanner.py",
                    "display_name": "🎯 kerberoast_scanner.py - Scanner Kerberoasting",
                    "description": "Ataque automatizado contra cuentas de servicio AD"
                },
                {
                    "name": "av_evasion_engine.py",
                    "file": "av_evasion_engine.py",
                    "display_name": "🛡️ av_evasion_engine.py - Motor evasión AV",
                    "description": "Motor de mutación de binarios para evadir AV"
                }
            ],
            "osint": [
                {
                    "name": "social_profile_mapper.py", 
                    "file": "social_profile_mapper.py",
                    "display_name": "👤 social_profile_mapper.py - Mapeo perfiles sociales",
                    "description": "Mapeo automático de perfiles sociales"
                }
            ],
            "social": [],
            "blue": [
                {
                    "name": "log_guardian.py",
                    "file": "log_guardian.py", 
                    "display_name": "📊 log_guardian.py - Guardian de logs",
                    "description": "Monitor avanzado de logs del sistema"
                },
                {
                    "name": "siem_alert_simulator.py",
                    "file": "siem_alert_simulator.py",
                    "display_name": "🚨 siem_alert_simulator.py - Simulador SIEM",
                    "description": "Generador de eventos sospechosos para SIEM"
                }
            ],
            "purple": [
                {
                    "name": "purple_attack_orchestrator.py",
                    "file": "purple_attack_orchestrator.py",
                    "display_name": "🟣 purple_attack_orchestrator.py - Orquestador Purple",
                    "description": "Orquestador de ataques coordinados Purple Team"
                }
            ],
            "malware": [],
            "dockerlabs": [
                {
                    "name": "lab_manager.py",
                    "file": "lab_manager.py",
                    "display_name": "🐳 lab_manager.py - Gestor de laboratorios",
                    "description": "Gestión de laboratorios Docker vulnerables"
                }
            ],
            "estudio": [
                {
                    "name": "sql_injection_trainer.py",
                    "file": "../../study/sql_injection/learn_sql_injection.py",
                    "display_name": "📚 SQL Injection - Fundamentos",
                    "description": "Entrenamiento interactivo de inyección SQL"
                },
                {
                    "name": "xss_trainer.py", 
                    "file": "../../study/xss/xss_trainer.py",
                    "display_name": "📚 XSS - Cross-Site Scripting",
                    "description": "Entrenamiento de vulnerabilidades XSS"
                },
                {
                    "name": "privesc_trainer.py", 
                    "file": "../../study/privilege_escalation/privesc_trainer.py",
                    "display_name": "📚 Privilege Escalation - Escalada de privilegios",
                    "description": "Técnicas avanzadas de escalada de privilegios"
                }
            ]
        }
        
        return scripts_map.get(module, [])

    def show_config_menu(self):
        # ... keep existing code (config menu)
        self.clear_screen()
        self.print_banner()
        
        print(f"{Fore.CYAN}═══════════════════════════════════════════════════════════════════")
        print(f"                           CONFIGURACIÓN")
        print(f"═══════════════════════════════════════════════════════════════════{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}📊 Estado del Sistema:{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}• Versión BOFA: {self.version}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}• Desarrollador: {self.author}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}• Sistema: {self.os_info['environment']}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}• Docker: {'Disponible' if self.docker_available['running'] else 'No disponible'}{Style.RESET_ALL}")
        
        script_count = sum(self.count_available_scripts().values())
        print(f"  {Fore.YELLOW}• Scripts disponibles: {script_count}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}• Ruta scripts: {self.scripts_path}{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}🔗 Enlaces útiles:{Style.RESET_ALL}")
        if self.docker_available['running']:
            print(f"  {Fore.CYAN}• Panel Web: https://localhost{Style.RESET_ALL}")
            print(f"  {Fore.CYAN}• API Backend: http://localhost:8000{Style.RESET_ALL}")
            print(f"  {Fore.CYAN}• Documentación: http://localhost:8000/docs{Style.RESET_ALL}")
        else:
            print(f"  {Fore.YELLOW}• Panel Web: Requiere Docker{Style.RESET_ALL}")
            print(f"  {Fore.YELLOW}• Para habilitar: docker-compose up{Style.RESET_ALL}")
        
        input(f"\n{Fore.CYAN}Presiona Enter para volver...{Style.RESET_ALL}")
        
    def run(self):
        while True:
            self.clear_screen()
            self.print_banner()
            self.print_menu()
            
            try:
                choice = input(f"{Fore.YELLOW}Selecciona una opción [0-9,A,C]: {Style.RESET_ALL}").upper()
                
                if choice == "0":
                    print(f"\n{Fore.CYAN}🛡️  Gracias por usar BOFA!")
                    print(f"Desarrollado por {self.author}")
                    print(f"Sistema: {self.os_info['environment']}")
                    print(f"¡Mantente seguro! 👋{Style.RESET_ALL}")
                    sys.exit(0)
                    
                elif choice == "1":
                    scripts = self.get_scripts_for_module("reconocimiento")
                    self.show_module_menu("Reconocimiento", scripts)
                    
                elif choice == "2":
                    scripts = self.get_scripts_for_module("explotacion")
                    self.show_module_menu("Explotación", scripts)
                    
                elif choice == "3":
                    scripts = self.get_scripts_for_module("osint")
                    self.show_module_menu("OSINT", scripts)
                    
                elif choice == "4":
                    scripts = self.get_scripts_for_module("social")
                    self.show_module_menu("Ingeniería Social", scripts)
                    
                elif choice == "5":
                    scripts = self.get_scripts_for_module("blue")
                    self.show_module_menu("Blue Team", scripts)
                    
                elif choice == "6":
                    scripts = self.get_scripts_for_module("malware")
                    self.show_module_menu("Análisis Malware", scripts)
                    
                elif choice == "7":
                    scripts = self.get_scripts_for_module("dockerlabs")
                    self.show_module_menu("Docker Labs", scripts)
                    
                elif choice == "8":
                    scripts = self.get_scripts_for_module("estudio")
                    self.show_module_menu("Modo Estudio", scripts)
                    
                elif choice == "9":
                    scripts = self.get_scripts_for_module("purple")
                    self.show_module_menu("Purple Team", scripts)
                    
                elif choice == "A":
                    self.show_system_info()
                    
                elif choice == "C":
                    self.show_config_menu()
                    
                else:
                    print(f"{Fore.RED}❌ Opción inválida. Por favor selecciona una opción válida.{Style.RESET_ALL}")
                    time.sleep(1)
                    
            except KeyboardInterrupt:
                print(f"\n\n{Fore.CYAN}🛡️  Saliendo de BOFA CLI...")
                print(f"¡Hasta la próxima! 👋{Style.RESET_ALL}")
                sys.exit(0)
            except Exception as e:
                print(f"{Fore.RED}❌ Error: {str(e)}{Style.RESET_ALL}")
                time.sleep(2)

if __name__ == "__main__":
    cli = BOFAcli()
    cli.run()
