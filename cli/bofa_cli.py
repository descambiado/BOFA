#!/usr/bin/env python3
"""
BOFA CLI - Best Of All Command Line Interface
Desarrollado por @descambiado (David Hernández Jiménez)
"""

import os
import sys
import time
import subprocess
import shlex
from colorama import Fore, Back, Style, init

# Inicializar colorama
init(autoreset=True)

class BOFAcli:
    def __init__(self):
        self.version = "v1.0.0"
        self.author = "@descambiado"
        self.scripts_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
        
    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        
    def print_banner(self):
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
╚══════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)
        
    def print_menu(self):
        menu = f"""
{Fore.YELLOW}┌─────────────────────────────────────────────────────────────────┐
│                        MENÚ PRINCIPAL                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  {Fore.GREEN}[1]{Fore.WHITE} 🕵️  Reconocimiento        {Fore.GREEN}[2]{Fore.WHITE} 💥 Explotación          │
│  {Fore.GREEN}[3]{Fore.WHITE} 🔍 OSINT                  {Fore.GREEN}[4]{Fore.WHITE} 🎭 Ingeniería Social    │
│  {Fore.GREEN}[5]{Fore.WHITE} 🛡️  Blue Team             {Fore.GREEN}[6]{Fore.WHITE} 🧪 Análisis Malware     │
│  {Fore.GREEN}[7]{Fore.WHITE} 🐳 Docker Labs            {Fore.GREEN}[8]{Fore.WHITE} 🎓 Modo Estudio         │
│                                                                 │
│  {Fore.CYAN}[9]{Fore.WHITE} ⚙️  Configuración          {Fore.RED}[0]{Fore.WHITE} 🚪 Salir                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘{Style.RESET_ALL}
"""
        print(menu)
        
    def execute_script(self, module, script_info):
        """Ejecuta un script real del sistema"""
        print(f"\n{Fore.CYAN}🚀 Ejecutando: {script_info['name']}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}📁 Módulo: {module}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}📝 Descripción: {script_info['description']}{Style.RESET_ALL}")
        
        # Construir ruta del script
        script_path = os.path.join(self.scripts_path, module, script_info['file'])
        
        if not os.path.exists(script_path):
            print(f"{Fore.RED}❌ Error: Script no encontrado en {script_path}{Style.RESET_ALL}")
            input(f"\n{Fore.CYAN}Presiona Enter para continuar...{Style.RESET_ALL}")
            return
        
        # Verificar permisos de ejecución
        if not os.access(script_path, os.X_OK):
            print(f"{Fore.YELLOW}⚠️  Añadiendo permisos de ejecución...{Style.RESET_ALL}")
            try:
                os.chmod(script_path, 0o755)
            except Exception as e:
                print(f"{Fore.RED}❌ Error al cambiar permisos: {str(e)}{Style.RESET_ALL}")
                input(f"\n{Fore.CYAN}Presiona Enter para continuar...{Style.RESET_ALL}")
                return
        
        # Pedir parámetros si el script los necesita
        params = self.get_script_parameters(script_info['name'])
        
        try:
            print(f"{Fore.MAGENTA}⏳ Ejecutando script...{Style.RESET_ALL}")
            
            # Construir comando
            if script_info['file'].endswith('.py'):
                cmd = ['python3', script_path] + params
            elif script_info['file'].endswith('.sh'):
                cmd = ['bash', script_path] + params
            else:
                cmd = [script_path] + params
            
            print(f"{Fore.CYAN}💻 Comando: {' '.join(cmd)}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
            
            # Ejecutar script
            result = subprocess.run(cmd, capture_output=False, text=True, cwd=os.path.dirname(script_path))
            
            print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
            if result.returncode == 0:
                print(f"{Fore.GREEN}✅ Script ejecutado exitosamente (código: {result.returncode}){Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}⚠️  Script finalizado con código: {result.returncode}{Style.RESET_ALL}")
                
        except FileNotFoundError:
            print(f"{Fore.RED}❌ Error: Intérprete no encontrado. Verifica que Python3/Bash estén instalados.{Style.RESET_ALL}")
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}⚠️  Ejecución interrumpida por el usuario{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}❌ Error durante la ejecución: {str(e)}{Style.RESET_ALL}")
        
        input(f"\n{Fore.CYAN}Presiona Enter para continuar...{Style.RESET_ALL}")
    
    def get_script_parameters(self, script_name):
        """Obtiene parámetros específicos según el script"""
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
            
    def get_scripts_for_module(self, module):
        """Obtiene scripts reales disponibles para cada módulo"""
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
                }
            ]
        }
        
        return scripts_map.get(module, [])

    def show_labs_menu(self):
        """Muestra el menú de laboratorios Docker"""
        self.clear_screen()
        self.print_banner()
        
        print(f"{Fore.CYAN}═══════════════════════════════════════════════════════════════════")
        print(f"                        LABORATORIOS DOCKER")
        print(f"═══════════════════════════════════════════════════════════════════{Style.RESET_ALL}")
        
        labs = [
            ("web-sqli", "🌐 SQL Injection Lab", "Aplicación web vulnerable para SQLi"),
            ("internal-network", "🕸️  Internal Network Lab", "Red interna con múltiples máquinas"),
            ("siem-detection", "🛡️  SIEM Detection Lab", "Laboratorio Blue Team con Wazuh"),
            ("malware-lab", "🦠 Malware Analysis Lab", "Entorno aislado para análisis de malware"),
            ("red-vs-blue", "⚔️  Red vs Blue Exercise", "Ejercicio competitivo de equipos")
        ]
        
        for i, (lab_id, name, desc) in enumerate(labs, 1):
            status = self.get_lab_status(lab_id)
            status_color = Fore.GREEN if status == "running" else Fore.RED
            print(f"{Fore.GREEN}[{i}]{Fore.WHITE} {name}")
            print(f"    {desc}")
            print(f"    Estado: {status_color}{status}{Style.RESET_ALL}")
            print()
        
        print(f"{Fore.YELLOW}[L]{Fore.WHITE} 📋 Listar laboratorios activos")
        print(f"{Fore.YELLOW}[S]{Fore.WHITE} 🛑 Detener todos los laboratorios")
        print(f"{Fore.RED}[0]{Fore.WHITE} ← Volver al menú principal")
        
        choice = input(f"\n{Fore.YELLOW}Selecciona una opción: {Style.RESET_ALL}")
        
        if choice == "0":
            return
        elif choice.upper() == "L":
            self.list_active_labs()
        elif choice.upper() == "S":
            self.stop_all_labs()
        elif choice.isdigit() and 1 <= int(choice) <= len(labs):
            lab_id, name, desc = labs[int(choice)-1]
            self.manage_lab(lab_id, name)
        else:
            print(f"{Fore.RED}❌ Opción inválida.{Style.RESET_ALL}")
            time.sleep(1)
            
    def get_lab_status(self, lab_id):
        """Obtiene el estado de un laboratorio"""
        try:
            # En un entorno real, esto consultaría el estado de Docker
            import subprocess
            result = subprocess.run(['docker-compose', '-f', f'labs/{lab_id}/docker-compose.yml', 'ps'], 
                                  capture_output=True, text=True, cwd=os.path.dirname(self.scripts_path))
            return "running" if "Up" in result.stdout else "stopped"
        except:
            return "stopped"
    
    def manage_lab(self, lab_id, lab_name):
        """Gestiona un laboratorio específico"""
        self.clear_screen()
        self.print_banner()
        
        print(f"{Fore.CYAN}═══════════════════════════════════════════════════════════════════")
        print(f"                    LABORATORIO: {lab_name.upper()}")
        print(f"═══════════════════════════════════════════════════════════════════{Style.RESET_ALL}")
        
        status = self.get_lab_status(lab_id)
        status_color = Fore.GREEN if status == "running" else Fore.RED
        print(f"{Fore.YELLOW}Estado actual: {status_color}{status}{Style.RESET_ALL}\n")
        
        print(f"{Fore.GREEN}[1]{Fore.WHITE} 🚀 Iniciar laboratorio")
        print(f"{Fore.RED}[2]{Fore.WHITE} 🛑 Detener laboratorio") 
        print(f"{Fore.YELLOW}[3]{Fore.WHITE} 🔄 Reiniciar laboratorio")
        print(f"{Fore.BLUE}[4]{Fore.WHITE} 📋 Ver logs")
        print(f"{Fore.CYAN}[5]{Fore.WHITE} 📖 Ver documentación")
        print(f"{Fore.RED}[0]{Fore.WHITE} ← Volver")
        
        choice = input(f"\n{Fore.YELLOW}Selecciona una acción: {Style.RESET_ALL}")
        
        if choice == "0":
            return
        elif choice == "1":
            self.start_lab(lab_id, lab_name)
        elif choice == "2":
            self.stop_lab(lab_id, lab_name)
        elif choice == "3":
            self.restart_lab(lab_id, lab_name)
        elif choice == "4":
            self.view_lab_logs(lab_id, lab_name)
        elif choice == "5":
            self.view_lab_docs(lab_id, lab_name)
    
    def start_lab(self, lab_id, lab_name):
        """Inicia un laboratorio"""
        print(f"{Fore.CYAN}🚀 Iniciando laboratorio {lab_name}...{Style.RESET_ALL}")
        try:
            import subprocess
            lab_path = os.path.join(os.path.dirname(self.scripts_path), "labs", lab_id)
            result = subprocess.run(['docker-compose', 'up', '-d'], 
                                  cwd=lab_path, capture_output=True, text=True)
            if result.returncode == 0:
                print(f"{Fore.GREEN}✅ Laboratorio iniciado correctamente{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}🌐 Accede en: http://localhost{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}❌ Error al iniciar el laboratorio{Style.RESET_ALL}")
                print(result.stderr)
        except Exception as e:
            print(f"{Fore.RED}❌ Error: {str(e)}{Style.RESET_ALL}")
        
        input(f"\n{Fore.CYAN}Presiona Enter para continuar...{Style.RESET_ALL}")

    def show_config_menu(self):
        self.clear_screen()
        self.print_banner()
        
        print(f"{Fore.CYAN}═══════════════════════════════════════════════════════════════════")
        print(f"                           CONFIGURACIÓN")
        print(f"═══════════════════════════════════════════════════════════════════{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}📊 Estado del Sistema:{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}• Versión BOFA: {self.version}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}• Desarrollador: {self.author}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}• Scripts disponibles: 5 activos{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}• Módulos activos: 6{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}• Ruta scripts: {self.scripts_path}{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}🔗 Enlaces útiles:{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}• Panel Web: https://localhost{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}• API Backend: http://localhost:8000{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}• Documentación: http://localhost:8000/docs{Style.RESET_ALL}")
        
        input(f"\n{Fore.CYAN}Presiona Enter para volver...{Style.RESET_ALL}")
        
    def run(self):
        while True:
            self.clear_screen()
            self.print_banner()
            self.print_menu()
            
            try:
                choice = input(f"{Fore.YELLOW}Selecciona una opción [0-9]: {Style.RESET_ALL}")
                
                if choice == "0":
                    print(f"\n{Fore.CYAN}🛡️  Gracias por usar BOFA!")
                    print(f"Desarrollado por {self.author}")
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
                    self.show_config_menu()
                    
                else:
                    print(f"{Fore.RED}❌ Opción inválida. Por favor selecciona 0-9.{Style.RESET_ALL}")
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
