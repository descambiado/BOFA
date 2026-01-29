#!/usr/bin/env python3
"""
BOFA CLI - Command Line Interface
=================================

Interfaz de línea de comandos de BOFA. Capa de presentación sobre el core.
Utiliza exclusivamente el core engine para descubrir módulos y ejecutar scripts.

Desarrollado por @descambiado (David Hernández Jiménez)
Versión multiplataforma: Windows 11, WSL2, Linux
"""

import os
import sys
import time
from pathlib import Path
from colorama import Fore, Style, init

# Directorios de interés
_CLI_DIR = Path(__file__).resolve().parent
_ROOT_DIR = _CLI_DIR.parent

# Añadir raíz del proyecto para importar el core
if str(_ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(_ROOT_DIR))

# Importar core de BOFA (única dependencia de lógica)
from core.engine import get_engine
from core.config import get_config
from core.logger import setup_logging, get_logger
from core.errors import (
    BOFAError,
    ModuleNotFoundError,
    ScriptNotFoundError,
    ExecutionError,
    ValidationError,
)
from flows.flow_runner import list_flows, run_flow

# Importar detector de OS (vive en cli/; exporta instancia os_detector)
try:
    import importlib.util
    _spec = importlib.util.spec_from_file_location("os_detector", _CLI_DIR / "os_detector.py")
    _mod = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    os_detector = _mod.os_detector  # instancia OSDetector()
except Exception:
    print("❌ Error: No se pudo cargar os_detector.py")
    print("💡 Ejecuta desde la raíz: ./bofa.sh o python3 cli/bofa_cli.py")
    sys.exit(1)

# Inicializar colorama
init(autoreset=True)

# Configurar logging (silencio por defecto en CLI interactiva)
setup_logging()
logger = get_logger(__name__)


class BOFAcli:
    """
    CLI de BOFA. Solo capa de presentación.
    
    Toda la lógica (módulos, scripts, ejecución) la gestiona el core.
    La CLI solo muestra menús, pide input y muestra resultados.
    """

    VERSION = "2.6.0"
    AUTHOR = "@descambiado"

    # Mapeo tecla -> nombre de módulo (descubierto por el core)
    MODULE_MENU = {
        "1": "recon",
        "2": "exploit",
        "3": "osint",
        "4": "social",
        "5": "blue",
        "6": "malware",
        "7": "dockerlabs",
        "8": "study",
        "9": "purple",
        "E": "examples",  # Módulos de ejemplo oficiales
    }

    def __init__(self):
        """Inicializar CLI. Carga config y engine del core."""
        self.version = self.VERSION
        self.author = self.AUTHOR
        self.config = get_config()
        self.engine = get_engine(self.config)
        self.os_info = os_detector.os_info
        self.docker_available = os_detector.docker_available
        logger.info("BOFA CLI iniciado", version=self.version)

    def clear_screen(self):
        """Limpiar pantalla según el sistema operativo."""
        if self.os_info.get("system") == "Windows" and not self.os_info.get("is_wsl"):
            os.system("cls")
        else:
            os.system("clear")

    def print_banner(self):
        """Imprimir banner de BOFA."""
        os_emoji = {"Windows": "🪟", "WSL2": "🐧", "Linux": "🐧", "Unix": "🖥️"}
        env_emoji = os_emoji.get(self.os_info.get("environment", ""), "🖥️")
        docker_ok = "✅" if self.docker_available.get("running") else "❌"

        print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║  {Fore.RED}██████╗  ██████╗ ███████╗ █████╗     {Fore.CYAN}Best Of All Suite          ║
║  {Fore.RED}██╔══██╗██╔═══██╗██╔════╝██╔══██╗    {Fore.CYAN}Ciberseguridad Profesional ║
║  {Fore.RED}██████╔╝██║   ██║█████╗  ███████║    {Fore.CYAN}                           ║
║  {Fore.RED}██╔══██╗██║   ██║██╔══╝  ██╔══██║    {Fore.CYAN}Versión: {self.version}            ║
║  {Fore.RED}██████╔╝╚██████╔╝██║     ██║  ██║    {Fore.CYAN}Por: {self.author}       ║
║  {Fore.RED}╚═════╝  ╚═════╝ ╚═╝     ╚═╝  ╚═╝                            ║
║                                                                  ║
║  {env_emoji} {Fore.YELLOW}Sistema: {self.os_info.get('environment', 'N/A'):<12} {Fore.YELLOW}🐳 Docker: {docker_ok:<3}        ║
╚══════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
""")

    def print_menu(self):
        """Imprimir menú principal. Opciones fijas, módulos vienen del core."""
        print(f"""
{Fore.YELLOW}┌─────────────────────────────────────────────────────────────────┐
│                        MENÚ PRINCIPAL                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  {Fore.GREEN}[1]{Fore.WHITE} 🕵️  Reconocimiento        {Fore.GREEN}[2]{Fore.WHITE} 💥 Explotación          │
│  {Fore.GREEN}[3]{Fore.WHITE} 🔍 OSINT                  {Fore.GREEN}[4]{Fore.WHITE} 🎭 Ingeniería Social    │
│  {Fore.GREEN}[5]{Fore.WHITE} 🛡️  Blue Team             {Fore.GREEN}[6]{Fore.WHITE} 🧪 Análisis Malware     │
│  {Fore.GREEN}[7]{Fore.WHITE} 🐳 Docker Labs            {Fore.GREEN}[8]{Fore.WHITE} 🎓 Modo Estudio         │
│  {Fore.GREEN}[9]{Fore.WHITE} 🟣 Purple Team            {Fore.GREEN}[E]{Fore.WHITE} 📚 Ejemplos              │
│                                                                 │
│  {Fore.CYAN}[A]{Fore.WHITE} ℹ️  Información Sistema    {Fore.CYAN}[C]{Fore.WHITE} ⚙️  Configuración         │
│  {Fore.CYAN}[F]{Fore.WHITE} 🔄 Flujos (run flow + informe)                               │
│  {Fore.RED}[0]{Fore.WHITE} 🚪 Salir                                                      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘{Style.RESET_ALL}
""")

    def show_module_menu(self, module_name: str):
        """Mostrar listado de scripts de un módulo (datos del core)."""
        self.clear_screen()
        self.print_banner()

        try:
            module = self.engine.get_module(module_name)
        except ModuleNotFoundError:
            print(f"{Fore.RED}❌ Módulo '{module_name}' no encontrado.{Style.RESET_ALL}")
            input(f"\n{Fore.CYAN}Presiona Enter para continuar...{Style.RESET_ALL}")
            return

        print(f"{Fore.CYAN}═══════════════════════════════════════════════════════════════════")
        print(f"                        MÓDULO: {module_name.upper()}")
        print(f"═══════════════════════════════════════════════════════════════════{Style.RESET_ALL}")
        if module.description:
            print(f"{Fore.YELLOW}{module.description}{Style.RESET_ALL}\n")

        if not module.scripts:
            print(f"{Fore.YELLOW}⚠️  No hay scripts en este módulo.{Style.RESET_ALL}")
        else:
            for i, script in enumerate(module.scripts, 1):
                desc = (script.description[:50] + "...") if len(script.description or "") > 50 else (script.description or "")
                print(f"  {Fore.GREEN}[{i}]{Fore.WHITE} {script.name}")
                if desc:
                    print(f"      {Fore.CYAN}{desc}{Style.RESET_ALL}")
        print(f"\n  {Fore.RED}[0]{Fore.WHITE} ← Volver al menú principal")

        choice = input(f"\n{Fore.YELLOW}Opción: {Style.RESET_ALL}").strip()
        if choice == "0":
            return
        if choice.isdigit() and 1 <= int(choice) <= len(module.scripts):
            script = module.scripts[int(choice) - 1]
            self.execute_script(module_name, script)
        else:
            print(f"{Fore.RED}❌ Opción inválida.{Style.RESET_ALL}")
            time.sleep(1)

    def get_script_parameters(self, script_info) -> dict:
        """Pedir parámetros al usuario según la especificación del script (core)."""
        parameters = {}
        if not getattr(script_info, "parameters", None):
            return parameters

        print(f"\n{Fore.CYAN}📋 Parámetros del script:{Style.RESET_ALL}")
        for param_name, param_spec in script_info.parameters.items():
            required = param_spec.get("required", False)
            default = param_spec.get("default")
            description = param_spec.get("description", "")
            # Tipo en YAML puede ser string "str"/"int"/"bool" (documentación)
            param_type = param_spec.get("type")
            if isinstance(param_type, str):
                type_hint = param_type.lower()
            else:
                type_hint = "str"

            prompt = f"  {Fore.YELLOW}{param_name}"
            if description:
                prompt += f" ({description})"
            if required:
                prompt += f" {Fore.RED}*{Fore.YELLOW}"
            if default is not None:
                prompt += f" [default: {default}]"
            prompt += f": {Style.RESET_ALL}"

            value = input(prompt).strip()
            if not value and default is not None:
                value = str(default)
            if not value and required:
                print(f"  {Fore.RED}⚠️  Requerido.{Style.RESET_ALL}")
                continue
            if not value:
                continue

            if type_hint == "int":
                try:
                    parameters[param_name] = int(value)
                except ValueError:
                    parameters[param_name] = value
            elif type_hint == "bool":
                parameters[param_name] = value.lower() in ("true", "1", "yes", "y")
            else:
                parameters[param_name] = value

        return parameters


    def execute_script(self, module_name: str, script_info):
        """Ejecutar un script mediante el core. Solo mostrar resultado."""
        print(f"\n{Fore.CYAN}🚀 Ejecutando: {script_info.name}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}📁 Módulo: {module_name}{Style.RESET_ALL}")
        if getattr(script_info, "description", None):
            print(f"{Fore.YELLOW}📝 {script_info.description}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}🖥️  Sistema: {self.os_info.get('environment', 'N/A')}{Style.RESET_ALL}")

        parameters = self.get_script_parameters(script_info)

        try:
            print(f"\n{Fore.MAGENTA}⏳ Ejecutando...{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
            result = self.engine.execute_script(
                module_name=module_name,
                script_name=script_info.name,
                parameters=parameters,
            )
            print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

            if result.status == "success":
                print(f"{Fore.GREEN}✅ Completado correctamente{Style.RESET_ALL}")
                print(f"{Fore.CYAN}⏱️  Duración: {result.duration:.2f}s{Style.RESET_ALL}")
                if result.stdout:
                    print(f"\n{Fore.YELLOW}📤 Salida:{Style.RESET_ALL}\n{result.stdout}")
            else:
                print(f"{Fore.RED}❌ Falló (código: {result.exit_code}){Style.RESET_ALL}")
                if result.stderr:
                    print(f"\n{Fore.RED}Error:{Style.RESET_ALL}\n{result.stderr}")
                if getattr(result, "error", None):
                    print(f"\n{Fore.RED}{result.error}{Style.RESET_ALL}")

        except ScriptNotFoundError as e:
            print(f"{Fore.RED}❌ {e}{Style.RESET_ALL}")
        except ValidationError as e:
            print(f"{Fore.RED}❌ Validación: {e}{Style.RESET_ALL}")
        except ExecutionError as e:
            print(f"{Fore.RED}❌ Ejecución: {e}{Style.RESET_ALL}")
        except BOFAError as e:
            print(f"{Fore.RED}❌ {e}{Style.RESET_ALL}")
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}⚠️  Interrumpido por el usuario.{Style.RESET_ALL}")
        except Exception as e:
            logger.exception("Error ejecutando script")
            print(f"{Fore.RED}❌ Error: {e}{Style.RESET_ALL}")

        input(f"\n{Fore.CYAN}Presiona Enter para continuar...{Style.RESET_ALL}")

    def show_system_info(self):
        """Información del sistema y del core (módulos/scripts descubiertos)."""
        self.clear_screen()
        self.print_banner()
        print(f"{Fore.CYAN}═══════════════════════════════════════════════════════════════════")
        print("                    INFORMACIÓN DEL SISTEMA")
        print(f"═══════════════════════════════════════════════════════════════════{Style.RESET_ALL}")

        print(f"\n{Fore.GREEN}🖥️  Sistema:{Style.RESET_ALL}")
        print(f"  • Entorno: {self.os_info.get('environment', 'N/A')}")
        print(f"  • Plataforma: {self.os_info.get('platform', 'N/A')}")
        print(f"\n{Fore.GREEN}🐳 Docker:{Style.RESET_ALL}")
        print(f"  • Instalado: {'✅' if self.docker_available.get('installed') else '❌'}")
        print(f"  • Corriendo: {'✅' if self.docker_available.get('running') else '❌'}")

        print(f"\n{Fore.GREEN}📊 BOFA (core):{Style.RESET_ALL}")
        print(f"  • Versión CLI: {self.version}")
        print(f"  • Base: {self.config.base_path}")
        print(f"  • Scripts: {self.config.scripts_path}")
        print(f"  • Salida: {self.config.output_path}")

        modules = self.engine.list_modules()
        total = 0
        print(f"\n{Fore.GREEN}📦 Módulos ({len(modules)}):{Style.RESET_ALL}")
        for name in sorted(modules):
            scripts = self.engine.list_scripts(name)
            count = len(scripts.get(name, []))
            total += count
            print(f"  • {name}: {count} scripts")
        print(f"  • Total scripts: {total}")

        input(f"\n{Fore.CYAN}Presiona Enter para volver...{Style.RESET_ALL}")

    def show_config_menu(self):
        """Mostrar configuración actual (del core)."""
        self.clear_screen()
        self.print_banner()
        print(f"{Fore.CYAN}═══════════════════════════════════════════════════════════════════")
        print("                           CONFIGURACIÓN")
        print(f"═══════════════════════════════════════════════════════════════════{Style.RESET_ALL}")
        print(f"\n{Fore.GREEN}📊 Estado:{Style.RESET_ALL}")
        print(f"  • Versión: {self.version}")
        print(f"  • Sistema: {self.os_info.get('environment', 'N/A')}")
        print(f"  • Log level: {self.config.log_level}")
        print(f"  • Log format: {self.config.log_format}")
        input(f"\n{Fore.CYAN}Presiona Enter para volver...{Style.RESET_ALL}")

    def show_flows_menu(self):
        """Listar flujos, pedir flujo + target, ejecutar y mostrar ruta del informe."""
        self.clear_screen()
        self.print_banner()
        print(f"{Fore.CYAN}═══════════════════════════════════════════════════════════════════")
        print("                        FLUJOS BOFA")
        print(f"═══════════════════════════════════════════════════════════════════{Style.RESET_ALL}\n")

        try:
            flows = list_flows()
        except Exception as e:
            logger.exception("Error listando flujos")
            print(f"{Fore.RED}❌ Error listando flujos: {e}{Style.RESET_ALL}")
            input(f"\n{Fore.CYAN}Presiona Enter para continuar...{Style.RESET_ALL}")
            return

        if not flows:
            print(f"{Fore.YELLOW}⚠️  No hay flujos definidos en config/flows/{Style.RESET_ALL}")
            input(f"\n{Fore.CYAN}Presiona Enter para continuar...{Style.RESET_ALL}")
            return

        for f in flows:
            print(f"  {Fore.GREEN}[{f['id']}]{Fore.WHITE} {f['name']} — {f['description'] or '(sin descripción)'}")
            print(f"      {Fore.CYAN}Pasos: {f['steps_count']}{Style.RESET_ALL}")
        print(f"\n  {Fore.RED}[0]{Fore.WHITE} ← Volver al menú principal")

        flow_choice = input(f"\n{Fore.YELLOW}Id del flujo (o 0 para volver): {Style.RESET_ALL}").strip().lower()
        if flow_choice == "0":
            return

        target = input(f"{Fore.YELLOW}Target (valor a inyectar en {{target}}): {Style.RESET_ALL}").strip()
        if not target:
            print(f"{Fore.RED}⚠️  Target requerido.{Style.RESET_ALL}")
            input(f"\n{Fore.CYAN}Presiona Enter para continuar...{Style.RESET_ALL}")
            return

        try:
            print(f"\n{Fore.MAGENTA}⏳ Ejecutando flujo '{flow_choice}' con target '{target}'...{Style.RESET_ALL}")
            result = run_flow(flow_choice, target)
            status = result.get("status", "unknown")
            report_path = result.get("report_path", "")

            if status == "success":
                print(f"{Fore.GREEN}✅ Flujo completado correctamente{Style.RESET_ALL}")
            elif status == "partial":
                print(f"{Fore.YELLOW}⚠️  Flujo completado con errores en algunos pasos{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}❌ Flujo falló{Style.RESET_ALL}")

            if report_path:
                print(f"\n{Fore.CYAN}📄 Informe guardado en:{Style.RESET_ALL}\n  {report_path}")
            for s in result.get("steps", []):
                color = Fore.GREEN if s.get("status") == "success" else Fore.RED
                print(f"  {color}• {s.get('module')}/{s.get('script')}: {s.get('status')} (exit {s.get('exit_code')}){Style.RESET_ALL}")
        except FileNotFoundError as e:
            print(f"{Fore.RED}❌ {e}{Style.RESET_ALL}")
        except Exception as e:
            logger.exception("Error ejecutando flujo")
            print(f"{Fore.RED}❌ Error: {e}{Style.RESET_ALL}")

        input(f"\n{Fore.CYAN}Presiona Enter para continuar...{Style.RESET_ALL}")

    def run(self):
        """Bucle principal. Solo menú e input; acciones delegadas al core."""
        while True:
            self.clear_screen()
            self.print_banner()
            self.print_menu()

            try:
                choice = input(f"{Fore.YELLOW}Opción [0-9,E,A,C,F]: {Style.RESET_ALL}").strip().upper()
            except (KeyboardInterrupt, EOFError):
                print(f"\n{Fore.CYAN}🛡️  Saliendo de BOFA CLI. ¡Hasta pronto! 👋{Style.RESET_ALL}")
                sys.exit(0)

            if choice == "0":
                print(f"\n{Fore.CYAN}🛡️  Gracias por usar BOFA. ¡Hasta pronto! 👋{Style.RESET_ALL}")
                sys.exit(0)
            if choice in self.MODULE_MENU:
                self.show_module_menu(self.MODULE_MENU[choice])
            elif choice == "A":
                self.show_system_info()
            elif choice == "C":
                self.show_config_menu()
            elif choice == "F":
                self.show_flows_menu()
            else:
                print(f"{Fore.RED}❌ Opción inválida.{Style.RESET_ALL}")
                time.sleep(1)


def main():
    """Punto de entrada para pyproject / bofa-cli."""
    try:
        cli = BOFAcli()
        cli.run()
    except Exception as e:
        logger.exception("Error fatal en CLI")
        print(f"{Fore.RED}❌ Error fatal: {e}{Style.RESET_ALL}")
        sys.exit(1)


if __name__ == "__main__":
    main()
