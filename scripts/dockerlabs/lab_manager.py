
#!/usr/bin/env python3
"""
Lab Manager - Gestor de Laboratorios Docker
Desarrollado por @descambiado para BOFA
"""

import os
import sys
import subprocess
import yaml
from colorama import Fore, Style, init

init(autoreset=True)

def print_banner():
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════╗
║                      LAB MANAGER                                ║
║                 Gestor de Laboratorios                          ║
╚══════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)

def get_available_labs():
    """Obtiene la lista de laboratorios disponibles"""
    labs_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "labs")
    labs = []
    
    if os.path.exists(labs_dir):
        for item in os.listdir(labs_dir):
            lab_path = os.path.join(labs_dir, item)
            metadata_file = os.path.join(lab_path, "metadata.yaml")
            
            if os.path.isdir(lab_path) and os.path.exists(metadata_file):
                try:
                    with open(metadata_file, 'r') as f:
                        metadata = yaml.safe_load(f)
                    labs.append({
                        'id': item,
                        'name': metadata.get('name', item),
                        'description': metadata.get('description', ''),
                        'category': metadata.get('category', 'unknown'),
                        'difficulty': metadata.get('difficulty', 'unknown')
                    })
                except Exception as e:
                    print(f"{Fore.YELLOW}⚠️  Error leyendo metadata de {item}: {str(e)}{Style.RESET_ALL}")
    
    return labs

def list_labs():
    """Lista todos los laboratorios disponibles"""
    print(f"{Fore.YELLOW}📋 Laboratorios Disponibles{Style.RESET_ALL}")
    print("="*60)
    
    labs = get_available_labs()
    
    if not labs:
        print(f"{Fore.RED}❌ No se encontraron laboratorios{Style.RESET_ALL}")
        return
    
    for i, lab in enumerate(labs, 1):
        print(f"{Fore.GREEN}[{i}] {lab['name']}")
        print(f"    ID: {lab['id']}")
        print(f"    Categoría: {lab['category']}")
        print(f"    Dificultad: {lab['difficulty']}")
        print(f"    Descripción: {lab['description']}")
        print()

def main():
    print_banner()
    
    if len(sys.argv) < 2:
        print(f"{Fore.YELLOW}Uso: python lab_manager.py [list|start|stop|status] [lab_id]{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Comandos disponibles:")
        print(f"  list   - Lista laboratorios disponibles")
        print(f"  start  - Inicia un laboratorio")
        print(f"  stop   - Detiene un laboratorio")
        print(f"  status - Muestra el estado de un laboratorio{Style.RESET_ALL}")
        return
    
    command = sys.argv[1].lower()
    
    if command == "list":
        list_labs()
    elif command in ["start", "stop", "status"] and len(sys.argv) > 2:
        lab_id = sys.argv[2]
        if command == "start":
            start_lab(lab_id)
        elif command == "stop":
            stop_lab(lab_id)
        elif command == "status":
            check_lab_status(lab_id)
    else:
        print(f"{Fore.RED}❌ Comando inválido o faltan argumentos{Style.RESET_ALL}")

def start_lab(lab_id):
    """Inicia un laboratorio específico"""
    labs_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "labs")
    lab_path = os.path.join(labs_dir, lab_id)
    
    if not os.path.exists(lab_path):
        print(f"{Fore.RED}❌ Laboratorio '{lab_id}' no encontrado{Style.RESET_ALL}")
        return
    
    print(f"{Fore.CYAN}🚀 Iniciando laboratorio '{lab_id}'...{Style.RESET_ALL}")
    
    try:
        result = subprocess.run(['docker-compose', 'up', '-d'], 
                              cwd=lab_path, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"{Fore.GREEN}✅ Laboratorio iniciado correctamente{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}❌ Error al iniciar el laboratorio:{Style.RESET_ALL}")
            print(result.stderr)
    except FileNotFoundError:
        print(f"{Fore.RED}❌ Docker Compose no está instalado{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}❌ Error: {str(e)}{Style.RESET_ALL}")

def stop_lab(lab_id):
    """Detiene un laboratorio específico"""
    labs_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "labs")
    lab_path = os.path.join(labs_dir, lab_id)
    
    if not os.path.exists(lab_path):
        print(f"{Fore.RED}❌ Laboratorio '{lab_id}' no encontrado{Style.RESET_ALL}")
        return
    
    print(f"{Fore.YELLOW}🛑 Deteniendo laboratorio '{lab_id}'...{Style.RESET_ALL}")
    
    try:
        result = subprocess.run(['docker-compose', 'down'], 
                              cwd=lab_path, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"{Fore.GREEN}✅ Laboratorio detenido correctamente{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}❌ Error al detener el laboratorio:{Style.RESET_ALL}")
            print(result.stderr)
    except Exception as e:
        print(f"{Fore.RED}❌ Error: {str(e)}{Style.RESET_ALL}")

def check_lab_status(lab_id):
    """Verifica el estado de un laboratorio"""
    labs_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "labs")
    lab_path = os.path.join(labs_dir, lab_id)
    
    if not os.path.exists(lab_path):
        print(f"{Fore.RED}❌ Laboratorio '{lab_id}' no encontrado{Style.RESET_ALL}")
        return
    
    try:
        result = subprocess.run(['docker-compose', 'ps'], 
                              cwd=lab_path, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"{Fore.CYAN}Estado del laboratorio '{lab_id}':{Style.RESET_ALL}")
            print(result.stdout)
        else:
            print(f"{Fore.RED}❌ Error al verificar el estado:{Style.RESET_ALL}")
            print(result.stderr)
    except Exception as e:
        print(f"{Fore.RED}❌ Error: {str(e)}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
