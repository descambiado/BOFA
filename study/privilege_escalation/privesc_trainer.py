
#!/usr/bin/env python3
"""
Privilege Escalation Trainer
Interactive training environment for privilege escalation techniques
Desarrollado por @descambiado para BOFA
"""

import os
import sys
import subprocess
import platform
from datetime import datetime

def print_banner():
    banner = """
╔══════════════════════════════════════════════════════════════════╗
║                 PRIVILEGE ESCALATION TRAINER                    ║
║              Interactive Learning Environment                    ║
╚══════════════════════════════════════════════════════════════════╝
"""
    print(banner)

class PrivEscTrainer:
    def __init__(self):
        self.system = platform.system().lower()
        self.exercises = {
            "1": {"name": "SUID Binary Detection", "function": self.exercise_suid_detection},
            "2": {"name": "Sudo Configuration Analysis", "function": self.exercise_sudo_analysis},
            "3": {"name": "Cron Job Enumeration", "function": self.exercise_cron_enumeration},
            "4": {"name": "Kernel Version Analysis", "function": self.exercise_kernel_analysis},
            "5": {"name": "File Permission Audit", "function": self.exercise_file_permissions}
        }
        
    def show_menu(self):
        """Muestra el menú principal"""
        print("\n" + "="*60)
        print("            PRIVILEGE ESCALATION EXERCISES")
        print("="*60)
        
        for key, exercise in self.exercises.items():
            print(f"[{key}] {exercise['name']}")
        
        print("[0] Salir")
        print("\nSelecciona un ejercicio:")
    
    def exercise_suid_detection(self):
        """Ejercicio: Detección de binarios SUID"""
        print("\n🔍 EJERCICIO: Detección de binarios SUID/SGID")
        print("="*50)
        
        print("\n📚 Teoría:")
        print("Los binarios SUID (Set User ID) se ejecutan con los privilegios del propietario,")
        print("no del usuario que los ejecuta. Esto puede ser explotado para escalada de privilegios.")
        
        print("\n🧪 Práctica:")
        print("Ejecutando búsqueda de binarios SUID...")
        
        try:
            # Buscar binarios SUID (limitado para seguridad)
            result = subprocess.run(['find', '/usr/bin', '-perm', '-4000', '-type', 'f'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0 and result.stdout:
                suid_binaries = result.stdout.strip().split('\n')
                print(f"\n✅ Encontrados {len(suid_binaries)} binarios SUID en /usr/bin:")
                for binary in suid_binaries[:10]:  # Mostrar primeros 10
                    print(f"  - {binary}")
                
                print("\n🎯 Pregunta: ¿Cuál de estos binarios podría ser peligroso?")
                print("Pista: Busca editores de texto, intérpretes o herramientas de sistema")
                
            else:
                print("❌ No se pudieron encontrar binarios SUID o acceso denegado")
                
        except Exception as e:
            print(f"❌ Error en la búsqueda: {str(e)}")
        
        print("\n📖 Comandos útiles:")
        print("  find / -perm -4000 -type f 2>/dev/null    # Buscar SUID")
        print("  find / -perm -2000 -type f 2>/dev/null    # Buscar SGID")
        print("  ls -la /usr/bin/sudo                       # Verificar permisos")
        
        self.wait_for_continue()
    
    def exercise_sudo_analysis(self):
        """Ejercicio: Análisis de configuración sudo"""
        print("\n🔐 EJERCICIO: Análisis de configuración sudo")
        print("="*50)
        
        print("\n📚 Teoría:")
        print("Una configuración incorrecta de sudo puede permitir escalada de privilegios.")
        print("Comandos sin contraseña o con comodines pueden ser explotados.")
        
        print("\n🧪 Práctica:")
        print("Verificando configuración sudo del usuario actual...")
        
        try:
            result = subprocess.run(['sudo', '-l'], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                print("\n✅ Configuración sudo:")
                sudo_output = result.stdout[:500]  # Limitar output
                print(sudo_output)
                
                # Analizar configuración
                if "NOPASSWD" in sudo_output:
                    print("\n⚠️  HALLAZGO: Comandos sudo sin contraseña detectados!")
                    print("Esto podría permitir escalada de privilegios.")
                
                if "*" in sudo_output or "ALL" in sudo_output:
                    print("\n⚠️  HALLAZGO: Permisos sudo amplios detectados!")
                    print("Revisar si se pueden explotar comodines.")
                    
            else:
                print("❌ No se pueden verificar privilegios sudo")
                print("Esto es normal si no tienes permisos sudo")
                
        except Exception as e:
            print(f"❌ Error verificando sudo: {str(e)}")
        
        print("\n📖 Comandos de análisis:")
        print("  sudo -l                    # Listar permisos sudo")
        print("  cat /etc/sudoers           # Ver configuración (si tienes acceso)")
        print("  sudo -u#-1 /bin/bash       # Exploit CVE-2019-14287")
        
        print("\n🎯 Pregunta: ¿Qué buscarías en la configuración sudo para escalada?")
        print("Respuesta: NOPASSWD, comodines (*), comandos peligrosos como vim, less, etc.")
        
        self.wait_for_continue()
    
    def exercise_cron_enumeration(self):
        """Ejercicio: Enumeración de cron jobs"""
        print("\n⏰ EJERCICIO: Enumeración de Cron Jobs")
        print("="*50)
        
        print("\n📚 Teoría:")
        print("Los cron jobs ejecutan scripts/comandos automáticamente.")
        print("Si un script es modificable, puede usarse para escalada de privilegios.")
        
        print("\n🧪 Práctica:")
        print("Buscando cron jobs del sistema...")
        
        cron_locations = [
            "/etc/crontab",
            "/etc/cron.d/",
            "/var/spool/cron/crontabs/"
        ]
        
        for location in cron_locations:
            print(f"\n🔍 Verificando: {location}")
            try:
                if os.path.isfile(location):
                    result = subprocess.run(['cat', location], capture_output=True, text=True)
                    if result.returncode == 0 and result.stdout.strip():
                        print(f"✅ Contenido encontrado:")
                        print(result.stdout[:300])  # Primeros 300 caracteres
                    else:
                        print("❌ Acceso denegado o archivo vacío")
                elif os.path.isdir(location):
                    result = subprocess.run(['ls', '-la', location], capture_output=True, text=True)
                    if result.returncode == 0:
                        print(f"✅ Archivos en directorio:")
                        print(result.stdout[:300])
                    else:
                        print("❌ Acceso denegado al directorio")
                else:
                    print("❌ Ubicación no existe")
            except Exception as e:
                print(f"❌ Error: {str(e)}")
        
        print("\n📖 Comandos de enumeración:")
        print("  cat /etc/crontab                    # Cron del sistema")
        print("  ls -la /etc/cron.*                  # Directorios cron")
        print("  crontab -l                          # Cron del usuario")
        print("  ls -la /var/spool/cron/crontabs/    # Crontabs de usuarios")
        
        print("\n🎯 ¿Qué buscar en cron jobs?")
        print("- Scripts con permisos de escritura")
        print("- Paths relativos sin rutas completas")
        print("- Scripts que se ejecutan como root")
        
        self.wait_for_continue()
    
    def exercise_kernel_analysis(self):
        """Ejercicio: Análisis de versión del kernel"""
        print("\n🐧 EJERCICIO: Análisis de versión del kernel")
        print("="*50)
        
        print("\n📚 Teoría:")
        print("Los kernels antiguos pueden tener vulnerabilidades conocidas.")
        print("Los exploits de kernel pueden dar acceso root directo.")
        
        print("\n🧪 Práctica:")
        print("Recopilando información del kernel...")
        
        kernel_commands = [
            ("uname -a", "Información completa del sistema"),
            ("cat /proc/version", "Versión detallada del kernel"),
            ("cat /etc/os-release", "Información del SO"),
            ("lsb_release -a", "Información de distribución")
        ]
        
        kernel_info = {}
        
        for cmd, description in kernel_commands:
            print(f"\n🔍 {description}:")
            try:
                result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=5)
                if result.returncode == 0 and result.stdout.strip():
                    output = result.stdout.strip()
                    print(f"✅ {output}")
                    kernel_info[cmd] = output
                else:
                    print("❌ Comando no disponible o sin output")
            except Exception as e:
                print(f"❌ Error: {str(e)}")
        
        # Análisis básico
        if "uname -a" in kernel_info:
            uname_output = kernel_info["uname -a"]
            if "Ubuntu" in uname_output and "4." in uname_output:
                print("\n⚠️  HALLAZGO: Kernel Ubuntu 4.x detectado")
                print("Buscar exploits: DirtyCow, privilege escalation vulns")
            elif "3." in uname_output:
                print("\n⚠️  HALLAZGO: Kernel 3.x muy antiguo")
                print("Alto riesgo de vulnerabilidades conocidas")
        
        print("\n📖 Recursos para exploits:")
        print("  searchsploit kernel <version>       # Buscar exploits")
        print("  exploit-db.com                      # Base de datos online")
        print("  linux-exploit-suggester             # Tool automatizada")
        
        print("\n🎯 Pregunta: ¿Cómo verificarías si hay exploits disponibles?")
        print("Respuesta: searchsploit, CVE databases, linux-exploit-suggester")
        
        self.wait_for_continue()
    
    def exercise_file_permissions(self):
        """Ejercicio: Auditoría de permisos de archivos"""
        print("\n📁 EJERCICIO: Auditoría de permisos de archivos")
        print("="*50)
        
        print("\n📚 Teoría:")
        print("Archivos con permisos incorrectos pueden permitir escalada.")
        print("Buscar archivos escribibles en ubicaciones sensibles.")
        
        print("\n🧪 Práctica:")
        print("Buscando archivos con permisos interesantes...")
        
        permission_checks = [
            ("find /etc -writable -type f 2>/dev/null", "Archivos escribibles en /etc"),
            ("find /usr/bin -writable -type f 2>/dev/null", "Binarios escribibles"),
            ("find /home -name '*.sh' -perm -002 2>/dev/null", "Scripts escribibles por otros")
        ]
        
        for cmd, description in permission_checks:
            print(f"\n🔍 {description}:")
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                if result.returncode == 0 and result.stdout.strip():
                    files = result.stdout.strip().split('\n')
                    print(f"✅ Encontrados {len(files)} archivos:")
                    for file in files[:5]:  # Mostrar primeros 5
                        print(f"  - {file}")
                    if len(files) > 5:
                        print(f"  ... y {len(files) - 5} más")
                else:
                    print("✅ No se encontraron archivos (es bueno para seguridad)")
            except Exception as e:
                print(f"❌ Error: {str(e)}")
        
        # Verificar /etc/passwd
        print(f"\n🔍 Verificando permisos de /etc/passwd:")
        try:
            result = subprocess.run(['ls', '-la', '/etc/passwd'], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"✅ {result.stdout.strip()}")
                if "-rw-rw-rw-" in result.stdout or "-rw-r--rw-" in result.stdout:
                    print("⚠️  CRÍTICO: /etc/passwd es escribible!")
                    print("Esto permite agregar usuarios root!")
            else:
                print("❌ No se puede verificar /etc/passwd")
        except Exception as e:
            print(f"❌ Error: {str(e)}")
        
        print("\n📖 Comandos útiles:")
        print("  find / -writable -type f 2>/dev/null      # Archivos escribibles")
        print("  find / -perm -002 -type f 2>/dev/null     # World-writable")
        print("  ls -la /etc/passwd                         # Permisos críticos")
        print("  find /home -name '*.ssh' -type d           # Directorios SSH")
        
        self.wait_for_continue()
    
    def wait_for_continue(self):
        """Espera confirmación del usuario"""
        input("\n[Presiona Enter para continuar...]")
    
    def run(self):
        """Ejecuta el trainer"""
        print_banner()
        print("🎓 Bienvenido al Privilege Escalation Trainer")
        print("Este entorno te ayudará a aprender técnicas de escalada de privilegios")
        
        while True:
            self.show_menu()
            choice = input().strip()
            
            if choice == "0":
                print("\n👋 ¡Gracias por usar el Privilege Escalation Trainer!")
                break
            elif choice in self.exercises:
                self.exercises[choice]["function"]()
            else:
                print("❌ Opción inválida. Intenta de nuevo.")

def main():
    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help']:
        print("Privilege Escalation Trainer")
        print("Entorno interactivo para aprender escalada de privilegios")
        print("\nCaracterísticas:")
        print("- Detección de binarios SUID/SGID")
        print("- Análisis de configuración sudo")
        print("- Enumeración de cron jobs")
        print("- Análisis de kernel y exploits")
        print("- Auditoría de permisos de archivos")
        print("\nUso: python3 privesc_trainer.py")
        return
    
    trainer = PrivEscTrainer()
    trainer.run()

if __name__ == "__main__":
    main()
