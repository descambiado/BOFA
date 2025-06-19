
#!/usr/bin/env python3
"""
BOFA Threat Emulator - Simula comportamiento de amenazas reales de forma ética
Autor: @descambiado
Versión: 1.0
"""

import time
import random
import json
import argparse
from datetime import datetime

class ThreatEmulator:
    def __init__(self):
        self.threats = {
            "apt": {
                "name": "APT Simulation",
                "behaviors": ["lateral_movement", "data_exfil", "persistence"],
                "duration": 300
            },
            "ransomware": {
                "name": "Ransomware Simulation", 
                "behaviors": ["file_encryption_sim", "network_discovery", "backup_deletion_sim"],
                "duration": 180
            },
            "insider": {
                "name": "Insider Threat Simulation",
                "behaviors": ["data_access", "credential_abuse", "policy_violation"],
                "duration": 240
            }
        }
    
    def simulate_apt(self):
        print(f"[{datetime.now()}] 🎭 Iniciando simulación APT...")
        behaviors = [
            "Reconocimiento inicial de red",
            "Movimiento lateral simulado",
            "Establecimiento de persistencia",
            "Exfiltración de datos simulada"
        ]
        
        for behavior in behaviors:
            print(f"[{datetime.now()}] 📡 {behavior}")
            time.sleep(random.uniform(5, 15))
        
        print(f"[{datetime.now()}] ✅ Simulación APT completada")
    
    def simulate_ransomware(self):
        print(f"[{datetime.now()}] 🔒 Iniciando simulación Ransomware...")
        behaviors = [
            "Descubrimiento de red y recursos",
            "Simulación de cifrado de archivos (NO REAL)",
            "Simulación de eliminación de backups",
            "Despliegue de nota de rescate simulada"
        ]
        
        for behavior in behaviors:
            print(f"[{datetime.now()}] 🚨 {behavior}")
            time.sleep(random.uniform(3, 10))
        
        print(f"[{datetime.now()}] ✅ Simulación Ransomware completada")
    
    def simulate_insider(self):
        print(f"[{datetime.now()}] 👤 Iniciando simulación Insider Threat...")
        behaviors = [
            "Acceso a datos sensibles simulado",
            "Uso indebido de credenciales",
            "Violación de políticas de seguridad",
            "Transferencia no autorizada de datos"
        ]
        
        for behavior in behaviors:
            print(f"[{datetime.now()}] ⚠️ {behavior}")
            time.sleep(random.uniform(4, 12))
        
        print(f"[{datetime.now()}] ✅ Simulación Insider Threat completada")

def main():
    parser = argparse.ArgumentParser(description="BOFA Threat Emulator")
    parser.add_argument("-t", "--threat", choices=["apt", "ransomware", "insider", "all"], 
                       default="apt", help="Tipo de amenaza a simular")
    parser.add_argument("-o", "--output", help="Archivo de salida para logs")
    
    args = parser.parse_args()
    
    print("🎭 BOFA Threat Emulator v1.0")
    print("⚠️ SOLO PARA FINES EDUCATIVOS Y ENTORNOS CONTROLADOS")
    print("=" * 60)
    
    emulator = ThreatEmulator()
    
    if args.threat == "apt":
        emulator.simulate_apt()
    elif args.threat == "ransomware":
        emulator.simulate_ransomware()
    elif args.threat == "insider":
        emulator.simulate_insider()
    elif args.threat == "all":
        emulator.simulate_apt()
        time.sleep(5)
        emulator.simulate_ransomware()
        time.sleep(5)
        emulator.simulate_insider()

if __name__ == "__main__":
    main()
