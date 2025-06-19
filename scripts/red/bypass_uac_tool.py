
#!/usr/bin/env python3
"""
UAC Bypass Simulator - BOFA Red Team Module
Simula técnicas de bypass UAC para fines educativos
"""

import os
import sys
import argparse
import json
import subprocess
import winreg
from datetime import datetime

class UACBypassSimulator:
    def __init__(self):
        self.techniques = {
            "fodhelper": {
                "name": "FodHelper Registry Bypass",
                "description": "Utiliza fodhelper.exe para bypass UAC",
                "severity": "HIGH",
                "detection": "Registry monitoring, Process monitoring"
            },
            "sdclt": {
                "name": "SDCLT Control Panel Bypass", 
                "description": "Abusa de sdclt.exe para ejecutar comandos elevados",
                "severity": "HIGH",
                "detection": "Process creation monitoring"
            },
            "computerdefaults": {
                "name": "ComputerDefaults UAC Bypass",
                "description": "Utiliza ComputerDefaults.exe como vector",
                "severity": "MEDIUM",
                "detection": "Registry changes, Process monitoring"
            },
            "eventvwr": {
                "name": "Event Viewer MSC Bypass",
                "description": "Abusa del Event Viewer para elevar privilegios",
                "severity": "HIGH", 
                "detection": "MSC file monitoring, Registry monitoring"
            }
        }
        self.output_dir = "output/uac_bypass"
        
    def create_output_dir(self):
        os.makedirs(self.output_dir, exist_ok=True)
        
    def check_uac_status(self):
        """Verifica estado actual de UAC"""
        try:
            if os.name != 'nt':
                return {"enabled": False, "reason": "No Windows system"}
                
            # Verificar registro UAC
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                               r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")
            
            enable_lua, _ = winreg.QueryValueEx(key, "EnableLUA")
            consent_prompt, _ = winreg.QueryValueEx(key, "ConsentPromptBehaviorAdmin")
            
            winreg.CloseKey(key)
            
            return {
                "enabled": bool(enable_lua),
                "consent_prompt": consent_prompt,
                "bypass_possible": enable_lua and consent_prompt < 2
            }
            
        except Exception as e:
            return {"enabled": "unknown", "error": str(e)}
    
    def simulate_fodhelper_bypass(self):
        """Simula bypass usando fodhelper.exe"""
        print("[+] Simulando FodHelper UAC Bypass...")
        
        steps = [
            "1. Crear clave de registro: HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command",
            "2. Establecer valor por defecto: cmd.exe /c calc.exe",
            "3. Crear valor DelegateExecute (vacío)",
            "4. Ejecutar: fodhelper.exe",
            "5. Limpiar registro tras ejecución"
        ]
        
        # Simulación educativa - NO ejecuta realmente
        simulation_log = {
            "technique": "fodhelper",
            "timestamp": datetime.now().isoformat(),
            "steps": steps,
            "registry_keys": [
                "HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command",
                "HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command\\DelegateExecute"
            ],
            "detection_methods": [
                "Monitor registry changes in HKCU\\Software\\Classes",
                "Monitor fodhelper.exe process creation",
                "Monitor unusual child processes of fodhelper.exe"
            ],
            "mitigation": [
                "Enable UAC at highest level",
                "Use Application Control policies", 
                "Monitor registry modifications"
            ]
        }
        
        return simulation_log
    
    def simulate_sdclt_bypass(self):
        """Simula bypass usando sdclt.exe"""
        print("[+] Simulando SDCLT UAC Bypass...")
        
        steps = [
            "1. Crear clave: HKCU\\Software\\Classes\\exefile\\shell\\runas\\command",
            "2. Establecer valor: cmd.exe /c calc.exe",
            "3. Ejecutar: sdclt.exe /KickOffElev",
            "4. Limpiar registro"
        ]
        
        simulation_log = {
            "technique": "sdclt",
            "timestamp": datetime.now().isoformat(),
            "steps": steps,
            "registry_keys": [
                "HKCU\\Software\\Classes\\exefile\\shell\\runas\\command"
            ],
            "detection_methods": [
                "Monitor sdclt.exe with /KickOffElev parameter",
                "Monitor registry changes in exefile associations",
                "Process parent-child relationship monitoring"
            ],
            "mitigation": [
                "Restrict sdclt.exe execution",
                "Monitor file association changes",
                "Enable advanced UAC settings"
            ]
        }
        
        return simulation_log
    
    def simulate_eventvwr_bypass(self):
        """Simula bypass usando Event Viewer"""
        print("[+] Simulando EventVwr MSC Bypass...")
        
        steps = [
            "1. Crear clave: HKCU\\Software\\Classes\\mscfile\\shell\\open\\command",
            "2. Establecer valor por defecto: cmd.exe /c calc.exe",
            "3. Ejecutar: eventvwr.exe",
            "4. Restaurar configuración original"
        ]
        
        simulation_log = {
            "technique": "eventvwr",
            "timestamp": datetime.now().isoformat(),
            "steps": steps,
            "registry_keys": [
                "HKCU\\Software\\Classes\\mscfile\\shell\\open\\command"
            ],
            "detection_methods": [
                "Monitor mscfile association changes",
                "Monitor eventvwr.exe process creation",
                "Registry monitoring for unusual mscfile handlers"
            ],
            "mitigation": [
                "Restrict eventvwr.exe access",
                "Monitor file association modifications",
                "Implement application whitelisting"
            ]
        }
        
        return simulation_log
    
    def generate_bypass_report(self, simulations):
        """Genera reporte completo de simulaciones"""
        uac_status = self.check_uac_status()
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "system_info": {
                "os": os.name,
                "platform": sys.platform,
                "uac_status": uac_status
            },
            "simulations": simulations,
            "summary": {
                "total_techniques": len(simulations),
                "high_risk": len([s for s in simulations if self.techniques.get(s["technique"], {}).get("severity") == "HIGH"]),
                "detection_coverage": len(set().union(*[s.get("detection_methods", []) for s in simulations]))
            },
            "recommendations": [
                "Mantener UAC habilitado en nivel máximo",
                "Implementar monitoreo de registro en tiempo real",
                "Usar Application Control (AppLocker/WDAC)",
                "Monitorear procesos con privilegios elevados",
                "Implementar behavioral analysis para detección"
            ]
        }
        
        # Guardar reporte
        report_file = f"{self.output_dir}/uac_bypass_simulation.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Reporte guardado en: {report_file}")
        return report_file

def main():
    parser = argparse.ArgumentParser(description="UAC Bypass Simulator (Educational)")
    parser.add_argument("-t", "--technique", choices=["fodhelper", "sdclt", "eventvwr", "all"],
                       default="all", help="Técnica a simular")
    parser.add_argument("-o", "--output", help="Directorio de salida")
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("🔴 BOFA UAC Bypass Simulator")
    print("⚠️  SOLO SIMULACIÓN - FINES EDUCATIVOS")
    print("=" * 60)
    
    simulator = UACBypassSimulator()
    
    if args.output:
        simulator.output_dir = args.output
    
    simulator.create_output_dir()
    
    simulations = []
    
    try:
        if args.technique == "all" or args.technique == "fodhelper":
            simulations.append(simulator.simulate_fodhelper_bypass())
            
        if args.technique == "all" or args.technique == "sdclt":
            simulations.append(simulator.simulate_sdclt_bypass())
            
        if args.technique == "all" or args.technique == "eventvwr":
            simulations.append(simulator.simulate_eventvwr_bypass())
        
        # Generar reporte
        simulator.generate_bypass_report(simulations)
        
        print(f"\n[✓] Simulación completada")
        print(f"[✓] {len(simulations)} técnicas simuladas")
        print("[!] RECUERDA: Esto es solo educativo - implementa las mitigaciones sugeridas")
        
    except Exception as e:
        print(f"[!] Error durante simulación: {e}")

if __name__ == "__main__":
    main()
