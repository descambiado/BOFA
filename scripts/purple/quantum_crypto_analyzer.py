
#!/usr/bin/env python3
"""
BOFA Quantum-Safe Crypto Analyzer v1.0
Evalúa la resistencia criptográfica ante computación cuántica
Author: @descambiado
"""

import hashlib
import re
import json
import ssl
import socket
from datetime import datetime, timedelta
import subprocess
from typing import Dict, List, Tuple, Any
import base64

class QuantumCryptoAnalyzer:
    def __init__(self):
        self.quantum_vulnerable = {
            "rsa": {"max_safe_bits": 2048, "post_quantum": False, "risk": "critical"},
            "ecdsa": {"max_safe_bits": 256, "post_quantum": False, "risk": "critical"},
            "dsa": {"max_safe_bits": 2048, "post_quantum": False, "risk": "critical"},
            "dh": {"max_safe_bits": 2048, "post_quantum": False, "risk": "critical"},
            "md5": {"max_safe_bits": 0, "post_quantum": False, "risk": "critical"},
            "sha1": {"max_safe_bits": 0, "post_quantum": False, "risk": "high"},
            "3des": {"max_safe_bits": 0, "post_quantum": False, "risk": "medium"}
        }
        
        self.quantum_safe = {
            "kyber": {"key_sizes": [512, 768, 1024], "type": "kem", "risk": "low"},
            "dilithium": {"key_sizes": [2, 3, 5], "type": "signature", "risk": "low"},
            "falcon": {"key_sizes": [512, 1024], "type": "signature", "risk": "low"},
            "sphincs": {"key_sizes": [128, 192, 256], "type": "signature", "risk": "low"},
            "aes": {"key_sizes": [128, 192, 256], "type": "symmetric", "risk": "low"},
            "chacha20": {"key_sizes": [256], "type": "symmetric", "risk": "low"},
            "sha3": {"key_sizes": [224, 256, 384, 512], "type": "hash", "risk": "low"}
        }
        
        self.migration_paths = {
            "rsa": ["dilithium", "falcon", "sphincs"],
            "ecdsa": ["dilithium", "falcon"],
            "dh": ["kyber"],
            "md5": ["sha3-256", "sha3-512"],
            "sha1": ["sha3-256", "sha3-512"],
            "3des": ["aes-256"]
        }
    
    def analyze_certificate(self, cert_data: bytes) -> Dict:
        """Analiza certificado SSL/TLS"""
        try:
            import cryptography.x509 as x509
            from cryptography.hazmat.backends import default_backend
            
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            
            # Extraer información del certificado
            public_key = cert.public_key()
            signature_algorithm = cert.signature_algorithm_oid._name
            
            analysis = {
                "subject": str(cert.subject),
                "issuer": str(cert.issuer),
                "valid_from": cert.not_valid_before.isoformat(),
                "valid_to": cert.not_valid_after.isoformat(),
                "signature_algorithm": signature_algorithm,
                "quantum_vulnerable": True,
                "risk_level": "high",
                "recommendations": []
            }
            
            # Analizar clave pública
            if hasattr(public_key, 'key_size'):
                key_size = public_key.key_size
                key_type = type(public_key).__name__.lower()
                
                analysis.update({
                    "key_type": key_type,
                    "key_size": key_size,
                    "quantum_safe": False
                })
                
                # Verificar vulnerabilidad cuántica
                if 'rsa' in key_type and key_size < 3072:
                    analysis["risk_level"] = "critical"
                    analysis["recommendations"].append("Migrar a RSA-4096 o algoritmo post-cuántico")
                elif 'ec' in key_type:
                    analysis["risk_level"] = "critical"
                    analysis["recommendations"].append("Migrar a Dilithium o Falcon")
            
            return analysis
            
        except Exception as e:
            return {"error": f"Error analizando certificado: {str(e)}"}
    
    def scan_network_crypto(self, target: str, port: int = 443) -> Dict:
        """Escanea protocolos criptográficos en red"""
        results = {
            "target": target,
            "port": port,
            "protocols": [],
            "ciphers": [],
            "quantum_risk": "unknown",
            "recommendations": []
        }
        
        try:
            # Simular escaneo SSL/TLS
            context = ssl.create_default_context()
            with socket.create_connection((target, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    protocol = ssock.version()
                    cipher = ssock.cipher()
                    
                    results["protocols"].append(protocol)
                    if cipher:
                        results["ciphers"].append({
                            "cipher": cipher[0],
                            "version": cipher[1],
                            "bits": cipher[2]
                        })
                    
                    # Obtener certificado
                    cert_der = ssock.getpeercert_raw()
                    cert_pem = ssl.DER_cert_to_PEM_cert(cert_der)
                    
                    cert_analysis = self.analyze_certificate(cert_pem.encode())
                    results["certificate"] = cert_analysis
                    
                    # Evaluar riesgo cuántico
                    if any("rsa" in c["cipher"].lower() or "ecdsa" in c["cipher"].lower() 
                           for c in results["ciphers"]):
                        results["quantum_risk"] = "high"
                        results["recommendations"].append("Actualizar a cipher suites post-cuánticos")
        
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    def analyze_code_crypto(self, code: str, language: str = "python") -> Dict:
        """Analiza uso criptográfico en código"""
        patterns = {
            "python": {
                "rsa": r"RSA\.|rsa\.|\.RSA|Crypto\.PublicKey\.RSA",
                "ecdsa": r"ECDSA|ecdsa|ECC\.|ecc\.",
                "md5": r"hashlib\.md5|MD5|md5",
                "sha1": r"hashlib\.sha1|SHA1|sha1",
                "des": r"DES|des|3DES|3des",
                "aes": r"AES|aes|Crypto\.Cipher\.AES"
            },
            "java": {
                "rsa": r"RSA|KeyPairGenerator.*RSA",
                "ecdsa": r"ECDSA|EC|EllipticCurve",
                "md5": r"MD5|MessageDigest.*MD5",
                "sha1": r"SHA-1|SHA1|MessageDigest.*SHA-1"
            }
        }
        
        findings = []
        vulnerabilities = []
        recommendations = []
        
        for crypto_type, pattern in patterns.get(language, {}).items():
            matches = re.findall(pattern, code, re.IGNORECASE)
            if matches:
                findings.append({
                    "type": crypto_type,
                    "occurrences": len(matches),
                    "locations": matches[:5]  # Primeras 5 ocurrencias
                })
                
                # Verificar vulnerabilidad cuántica
                if crypto_type in self.quantum_vulnerable:
                    vulnerabilities.append({
                        "algorithm": crypto_type,
                        "risk": self.quantum_vulnerable[crypto_type]["risk"],
                        "post_quantum": False,
                        "migration_options": self.migration_paths.get(crypto_type, [])
                    })
                    
                    recommendations.append(
                        f"Migrar {crypto_type.upper()} a: {', '.join(self.migration_paths.get(crypto_type, ['algoritmo post-cuántico']))}"
                    )
        
        return {
            "findings": findings,
            "vulnerabilities": vulnerabilities,
            "recommendations": recommendations,
            "quantum_safe_score": self.calculate_quantum_safety_score(vulnerabilities),
            "migration_plan": self.generate_migration_plan(vulnerabilities)
        }
    
    def calculate_quantum_safety_score(self, vulnerabilities: List[Dict]) -> float:
        """Calcula score de seguridad cuántica (0-100)"""
        if not vulnerabilities:
            return 100.0
        
        risk_weights = {"critical": 0, "high": 25, "medium": 50, "low": 75}
        total_weight = sum(risk_weights.get(vuln["risk"], 0) for vuln in vulnerabilities)
        
        return max(0, 100 - (len(vulnerabilities) * 10) + (total_weight / len(vulnerabilities)))
    
    def generate_migration_plan(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Genera plan de migración post-cuántico"""
        plan = []
        
        priority_order = {"critical": 1, "high": 2, "medium": 3, "low": 4}
        sorted_vulns = sorted(vulnerabilities, key=lambda x: priority_order.get(x["risk"], 5))
        
        for i, vuln in enumerate(sorted_vulns):
            phase = f"Fase {i + 1}"
            algorithm = vuln["algorithm"]
            
            plan.append({
                "phase": phase,
                "priority": vuln["risk"],
                "current_algorithm": algorithm,
                "recommended_alternatives": self.migration_paths.get(algorithm, []),
                "estimated_effort": self.estimate_migration_effort(algorithm),
                "timeline": f"{(i + 1) * 30} días",
                "considerations": self.get_migration_considerations(algorithm)
            })
        
        return plan
    
    def estimate_migration_effort(self, algorithm: str) -> str:
        """Estima esfuerzo de migración"""
        effort_map = {
            "rsa": "Alto - Requiere cambios en infraestructura PKI",
            "ecdsa": "Medio - Actualización de certificados y claves",
            "md5": "Bajo - Cambio directo de función hash",
            "sha1": "Bajo - Cambio directo de función hash",
            "des": "Medio - Actualización de cifrado simétrico",
            "3des": "Medio - Actualización de cifrado simétrico"
        }
        return effort_map.get(algorithm, "Medio")
    
    def get_migration_considerations(self, algorithm: str) -> List[str]:
        """Obtiene consideraciones para migración"""
        considerations = {
            "rsa": [
                "Verificar compatibilidad con sistemas legados",
                "Actualizar herramientas de gestión de certificados",
                "Coordinar con autoridades certificadoras"
            ],
            "ecdsa": [
                "Evaluar soporte de hardware para nuevos algoritmos",
                "Actualizar bibliotecas criptográficas",
                "Probar interoperabilidad"
            ],
            "md5": [
                "Verificar que no se use para integridad crítica",
                "Actualizar funciones de hash en código"
            ],
            "sha1": [
                "Migrar certificados que usen SHA-1",
                "Actualizar configuraciones de firma digital"
            ]
        }
        return considerations.get(algorithm, ["Evaluar impacto en sistemas existentes"])
    
    def generate_report(self, analyses: List[Dict]) -> Dict:
        """Genera reporte completo"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_analyses": len(analyses),
                "quantum_vulnerable": 0,
                "quantum_safe": 0,
                "critical_findings": 0,
                "avg_safety_score": 0
            },
            "findings": analyses,
            "recommendations": [],
            "migration_timeline": {},
            "compliance_status": {}
        }
        
        # Calcular métricas
        safety_scores = []
        for analysis in analyses:
            if "quantum_safe_score" in analysis:
                score = analysis["quantum_safe_score"]
                safety_scores.append(score)
                
                if score < 50:
                    report["summary"]["quantum_vulnerable"] += 1
                else:
                    report["summary"]["quantum_safe"] += 1
                
                if score < 25:
                    report["summary"]["critical_findings"] += 1
        
        if safety_scores:
            report["summary"]["avg_safety_score"] = sum(safety_scores) / len(safety_scores)
        
        # Generar recomendaciones generales
        if report["summary"]["quantum_vulnerable"] > 0:
            report["recommendations"].extend([
                "🚨 Implementar plan de migración post-cuántica urgente",
                "📋 Realizar auditoría completa de infraestructura criptográfica",
                "🔄 Establecer cronograma de actualización de algoritmos",
                "📚 Capacitar al equipo en criptografía post-cuántica"
            ])
        
        return report

def main():
    """Función principal"""
    analyzer = QuantumCryptoAnalyzer()
    
    print("🔮 BOFA Quantum-Safe Crypto Analyzer v1.0")
    print("=" * 50)
    
    analyses = []
    
    # Ejemplo 1: Análisis de código Python
    sample_code = """
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import ecdsa

# Código vulnerable
key = RSA.generate(2048)
hash_obj = hashlib.md5()
signature = ecdsa.SigningKey.generate()

# Código más seguro
aes_cipher = AES.new(key, AES.MODE_GCM)
sha3_hash = hashlib.sha3_256()
"""
    
    print("🔍 Analizando código Python...")
    code_analysis = analyzer.analyze_code_crypto(sample_code, "python")
    analyses.append(code_analysis)
    
    print(f"Vulnerabilidades encontradas: {len(code_analysis['vulnerabilities'])}")
    print(f"Score de seguridad cuántica: {code_analysis['quantum_safe_score']:.1f}/100")
    
    # Ejemplo 2: Análisis de certificado (simulado)
    print("\n🔍 Analizando configuración de red...")
    network_analysis = analyzer.scan_network_crypto("google.com", 443)
    if "error" not in network_analysis:
        analyses.append(network_analysis)
        print(f"Protocolos encontrados: {network_analysis['protocols']}")
        print(f"Riesgo cuántico: {network_analysis['quantum_risk']}")
    
    # Generar reporte final
    print("\n📊 Generando reporte completo...")
    report = analyzer.generate_report(analyses)
    
    print("\n" + "=" * 50)
    print("📋 RESUMEN EJECUTIVO")
    print("=" * 50)
    
    summary = report["summary"]
    print(f"Análisis realizados: {summary['total_analyses']}")
    print(f"Sistemas vulnerables: {summary['quantum_vulnerable']}")
    print(f"Sistemas seguros: {summary['quantum_safe']}")
    print(f"Hallazgos críticos: {summary['critical_findings']}")
    print(f"Score promedio: {summary['avg_safety_score']:.1f}/100")
    
    print("\n🚨 VULNERABILIDADES CRÍTICAS")
    for analysis in analyses:
        if "vulnerabilities" in analysis:
            for vuln in analysis["vulnerabilities"]:
                if vuln["risk"] in ["critical", "high"]:
                    print(f"- {vuln['algorithm'].upper()}: {vuln['risk']} risk")
    
    print("\n📋 PLAN DE MIGRACIÓN")
    for analysis in analyses:
        if "migration_plan" in analysis:
            for phase in analysis["migration_plan"][:3]:  # Primeras 3 fases
                print(f"{phase['phase']}: {phase['current_algorithm']} → {', '.join(phase['recommended_alternatives'])}")
    
    print("\n💡 RECOMENDACIONES PRINCIPALES")
    for i, rec in enumerate(report["recommendations"], 1):
        print(f"{i}. {rec}")
    
    # Exportar reporte
    output_file = f"quantum_crypto_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    print(f"\n✅ Reporte exportado a: {output_file}")
    print("🔮 Análisis criptográfico cuántico completado!")

if __name__ == "__main__":
    main()
