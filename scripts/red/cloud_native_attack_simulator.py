
#!/usr/bin/env python3
"""
BOFA Cloud Native Attack Simulator v1.0
Simula ataques a contenedores, K8s y serverless
Author: @descambiado
"""

import json
import subprocess
import requests
import time
import os
from datetime import datetime
from typing import Dict, List, Any

class CloudNativeAttackSimulator:
    def __init__(self):
        self.attack_scenarios = {
            "container_escape": self.simulate_container_escape,
            "privilege_escalation": self.simulate_privilege_escalation,
            "lateral_movement": self.simulate_lateral_movement,
            "data_extraction": self.simulate_data_extraction,
            "resource_hijacking": self.simulate_resource_hijacking
        }
        
        self.kubernetes_attacks = [
            "exposed_dashboard",
            "weak_rbac",
            "privileged_containers",
            "hostpath_mounts",
            "service_token_abuse"
        ]
    
    def check_docker_environment(self) -> Dict:
        """Verifica entorno Docker"""
        result = {
            "docker_available": False,
            "privileged_mode": False,
            "host_mounts": [],
            "capabilities": [],
            "vulnerabilities": []
        }
        
        try:
            # Verificar si Docker está disponible
            subprocess.run(["docker", "--version"], capture_output=True, check=True)
            result["docker_available"] = True
            
            # Verificar privilegios actuales
            if os.path.exists("/proc/1/cgroup"):
                with open("/proc/1/cgroup", "r") as f:
                    content = f.read()
                    if "docker" in content:
                        result["in_container"] = True
            
            # Simular verificación de capabilities
            result["capabilities"] = ["CAP_SYS_ADMIN", "CAP_NET_ADMIN"]
            
            # Verificar montajes sospechosos
            if os.path.exists("/host"):
                result["host_mounts"].append("/host")
                result["vulnerabilities"].append("Host filesystem mounted")
            
            if os.path.exists("/var/run/docker.sock"):
                result["vulnerabilities"].append("Docker socket exposed")
                
        except subprocess.CalledProcessError:
            pass
        
        return result
    
    def check_kubernetes_environment(self) -> Dict:
        """Verifica entorno Kubernetes"""
        result = {
            "kubernetes_available": False,
            "service_account": None,
            "rbac_permissions": [],
            "exposed_services": [],
            "vulnerabilities": []
        }
        
        try:
            # Verificar kubectl
            subprocess.run(["kubectl", "version", "--client"], capture_output=True, check=True)
            result["kubernetes_available"] = True
            
            # Verificar service account
            if os.path.exists("/var/run/secrets/kubernetes.io/serviceaccount"):
                result["service_account"] = "default"
                with open("/var/run/secrets/kubernetes.io/serviceaccount/token", "r") as f:
                    token = f.read().strip()
                    if token:
                        result["vulnerabilities"].append("Service account token accessible")
            
            # Simular verificación de RBAC
            result["rbac_permissions"] = ["get", "list", "create"]
            
        except subprocess.CalledProcessError:
            pass
        
        return result
    
    def simulate_container_escape(self) -> Dict:
        """Simula escape de contenedor"""
        print("[ATTACK] Simulando container escape...")
        
        escape_techniques = []
        
        # Técnica 1: Privileged container
        if os.path.exists("/dev"):
            devices = os.listdir("/dev")
            if len(devices) > 10:  # Muchos devices = probablemente privileged
                escape_techniques.append({
                    "technique": "Privileged Container",
                    "success": True,
                    "description": "Container running in privileged mode",
                    "impact": "Full host access",
                    "mitigation": "Avoid --privileged flag"
                })
        
        # Técnica 2: Host PID namespace
        if os.path.exists("/proc/1/exe"):
            try:
                link = os.readlink("/proc/1/exe")
                if "systemd" in link or "init" in link:
                    escape_techniques.append({
                        "technique": "Host PID Namespace",
                        "success": True,
                        "description": "Access to host PID namespace",
                        "impact": "Host process manipulation",
                        "mitigation": "Remove --pid=host"
                    })
            except:
                pass
        
        # Técnica 3: Docker socket mount
        if os.path.exists("/var/run/docker.sock"):
            escape_techniques.append({
                "technique": "Docker Socket Escape",
                "success": True,
                "description": "Docker socket mounted in container",
                "impact": "Container orchestration control",
                "mitigation": "Remove docker.sock mount"
            })
        
        return {
            "attack_type": "container_escape",
            "techniques_attempted": len(escape_techniques),
            "successful_techniques": len([t for t in escape_techniques if t["success"]]),
            "techniques": escape_techniques,
            "overall_success": len(escape_techniques) > 0
        }
    
    def simulate_privilege_escalation(self) -> Dict:
        """Simula escalada de privilegios"""
        print("[ATTACK] Simulando privilege escalation...")
        
        escalation_paths = []
        
        # Verificar SUID binaries
        try:
            result = subprocess.run(["find", "/", "-perm", "-4000", "-type", "f", "2>/dev/null"], 
                                  capture_output=True, text=True, timeout=10)
            suid_files = result.stdout.strip().split('\n') if result.stdout else []
            
            dangerous_suid = [f for f in suid_files if any(cmd in f for cmd in ["vim", "nano", "find", "bash"])]
            
            if dangerous_suid:
                escalation_paths.append({
                    "technique": "SUID Binary Abuse",
                    "success": True,
                    "binaries": dangerous_suid[:3],
                    "impact": "Root privilege escalation",
                    "mitigation": "Remove unnecessary SUID bits"
                })
        except:
            pass
        
        # Verificar sudo misconfigurations
        if os.path.exists("/etc/sudoers"):
            escalation_paths.append({
                "technique": "Sudo Misconfiguration",
                "success": True,
                "description": "Potential sudo misconfigurations",
                "impact": "Command execution as root",
                "mitigation": "Review sudo policies"
            })
        
        # Verificar capabilities
        try:
            result = subprocess.run(["capsh", "--print"], capture_output=True, text=True)
            if "cap_sys_admin" in result.stdout.lower():
                escalation_paths.append({
                    "technique": "Linux Capabilities",
                    "success": True,
                    "description": "Dangerous capabilities assigned",
                    "impact": "System administration access",
                    "mitigation": "Drop unnecessary capabilities"
                })
        except:
            pass
        
        return {
            "attack_type": "privilege_escalation",
            "paths_found": len(escalation_paths),
            "successful_paths": len([p for p in escalation_paths if p["success"]]),
            "escalation_paths": escalation_paths,
            "overall_success": len(escalation_paths) > 0
        }
    
    def simulate_lateral_movement(self) -> Dict:
        """Simula movimiento lateral"""
        print("[ATTACK] Simulando lateral movement...")
        
        movement_vectors = []
        
        # Simular discovery de servicios internos
        internal_services = [
            {"service": "redis", "port": 6379, "auth": False},
            {"service": "mongodb", "port": 27017, "auth": False},
            {"service": "elasticsearch", "port": 9200, "auth": False},
            {"service": "kubernetes-api", "port": 8080, "auth": False}
        ]
        
        for service in internal_services:
            movement_vectors.append({
                "technique": f"Internal {service['service'].title()} Access",
                "success": True,
                "target": f"{service['service']}:{service['port']}",
                "authentication": service["auth"],
                "impact": "Lateral movement to internal services",
                "mitigation": "Network segmentation and authentication"
            })
        
        # Simular credential harvesting
        credential_sources = [
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
            "/root/.aws/credentials",
            "/root/.docker/config.json",
            "/etc/kubernetes/admin.conf"
        ]
        
        found_credentials = [src for src in credential_sources if os.path.exists(src)]
        
        if found_credentials:
            movement_vectors.append({
                "technique": "Credential Harvesting",
                "success": True,
                "sources": found_credentials,
                "impact": "Access to external services",
                "mitigation": "Secure credential storage"
            })
        
        return {
            "attack_type": "lateral_movement",
            "vectors_attempted": len(movement_vectors),
            "successful_vectors": len([v for v in movement_vectors if v["success"]]),
            "movement_vectors": movement_vectors,
            "overall_success": len(movement_vectors) > 0
        }
    
    def simulate_data_extraction(self) -> Dict:
        """Simula extracción de datos"""
        print("[ATTACK] Simulando data extraction...")
        
        extraction_methods = []
        
        # Simular acceso a volúmenes montados
        sensitive_paths = [
            "/etc/passwd",
            "/etc/shadow",
            "/root/.ssh/",
            "/var/log/",
            "/proc/version",
            "/sys/class/dmi/id/"
        ]
        
        accessible_paths = [path for path in sensitive_paths if os.path.exists(path)]
        
        if accessible_paths:
            extraction_methods.append({
                "technique": "Host File Access",
                "success": True,
                "accessible_paths": accessible_paths,
                "impact": "Sensitive host information disclosure",
                "mitigation": "Limit mounted volumes"
            })
        
        # Simular acceso a secretos de Kubernetes
        k8s_secrets_path = "/var/run/secrets/kubernetes.io/serviceaccount"
        if os.path.exists(k8s_secrets_path):
            extraction_methods.append({
                "technique": "Kubernetes Secrets",
                "success": True,
                "location": k8s_secrets_path,
                "impact": "Cluster authentication tokens",
                "mitigation": "Use projected volumes with limited scope"
            })
        
        # Simular metadata service access (cloud providers)
        metadata_endpoints = [
            "http://169.254.169.254/latest/meta-data/",  # AWS
            "http://metadata.google.internal/computeMetadata/v1/",  # GCP
            "http://169.254.169.254/metadata/instance"  # Azure
        ]
        
        for endpoint in metadata_endpoints:
            extraction_methods.append({
                "technique": "Cloud Metadata Access",
                "success": False,  # Simulated - would need actual network access
                "endpoint": endpoint,
                "impact": "Cloud credentials and instance information",
                "mitigation": "Disable metadata service or use IMDSv2"
            })
        
        return {
            "attack_type": "data_extraction",
            "methods_attempted": len(extraction_methods),
            "successful_methods": len([m for m in extraction_methods if m["success"]]),
            "extraction_methods": extraction_methods,
            "overall_success": any(m["success"] for m in extraction_methods)
        }
    
    def simulate_resource_hijacking(self) -> Dict:
        """Simula secuestro de recursos"""
        print("[ATTACK] Simulando resource hijacking...")
        
        hijacking_techniques = []
        
        # Simular crypto mining
        hijacking_techniques.append({
            "technique": "Cryptocurrency Mining",
            "success": True,
            "description": "Deploy crypto miner in container",
            "resource_impact": "High CPU utilization",
            "detection_evasion": "Process name masquerading",
            "mitigation": "Resource limits and monitoring"
        })
        
        # Simular botnet deployment
        hijacking_techniques.append({
            "technique": "Botnet Deployment",
            "success": True,
            "description": "Container joins botnet network",
            "resource_impact": "Network bandwidth consumption",
            "detection_evasion": "Encrypted C2 communication",
            "mitigation": "Network policies and egress filtering"
        })
        
        # Simular resource exhaustion
        hijacking_techniques.append({
            "technique": "Resource Exhaustion",
            "success": True,
            "description": "Memory and CPU bomb deployment",
            "resource_impact": "System unavailability",
            "detection_evasion": "Gradual resource consumption",
            "mitigation": "Resource quotas and limits"
        })
        
        return {
            "attack_type": "resource_hijacking",
            "techniques_deployed": len(hijacking_techniques),
            "successful_deployments": len([t for t in hijacking_techniques if t["success"]]),
            "hijacking_techniques": hijacking_techniques,
            "overall_success": len(hijacking_techniques) > 0
        }
    
    def generate_attack_report(self, results: List[Dict]) -> Dict:
        """Genera reporte de ataque completo"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "attack_summary": {
                "total_attacks": len(results),
                "successful_attacks": len([r for r in results if r.get("overall_success")]),
                "attack_success_rate": 0
            },
            "attack_results": results,
            "risk_assessment": {
                "overall_risk": "HIGH",
                "critical_vulnerabilities": [],
                "immediate_actions": []
            },
            "recommendations": []
        }
        
        # Calcular tasa de éxito
        if results:
            success_rate = (report["attack_summary"]["successful_attacks"] / len(results)) * 100
            report["attack_summary"]["attack_success_rate"] = round(success_rate, 2)
        
        # Evaluar riesgo general
        successful_attacks = report["attack_summary"]["successful_attacks"]
        if successful_attacks >= 4:
            report["risk_assessment"]["overall_risk"] = "CRITICAL"
        elif successful_attacks >= 2:
            report["risk_assessment"]["overall_risk"] = "HIGH"
        elif successful_attacks >= 1:
            report["risk_assessment"]["overall_risk"] = "MEDIUM"
        else:
            report["risk_assessment"]["overall_risk"] = "LOW"
        
        # Generar recomendaciones
        recommendations = [
            "🔒 Implement least privilege principle for containers",
            "🚫 Avoid running containers in privileged mode",
            "📊 Set resource limits and quotas",
            "🔍 Enable comprehensive logging and monitoring",
            "🌐 Implement network segmentation",
            "🔐 Use secrets management solutions",
            "⚡ Regular security assessments and updates",
            "🛡️ Deploy runtime security tools"
        ]
        
        report["recommendations"] = recommendations[:6]  # Top 6 recommendations
        
        return report

def main():
    """Función principal"""
    simulator = CloudNativeAttackSimulator()
    
    print("☁️ BOFA Cloud Native Attack Simulator v1.0")
    print("=" * 50)
    
    # Verificar entornos
    print("\n🔍 ANÁLISIS DE ENTORNO")
    docker_info = simulator.check_docker_environment()
    k8s_info = simulator.check_kubernetes_environment()
    
    print(f"Docker disponible: {'✅' if docker_info['docker_available'] else '❌'}")
    print(f"Kubernetes disponible: {'✅' if k8s_info['kubernetes_available'] else '❌'}")
    
    if docker_info['vulnerabilities']:
        print("🚨 Vulnerabilidades Docker detectadas:")
        for vuln in docker_info['vulnerabilities']:
            print(f"  - {vuln}")
    
    # Ejecutar simulaciones de ataque
    print("\n⚔️ EJECUTANDO SIMULACIONES DE ATAQUE")
    attack_results = []
    
    scenarios = ["container_escape", "privilege_escalation", "lateral_movement", 
                "data_extraction", "resource_hijacking"]
    
    for scenario in scenarios:
        print(f"\n[{scenario.upper()}] Iniciando simulación...")
        if scenario in simulator.attack_scenarios:
            result = simulator.attack_scenarios[scenario]()
            attack_results.append(result)
            
            success_indicator = "✅ EXITOSO" if result.get("overall_success") else "❌ FALLIDO"
            print(f"[{scenario.upper()}] {success_indicator}")
        
        time.sleep(1)  # Pausa entre ataques
    
    # Generar reporte final
    print("\n📊 GENERANDO REPORTE FINAL")
    final_report = simulator.generate_attack_report(attack_results)
    
    print(f"\n🎯 RESUMEN DE RESULTADOS")
    print("=" * 30)
    summary = final_report["attack_summary"]
    print(f"Ataques ejecutados: {summary['total_attacks']}")
    print(f"Ataques exitosos: {summary['successful_attacks']}")
    print(f"Tasa de éxito: {summary['attack_success_rate']}%")
    print(f"Riesgo general: {final_report['risk_assessment']['overall_risk']}")
    
    print(f"\n💡 RECOMENDACIONES CRÍTICAS")
    for i, rec in enumerate(final_report["recommendations"], 1):
        print(f"{i}. {rec}")
    
    # Exportar reporte
    output_file = f"cloud_attack_simulation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump(final_report, f, indent=2, default=str)
    
    print(f"\n✅ Simulación completada. Reporte: {output_file}")

if __name__ == "__main__":
    main()
