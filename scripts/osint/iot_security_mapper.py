
#!/usr/bin/env python3
"""
BOFA IoT/OT Security Mapper v1.0
Descubre dispositivos IoT/OT expuestos
Author: @descambiado
"""

import json
import requests
import socket
from datetime import datetime
import ipaddress
from typing import Dict, List, Any
import subprocess

class IoTSecurityMapper:
    def __init__(self):
        self.industrial_protocols = {
            "modbus": {"port": 502, "description": "Modbus TCP"},
            "mqtt": {"port": 1883, "description": "MQTT Broker"},
            "bacnet": {"port": 47808, "description": "BACnet"},
            "dnp3": {"port": 20000, "description": "DNP3"},
            "iec61850": {"port": 102, "description": "IEC 61850"},
            "opcua": {"port": 4840, "description": "OPC UA"},
            "coap": {"port": 5683, "description": "CoAP"}
        }
        
        self.vulnerability_signatures = {
            "default_credentials": [
                {"username": "admin", "password": "admin"},
                {"username": "admin", "password": "password"},
                {"username": "root", "password": "root"},
                {"username": "admin", "password": ""},
                {"username": "", "password": ""}
            ],
            "common_exploits": [
                "CVE-2020-12345",  # Ejemplo de CVE para dispositivos IoT
                "CVE-2021-54321",
                "CVE-2022-98765"
            ]
        }
    
    def simulate_shodan_search(self, query: str, max_results: int = 100) -> List[Dict]:
        """Simula búsqueda en Shodan"""
        print(f"[SHODAN] Simulando búsqueda: {query}")
        
        # Simular resultados de Shodan
        simulated_devices = []
        
        device_types = [
            "Schneider Electric Gateway",
            "Siemens SIMATIC",
            "Rockwell Automation PLC",
            "Honeywell DCS",
            "ABB Industrial Router",
            "Omron PLC",
            "Mitsubishi Electric HMI",
            "Phoenix Contact Gateway",
            "Moxa Serial Server",
            "Red Lion MQTT Broker"
        ]
        
        countries = ["United States", "Germany", "China", "Japan", "United Kingdom", "France", "Canada", "Netherlands"]
        cities = ["New York", "Berlin", "Shanghai", "Tokyo", "London", "Paris", "Toronto", "Amsterdam"]
        
        for i in range(min(max_results, 50)):  # Limitar para demo
            device = {
                "ip": f"203.{i//10 + 1}.{i%10 + 1}.{i + 10}",
                "port": 502 + (i % 4) * 100,
                "protocol": list(self.industrial_protocols.keys())[i % len(self.industrial_protocols)],
                "banner": f"{device_types[i % len(device_types)]} v2.{i%5}.{i%10}",
                "country": countries[i % len(countries)],
                "city": cities[i % len(cities)],
                "org": f"Industrial Corp {i + 1}",
                "timestamp": datetime.now().isoformat(),
                "vulns": self.generate_vulnerabilities(i),
                "tags": self.generate_device_tags(i)
            }
            simulated_devices.append(device)
        
        return simulated_devices
    
    def generate_vulnerabilities(self, seed: int) -> List[str]:
        """Genera vulnerabilidades simuladas"""
        vulns = []
        
        # Probabilidad de vulnerabilidades basada en seed
        if seed % 3 == 0:
            vulns.append("CVE-2020-12345")
        if seed % 5 == 0:
            vulns.append("CVE-2021-54321")
        if seed % 7 == 0:
            vulns.append("Default credentials")
        if seed % 11 == 0:
            vulns.append("Unencrypted communications")
        
        return vulns
    
    def generate_device_tags(self, seed: int) -> List[str]:
        """Genera tags de dispositivo"""
        all_tags = ["industrial", "scada", "plc", "hmi", "gateway", "sensor", "controller", "router"]
        return [all_tags[i] for i in range(len(all_tags)) if (seed + i) % 3 == 0]
    
    def analyze_protocol_security(self, protocol: str, device_info: Dict) -> Dict:
        """Analiza seguridad del protocolo"""
        analysis = {
            "protocol": protocol,
            "security_level": "unknown",
            "vulnerabilities": [],
            "recommendations": []
        }
        
        protocol_info = self.industrial_protocols.get(protocol, {})
        
        if protocol == "modbus":
            analysis.update({
                "security_level": "low",
                "vulnerabilities": [
                    "No authentication mechanism",
                    "Plain text communications", 
                    "No encryption"
                ],
                "recommendations": [
                    "Use Modbus/TCP with VPN",
                    "Implement network segmentation",
                    "Monitor all Modbus communications"
                ]
            })
        
        elif protocol == "mqtt":
            analysis.update({
                "security_level": "medium",
                "vulnerabilities": [
                    "Potentially open broker",
                    "Weak authentication",
                    "Unencrypted topics"
                ],
                "recommendations": [
                    "Enable MQTT authentication",
                    "Use TLS encryption",
                    "Implement topic access controls"
                ]
            })
        
        elif protocol == "bacnet":
            analysis.update({
                "security_level": "low",
                "vulnerabilities": [
                    "No built-in security",
                    "Broadcast communications",
                    "Device enumeration possible"
                ],
                "recommendations": [
                    "Use BACnet/SC (Secure Connect)",
                    "Network segmentation required",
                    "Monitor broadcast traffic"
                ]
            })
        
        # Agregar vulnerabilidades específicas del dispositivo
        if device_info.get("vulns"):
            analysis["vulnerabilities"].extend(device_info["vulns"])
        
        return analysis
    
    def check_device_security(self, device: Dict) -> Dict:
        """Verifica seguridad del dispositivo"""
        security_check = {
            "device_ip": device["ip"],
            "security_score": 0,
            "max_score": 100,
            "issues": [],
            "recommendations": []
        }
        
        # Verificar credenciales por defecto
        if self.test_default_credentials(device):
            security_check["issues"].append({
                "severity": "critical",
                "issue": "Default credentials detected",
                "description": "Device uses default username/password"
            })
        else:
            security_check["security_score"] += 25
        
        # Verificar cifrado
        if self.check_encryption(device):
            security_check["security_score"] += 20
        else:
            security_check["issues"].append({
                "severity": "high",
                "issue": "Unencrypted communications",
                "description": "Device communications are not encrypted"
            })
        
        # Verificar versión de firmware
        if self.check_firmware_version(device):
            security_check["security_score"] += 15
        else:
            security_check["issues"].append({
                "severity": "medium",
                "issue": "Outdated firmware",
                "description": "Device firmware may be outdated"
            })
        
        # Verificar configuración de red
        if self.check_network_config(device):
            security_check["security_score"] += 20
        else:
            security_check["issues"].append({
                "severity": "medium",
                "issue": "Insecure network configuration",
                "description": "Device network settings are not optimal"
            })
        
        # Verificar acceso remoto
        if self.check_remote_access(device):
            security_check["security_score"] += 10
        else:
            security_check["issues"].append({
                "severity": "high",
                "issue": "Unsecured remote access",
                "description": "Remote access is enabled without proper security"
            })
        
        # Verificar logging y monitoreo
        if self.check_logging(device):
            security_check["security_score"] += 10
        else:
            security_check["issues"].append({
                "severity": "low",
                "issue": "Insufficient logging",
                "description": "Device logging capabilities are limited"
            })
        
        # Generar recomendaciones
        security_check["recommendations"] = self.generate_security_recommendations(security_check["issues"])
        
        return security_check
    
    def test_default_credentials(self, device: Dict) -> bool:
        """Simula prueba de credenciales por defecto"""
        # En una implementación real, haríamos conexión real al dispositivo
        # Aquí simulamos basado en el device info
        return "Default credentials" in device.get("vulns", [])
    
    def check_encryption(self, device: Dict) -> bool:
        """Verifica si el dispositivo usa cifrado"""
        # Simular verificación de cifrado
        return device.get("port", 0) != 502  # Modbus TCP normalmente no cifrado
    
    def check_firmware_version(self, device: Dict) -> bool:
        """Verifica versión de firmware"""
        banner = device.get("banner", "")
        # Simular check de versión
        return "v2.5" in banner or "v3." in banner  # Versiones "nuevas"
    
    def check_network_config(self, device: Dict) -> bool:
        """Verifica configuración de red"""
        # Simular verificación de configuración
        return len(device.get("tags", [])) > 2  # Dispositivos con más tags = mejor configurados
    
    def check_remote_access(self, device: Dict) -> bool:
        """Verifica acceso remoto seguro"""
        # Simular verificación
        return "gateway" not in device.get("tags", [])  # Gateways más probables de tener acceso remoto
    
    def check_logging(self, device: Dict) -> bool:
        """Verifica capacidades de logging"""
        # Simular verificación
        return "controller" in device.get("tags", [])  # Controllers suelen tener mejor logging
    
    def generate_security_recommendations(self, issues: List[Dict]) -> List[str]:
        """Genera recomendaciones de seguridad"""
        recommendations = []
        
        critical_issues = [issue for issue in issues if issue["severity"] == "critical"]
        high_issues = [issue for issue in issues if issue["severity"] == "high"]
        
        if critical_issues:
            recommendations.extend([
                "🚨 CRÍTICO: Cambiar credenciales por defecto inmediatamente",
                "🔒 Implementar autenticación fuerte",
                "🛡️ Aislar dispositivo hasta resolución"
            ])
        
        if high_issues:
            recommendations.extend([
                "🔐 Implementar cifrado de comunicaciones",
                "🌐 Configurar VPN para acceso remoto",
                "📊 Habilitar monitoreo continuo"
            ])
        
        # Recomendaciones generales
        recommendations.extend([
            "🔄 Actualizar firmware regularmente",
            "🚧 Implementar segmentación de red", 
            "📋 Establecer políticas de acceso",
            "🔍 Realizar auditorías periódicas"
        ])
        
        return recommendations[:6]  # Top 6 recomendaciones
    
    def generate_geographic_analysis(self, devices: List[Dict]) -> Dict:
        """Genera análisis geográfico"""
        country_count = {}
        city_count = {}
        
        for device in devices:
            country = device.get("country", "Unknown")
            city = device.get("city", "Unknown")
            
            country_count[country] = country_count.get(country, 0) + 1
            city_count[city] = city_count.get(city, 0) + 1
        
        return {
            "total_countries": len(country_count),
            "total_cities": len(city_count),
            "country_distribution": dict(sorted(country_count.items(), key=lambda x: x[1], reverse=True)[:10]),
            "city_distribution": dict(sorted(city_count.items(), key=lambda x: x[1], reverse=True)[:10]),
            "top_country": max(country_count.items(), key=lambda x: x[1]) if country_count else ("Unknown", 0),
            "geographic_diversity": len(country_count) / len(devices) if devices else 0
        }
    
    def generate_risk_assessment(self, devices: List[Dict], security_checks: List[Dict]) -> Dict:
        """Genera evaluación de riesgo"""
        if not security_checks:
            return {"error": "No security checks performed"}
        
        # Calcular métricas de riesgo
        total_score = sum(check["security_score"] for check in security_checks)
        avg_score = total_score / len(security_checks)
        
        critical_devices = len([check for check in security_checks 
                              if any(issue["severity"] == "critical" for issue in check["issues"])])
        
        high_risk_devices = len([check for check in security_checks 
                               if any(issue["severity"] == "high" for issue in check["issues"])])
        
        # Determinar nivel de riesgo general
        if avg_score < 30:
            overall_risk = "CRITICAL"
        elif avg_score < 50:
            overall_risk = "HIGH"
        elif avg_score < 70:
            overall_risk = "MEDIUM"
        else:
            overall_risk = "LOW"
        
        return {
            "overall_risk_level": overall_risk,
            "average_security_score": round(avg_score, 2),
            "devices_analyzed": len(security_checks),
            "critical_devices": critical_devices,
            "high_risk_devices": high_risk_devices,
            "devices_with_default_creds": len([d for d in devices if "Default credentials" in d.get("vulns", [])]),
            "most_common_vulnerability": self.get_most_common_vulnerability(devices),
            "risk_distribution": {
                "critical": critical_devices,
                "high": high_risk_devices,
                "medium": len(security_checks) - critical_devices - high_risk_devices - len([c for c in security_checks if c["security_score"] > 70]),
                "low": len([c for c in security_checks if c["security_score"] > 70])
            }
        }
    
    def get_most_common_vulnerability(self, devices: List[Dict]) -> str:
        """Obtiene la vulnerabilidad más común"""
        vuln_count = {}
        
        for device in devices:
            for vuln in device.get("vulns", []):
                vuln_count[vuln] = vuln_count.get(vuln, 0) + 1
        
        if vuln_count:
            return max(vuln_count.items(), key=lambda x: x[1])[0]
        return "None identified"

def main():
    """Función principal"""
    mapper = IoTSecurityMapper()
    
    print("🏭 BOFA IoT/OT Security Mapper v1.0")
    print("=" * 50)
    
    # Simular búsqueda
    search_query = "port:502,1883,47808"
    max_results = 50
    
    print(f"[INFO] Buscando dispositivos IoT/OT...")
    print(f"[INFO] Query: {search_query}")
    print(f"[INFO] Límite: {max_results} resultados")
    
    # Ejecutar búsqueda simulada
    devices = mapper.simulate_shodan_search(search_query, max_results)
    
    print(f"\n📊 DISPOSITIVOS ENCONTRADOS: {len(devices)}")
    
    # Análizar protocolos
    protocol_analysis = {}
    for device in devices:
        protocol = device.get("protocol")
        if protocol:
            if protocol not in protocol_analysis:
                protocol_analysis[protocol] = mapper.analyze_protocol_security(protocol, device)
            protocol_analysis[protocol]["device_count"] = protocol_analysis[protocol].get("device_count", 0) + 1
    
    print(f"\n🔌 PROTOCOLOS DETECTADOS:")
    for protocol, analysis in protocol_analysis.items():
        print(f"  {protocol.upper()}: {analysis['device_count']} dispositivos - Seguridad: {analysis['security_level']}")
    
    # Verificar seguridad de dispositivos
    print(f"\n🔒 VERIFICANDO SEGURIDAD DE DISPOSITIVOS...")
    security_checks = []
    for i, device in enumerate(devices[:10]):  # Limitar para demo
        check = mapper.check_device_security(device)
        security_checks.append(check)
        
        if i < 3:  # Mostrar solo primeros 3
            score_color = "🔴" if check["security_score"] < 30 else "🟡" if check["security_score"] < 70 else "🟢"
            print(f"  {device['ip']}: {score_color} {check['security_score']}/100")
    
    # Análisis geográfico
    geo_analysis = mapper.generate_geographic_analysis(devices)
    
    print(f"\n🌍 DISTRIBUCIÓN GEOGRÁFICA:")
    print(f"  Países: {geo_analysis['total_countries']}")
    print(f"  Ciudades: {geo_analysis['total_cities']}")
    print(f"  País principal: {geo_analysis['top_country'][0]} ({geo_analysis['top_country'][1]} dispositivos)")
    
    # Evaluación de riesgo
    risk_assessment = mapper.generate_risk_assessment(devices, security_checks)
    
    print(f"\n⚠️ EVALUACIÓN DE RIESGO:")
    print(f"  Nivel de riesgo general: {risk_assessment['overall_risk_level']}")
    print(f"  Puntuación promedio: {risk_assessment['average_security_score']}/100")
    print(f"  Dispositivos críticos: {risk_assessment['critical_devices']}")
    print(f"  Dispositivos alto riesgo: {risk_assessment['high_risk_devices']}")
    print(f"  Vulnerabilidad más común: {risk_assessment['most_common_vulnerability']}")
    
    print(f"\n💡 RECOMENDACIONES CRÍTICAS:")
    print("1. 🚨 Cambiar credenciales por defecto en todos los dispositivos")
    print("2. 🔒 Implementar segmentación de red para dispositivos industriales")
    print("3. 🛡️ Habilitar cifrado en comunicaciones críticas")
    print("4. 📊 Establecer monitoreo continuo de dispositivos OT")
    print("5. 🔄 Actualizar firmware de dispositivos vulnerables")
    
    # Generar reporte final
    final_report = {
        "timestamp": datetime.now().isoformat(),
        "search_parameters": {
            "query": search_query,
            "max_results": max_results
        },
        "summary": {
            "devices_found": len(devices),
            "protocols_detected": len(protocol_analysis),
            "countries": geo_analysis['total_countries'],
            "overall_risk": risk_assessment['overall_risk_level']
        },
        "devices": devices,
        "protocol_analysis": protocol_analysis,
        "geographic_analysis": geo_analysis,
        "security_analysis": security_checks,
        "risk_assessment": risk_assessment
    }
    
    # Exportar reporte
    output_file = f"iot_security_mapping_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump(final_report, f, indent=2, default=str)
    
    print(f"\n✅ Mapeo completado. Reporte: {output_file}")
    print("🏭 IoT/OT Security assessment finished!")

if __name__ == "__main__":
    main()
