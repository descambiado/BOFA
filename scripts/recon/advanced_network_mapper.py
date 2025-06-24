
#!/usr/bin/env python3
"""
Advanced Network Mapper v1.0
Herramienta avanzada de mapeo de red con técnicas sigilosas
Author: @descambiado
"""

import socket
import threading
import time
import random
import json
import subprocess
import re
from typing import Dict, List, Any, Optional
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

class AdvancedNetworkMapper:
    def __init__(self):
        self.scan_techniques = [
            "tcp_connect",
            "tcp_syn", 
            "udp_scan",
            "stealth_scan",
            "fragment_scan"
        ]
        
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080
        ]
        
        self.service_signatures = {
            21: "FTP",
            22: "SSH", 
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            135: "RPC",
            139: "NetBIOS",
            143: "IMAP",
            443: "HTTPS",
            993: "IMAPS",
            995: "POP3S",
            1723: "PPTP",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            8080: "HTTP-Alt"
        }
        
        self.discovered_hosts = {}
        self.open_ports = {}
        self.services_detected = {}
        
    def ping_sweep(self, network: str, timeout: float = 1.0) -> List[str]:
        """Realiza ping sweep de la red"""
        print(f"[INFO] Iniciando ping sweep en {network}")
        
        alive_hosts = []
        base_ip = ".".join(network.split(".")[:-1])
        
        def ping_host(host_num):
            target = f"{base_ip}.{host_num}"
            try:
                # Simular ping usando socket (más portable que subprocess)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((target, 80))  # Prueba puerto 80 común
                sock.close()
                
                if result == 0:
                    return target
                    
                # Intentar con otros puertos comunes si 80 falla
                for port in [22, 443, 135]:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(timeout)
                        result = sock.connect_ex((target, port))
                        sock.close()
                        if result == 0:
                            return target
                    except:
                        continue
                        
            except Exception:
                pass
            return None
        
        # Escaneo multi-hilo
        with ThreadPoolExecutor(max_workers=50) as executor:
            results = executor.map(ping_host, range(1, 255))
            alive_hosts = [host for host in results if host]
        
        print(f"[SUCCESS] Encontrados {len(alive_hosts)} hosts activos")
        return alive_hosts
    
    def port_scan(self, target: str, ports: List[int] = None, technique: str = "tcp_connect") -> Dict[int, str]:
        """Escanea puertos en un objetivo"""
        if ports is None:
            ports = self.common_ports
            
        print(f"[INFO] Escaneando {target} con técnica {technique}")
        
        open_ports = {}
        
        def scan_port(port):
            try:
                if technique == "tcp_connect":
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((target, port))
                    sock.close()
                    
                    if result == 0:
                        service = self.service_signatures.get(port, "Unknown")
                        return port, service
                        
                elif technique == "stealth_scan":
                    # Simular escaneo sigiloso con timeout aleatorio
                    time.sleep(random.uniform(0.1, 0.5))
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((target, port))
                    sock.close()
                    
                    if result == 0:
                        service = self.service_signatures.get(port, "Unknown")
                        return port, service
                        
            except Exception:
                pass
            return None, None
        
        # Escaneo multi-hilo con límite para sigilo
        max_workers = 10 if technique == "stealth_scan" else 50
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = executor.map(scan_port, ports)
            
            for port, service in results:
                if port:
                    open_ports[port] = service
        
        print(f"[SUCCESS] Encontrados {len(open_ports)} puertos abiertos en {target}")
        return open_ports
    
    def service_detection(self, target: str, port: int) -> Dict[str, Any]:
        """Detecta servicios específicos en puertos"""
        service_info = {
            "port": port,
            "service": self.service_signatures.get(port, "Unknown"),
            "version": "Unknown",
            "banner": "",
            "details": {}
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            
            # Intentar obtener banner
            if port in [21, 22, 23, 25, 110, 143]:  # Servicios con banner
                sock.send(b"\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                service_info["banner"] = banner
                
                # Extraer información de versión del banner
                version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', banner)
                if version_match:
                    service_info["version"] = version_match.group(1)
                    
            elif port == 80 or port == 8080:  # HTTP
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                service_info["banner"] = response.split('\r\n')[0]
                
                # Extraer servidor web
                server_match = re.search(r'Server:\s*([^\r\n]+)', response)
                if server_match:
                    service_info["details"]["server"] = server_match.group(1)
                    
            elif port == 443:  # HTTPS
                service_info["details"]["encryption"] = "TLS/SSL"
                
            sock.close()
            
        except Exception as e:
            service_info["error"] = str(e)
        
        return service_info
    
    def os_fingerprinting(self, target: str) -> Dict[str, Any]:
        """Intenta identificar el sistema operativo"""
        os_info = {
            "target": target,
            "os_guess": "Unknown",
            "confidence": 0,
            "indicators": []
        }
        
        # Técnicas básicas de fingerprinting
        tcp_fingerprints = {
            "Windows": ["135", "139", "445", "3389"],
            "Linux": ["22", "80", "443"],
            "MacOS": ["22", "548", "631"]
        }
        
        # Obtener puertos abiertos
        open_ports = list(self.open_ports.get(target, {}).keys())
        
        # Analizar patrones de puertos
        for os_type, typical_ports in tcp_fingerprints.items():
            matches = sum(1 for port in typical_ports if int(port) in open_ports)
            if matches > 0:
                confidence = (matches / len(typical_ports)) * 100
                if confidence > os_info["confidence"]:
                    os_info["os_guess"] = os_type
                    os_info["confidence"] = confidence
                    os_info["indicators"].append(f"Puertos típicos de {os_type}: {typical_ports}")
        
        # Análisis adicional basado en servicios específicos
        if 3389 in open_ports:  # RDP
            os_info["indicators"].append("RDP activo - Probablemente Windows")
            if os_info["confidence"] < 80:
                os_info["os_guess"] = "Windows"
                os_info["confidence"] = 80
                
        if 22 in open_ports and 80 in open_ports:  # SSH + HTTP
            os_info["indicators"].append("SSH + HTTP - Probablemente Linux/Unix")
            
        return os_info
    
    def vulnerability_scan(self, target: str, ports: Dict[int, str]) -> List[Dict[str, Any]]:
        """Escanea vulnerabilidades básicas"""
        vulnerabilities = []
        
        for port, service in ports.items():
            vuln_checks = {
                21: self._check_ftp_anonymous,
                22: self._check_ssh_version,
                23: self._check_telnet_security,
                25: self._check_smtp_relay,
                80: self._check_http_headers,
                443: self._check_ssl_config,
                3389: self._check_rdp_security
            }
            
            check_func = vuln_checks.get(port)
            if check_func:
                vuln_result = check_func(target, port)
                if vuln_result:
                    vulnerabilities.append(vuln_result)
        
        return vulnerabilities
    
    def _check_ftp_anonymous(self, target: str, port: int) -> Optional[Dict[str, Any]]:
        """Verifica acceso FTP anónimo"""
        try:
            import ftplib
            ftp = ftplib.FTP()
            ftp.connect(target, port, timeout=5)
            ftp.login("anonymous", "test@test.com")
            ftp.quit()
            
            return {
                "target": target,
                "port": port,
                "vulnerability": "FTP Anonymous Access",
                "severity": "Medium",
                "description": "Servidor FTP permite acceso anónimo"
            }
        except:
            return None
    
    def _check_ssh_version(self, target: str, port: int) -> Optional[Dict[str, Any]]:
        """Verifica versión SSH"""
        try:
            sock = socket.socket()
            sock.settimeout(5)
            sock.connect((target, port))
            banner = sock.recv(1024).decode()
            sock.close()
            
            # Buscar versiones vulnerables
            if "OpenSSH_7.2" in banner or "OpenSSH_6" in banner:
                return {
                    "target": target,
                    "port": port,
                    "vulnerability": "Outdated SSH Version",
                    "severity": "Low",
                    "description": f"Versión SSH potencialmente vulnerable: {banner.strip()}"
                }
        except:
            pass
        return None
    
    def _check_telnet_security(self, target: str, port: int) -> Dict[str, Any]:
        """Verifica seguridad Telnet"""
        return {
            "target": target,
            "port": port,
            "vulnerability": "Telnet Service Active",
            "severity": "High",
            "description": "Telnet es inseguro - transmite credenciales en texto plano"
        }
    
    def _check_smtp_relay(self, target: str, port: int) -> Optional[Dict[str, Any]]:
        """Verifica relay SMTP abierto"""
        # Implementación básica - en entorno real sería más complejo
        return {
            "target": target,
            "port": port,
            "vulnerability": "Potential SMTP Relay",
            "severity": "Medium",
            "description": "Servidor SMTP podría permitir relay no autorizado"
        }
    
    def _check_http_headers(self, target: str, port: int) -> Optional[Dict[str, Any]]:
        """Verifica headers HTTP de seguridad"""
        try:
            import urllib.request
            response = urllib.request.urlopen(f"http://{target}:{port}", timeout=5)
            headers = dict(response.headers)
            
            missing_headers = []
            if 'X-Frame-Options' not in headers:
                missing_headers.append('X-Frame-Options')
            if 'X-Content-Type-Options' not in headers:
                missing_headers.append('X-Content-Type-Options')
            if 'Strict-Transport-Security' not in headers:
                missing_headers.append('Strict-Transport-Security')
                
            if missing_headers:
                return {
                    "target": target,
                    "port": port,
                    "vulnerability": "Missing Security Headers",
                    "severity": "Low",
                    "description": f"Headers faltantes: {', '.join(missing_headers)}"
                }
        except:
            pass
        return None
    
    def _check_ssl_config(self, target: str, port: int) -> Dict[str, Any]:
        """Verifica configuración SSL"""
        return {
            "target": target,
            "port": port,
            "vulnerability": "SSL/TLS Configuration Check Needed",
            "severity": "Info",
            "description": "Verificar configuración SSL/TLS manualmente"
        }
    
    def _check_rdp_security(self, target: str, port: int) -> Dict[str, Any]:
        """Verifica seguridad RDP"""
        return {
            "target": target,
            "port": port,
            "vulnerability": "RDP Service Exposed",
            "severity": "Medium",
            "description": "Servicio RDP expuesto - verificar configuración de seguridad"
        }
    
    def comprehensive_scan(self, network: str, scan_type: str = "standard") -> Dict[str, Any]:
        """Escaneo comprehensivo de red"""
        print(f"🔍 Iniciando escaneo comprehensivo de {network}")
        print(f"📊 Tipo de escaneo: {scan_type}")
        
        start_time = datetime.now()
        
        # 1. Discovery de hosts
        alive_hosts = self.ping_sweep(network)
        self.discovered_hosts = {host: {"status": "alive"} for host in alive_hosts}
        
        # 2. Escaneo de puertos
        for host in alive_hosts[:5]:  # Limitar a 5 hosts para demo
            if scan_type == "stealth":
                ports = self.port_scan(host, technique="stealth_scan")
            else:
                ports = self.port_scan(host)
                
            self.open_ports[host] = ports
            
            # 3. Detección de servicios
            services = {}
            for port in list(ports.keys())[:5]:  # Limitar servicios para demo
                service_info = self.service_detection(host, port)
                services[port] = service_info
                
            self.services_detected[host] = services
        
        # 4. OS Fingerprinting
        os_results = {}
        for host in alive_hosts[:3]:  # Limitar para demo
            os_info = self.os_fingerprinting(host)
            os_results[host] = os_info
        
        # 5. Escaneo de vulnerabilidades
        vulnerability_results = {}
        for host, ports in self.open_ports.items():
            vulns = self.vulnerability_scan(host, ports)
            if vulns:
                vulnerability_results[host] = vulns
        
        end_time = datetime.now()
        scan_duration = (end_time - start_time).total_seconds()
        
        # Compilar resultados
        results = {
            "scan_info": {
                "network": network,
                "scan_type": scan_type,
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "duration_seconds": scan_duration,
                "hosts_discovered": len(alive_hosts),
                "total_open_ports": sum(len(ports) for ports in self.open_ports.values())
            },
            "discovered_hosts": self.discovered_hosts,
            "open_ports": self.open_ports,
            "services_detected": self.services_detected,
            "os_fingerprinting": os_results,
            "vulnerabilities": vulnerability_results,
            "recommendations": self._generate_recommendations(vulnerability_results)
        }
        
        return results
    
    def _generate_recommendations(self, vulnerabilities: Dict[str, List[Dict[str, Any]]]) -> List[str]:
        """Genera recomendaciones basadas en vulnerabilidades"""
        recommendations = []
        
        all_vulns = []
        for host_vulns in vulnerabilities.values():
            all_vulns.extend(host_vulns)
        
        if any("Telnet" in v.get("vulnerability", "") for v in all_vulns):
            recommendations.append("🚨 Deshabilitar servicios Telnet y usar SSH")
        
        if any("FTP Anonymous" in v.get("vulnerability", "") for v in all_vulns):
            recommendations.append("🔒 Configurar autenticación FTP adecuada")
        
        if any("RDP" in v.get("vulnerability", "") for v in all_vulns):
            recommendations.append("🛡️ Asegurar configuración RDP con autenticación fuerte")
        
        if any("SSH" in v.get("vulnerability", "") for v in all_vulns):
            recommendations.append("⬆️ Actualizar versiones SSH obsoletas")
        
        recommendations.extend([
            "🔥 Implementar firewall para limitar acceso",
            "📊 Monitorear logs de acceso regularmente",
            "🔐 Usar autenticación multifactor donde sea posible",
            "🛠️ Mantener servicios actualizados"
        ])
        
        return recommendations

def main():
    """Función principal"""
    mapper = AdvancedNetworkMapper()
    
    print("🗺️ Advanced Network Mapper v1.0")
    print("=" * 40)
    print("⚠️ SOLO PARA REDES AUTORIZADAS")
    print("=" * 40)
    
    # Red de ejemplo (localhost)
    target_network = "127.0.0.1"
    
    print(f"\n🎯 Objetivo: {target_network}")
    print("🔍 Iniciando escaneo comprehensivo...")
    
    # Realizar escaneo completo
    results = mapper.comprehensive_scan(target_network, "standard")
    
    # Mostrar resultados
    print(f"\n📊 RESULTADOS DEL ESCANEO")
    print("=" * 30)
    
    scan_info = results["scan_info"]
    print(f"Red escaneada: {scan_info['network']}")
    print(f"Duración: {scan_info['duration_seconds']:.2f} segundos")
    print(f"Hosts descubiertos: {scan_info['hosts_discovered']}")
    print(f"Puertos abiertos total: {scan_info['total_open_ports']}")
    
    print(f"\n🖥️ HOSTS ACTIVOS")
    for host in results["discovered_hosts"]:
        print(f"  📍 {host}")
        
        if host in results["open_ports"]:
            ports = results["open_ports"][host]
            print(f"    🔓 Puertos abiertos: {len(ports)}")
            for port, service in list(ports.items())[:3]:
                print(f"      {port}/tcp - {service}")
        
        if host in results["os_fingerprinting"]:
            os_info = results["os_fingerprinting"][host]
            print(f"    💻 OS: {os_info['os_guess']} (confianza: {os_info['confidence']:.1f}%)")
    
    print(f"\n🚨 VULNERABILIDADES ENCONTRADAS")
    total_vulns = 0
    for host, vulns in results["vulnerabilities"].items():
        total_vulns += len(vulns)
        print(f"  📍 {host}: {len(vulns)} vulnerabilidades")
        for vuln in vulns[:2]:  # Mostrar solo las primeras 2
            print(f"    - {vuln['vulnerability']} (Severidad: {vuln['severity']})")
    
    print(f"\n💡 RECOMENDACIONES ({len(results['recommendations'])})")
    for rec in results["recommendations"][:5]:
        print(f"  {rec}")
    
    # Exportar resultados
    output_file = f"network_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n✅ Resultados exportados a: {output_file}")
    print("🔍 Escaneo completado exitosamente!")

if __name__ == "__main__":
    main()
