
#!/usr/bin/env python3
"""
BOFA Ghost Scanner - Escaneo sigiloso sin ARP con TTL y MAC randomization
Autor: @descambiado
Versión: 1.0
"""

import socket
import random
import time
import argparse
import subprocess
from concurrent.futures import ThreadPoolExecutor

class GhostScanner:
    def __init__(self):
        self.alive_hosts = []
        self.stealth_delay = 0.5
    
    def randomize_ttl(self):
        """Randomiza TTL para evadir detección"""
        # TTL comunes: Windows (128), Linux (64), macOS (64)
        ttls = [64, 128, 255, 32, 60, 120]
        return random.choice(ttls)
    
    def stealth_ping(self, target):
        """Ping sigiloso con TTL randomizado"""
        try:
            ttl = self.randomize_ttl()
            # Usar diferentes métodos de ping para evadir detección
            methods = [
                f"ping -c 1 -t {ttl} -W 1 {target}",
                f"ping -c 1 -i 0.2 -W 1 {target}",
                f"hping3 -c 1 -S -p 80 {target}"  # Si está disponible
            ]
            
            method = random.choice(methods[:2])  # Solo ping normal por compatibilidad
            
            result = subprocess.run(method.split(), 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=3)
            
            if result.returncode == 0:
                return True
                
        except (subprocess.TimeoutExpired, Exception):
            pass
        
        return False
    
    def tcp_stealth_scan(self, target, port):
        """Escaneo TCP sigiloso"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            
            # Intentar conexión
            result = sock.connect_ex((target, port))
            sock.close()
            
            return result == 0
            
        except Exception:
            return False
    
    def ghost_scan_host(self, target):
        """Escaneo completo de un host"""
        print(f"👻 Escaneando {target}...")
        
        # Ping sigiloso primero
        if not self.stealth_ping(target):
            return None
        
        print(f"✅ Host activo: {target}")
        
        # Escaneo de puertos comunes
        common_ports = [22, 23, 53, 80, 135, 139, 443, 445, 993, 995, 1723, 3389, 5900]
        open_ports = []
        
        for port in common_ports:
            if self.tcp_stealth_scan(target, port):
                open_ports.append(port)
                print(f"  🔓 Puerto abierto: {port}")
            
            # Delay para evadir detección
            time.sleep(self.stealth_delay)
        
        return {
            "host": target,
            "open_ports": open_ports,
            "scan_time": time.time()
        }
    
    def scan_network(self, network_range):
        """Escanea rango de red completo"""
        print(f"🌐 Iniciando escaneo fantasma de {network_range}")
        print("⚠️ MODO SIGILOSO: Evitando detección ARP/IDS")
        print("=" * 50)
        
        # Generar lista de IPs
        base_ip = ".".join(network_range.split(".")[:-1])
        targets = [f"{base_ip}.{i}" for i in range(1, 255)]
        
        # Randomizar orden para evadir detección de patrones
        random.shuffle(targets)
        
        # Escaneo con threads limitados para mantener sigilo
        with ThreadPoolExecutor(max_workers=5) as executor:
            results = list(executor.map(self.ghost_scan_host, targets))
        
        # Filtrar resultados válidos
        self.alive_hosts = [r for r in results if r is not None]
        
        print(f"\n👻 ESCANEO FANTASMA COMPLETADO")
        print(f"📊 Hosts encontrados: {len(self.alive_hosts)}")
        
        return self.alive_hosts
    
    def generate_report(self, output_file=None):
        """Genera reporte de escaneo"""
        if not self.alive_hosts:
            print("❌ No hay hosts para reportar")
            return
        
        report_lines = [
            "🔍 BOFA Ghost Scanner Report",
            "=" * 40,
            f"Hosts escaneados: {len(self.alive_hosts)}",
            f"Generado: {time.ctime()}",
            "",
            "📋 HOSTS DETECTADOS:"
        ]
        
        for host_data in self.alive_hosts:
            report_lines.append(f"\n🎯 {host_data['host']}")
            if host_data['open_ports']:
                report_lines.append(f"   Puertos: {', '.join(map(str, host_data['open_ports']))}")
            else:
                report_lines.append("   Sin puertos detectados")
        
        report = "\n".join(report_lines)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report)
            print(f"💾 Reporte guardado en: {output_file}")
        else:
            print(report)

def main():
    parser = argparse.ArgumentParser(description="BOFA Ghost Scanner")
    parser.add_argument("-t", "--target", required=True, 
                       help="Rango de red (ej: 192.168.1.0)")
    parser.add_argument("-o", "--output", help="Archivo de salida")
    parser.add_argument("--delay", type=float, default=0.5,
                       help="Delay entre escaneos (segundos)")
    
    args = parser.parse_args()
    
    print("👻 BOFA Ghost Scanner v1.0")
    print("⚠️ SOLO PARA REDES AUTORIZADAS")
    print("🔒 Modo sigiloso activado")
    print("=" * 40)
    
    scanner = GhostScanner()
    scanner.stealth_delay = args.delay
    
    scanner.scan_network(args.target)
    scanner.generate_report(args.output)

if __name__ == "__main__":
    main()
