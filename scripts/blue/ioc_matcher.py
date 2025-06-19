
#!/usr/bin/env python3
"""
IOC Matcher - BOFA Blue Team Module
Comparación local con Indicators of Compromise
"""

import json
import re
import hashlib
import argparse
import requests
import os
from datetime import datetime
import ipaddress

class IOCMatcher:
    def __init__(self):
        self.iocs = {
            'ips': [],
            'domains': [],
            'hashes': [],
            'urls': [],
            'email_addresses': [],
            'file_paths': []
        }
        self.matches = []
        self.output_dir = "output/ioc_analysis"
        
    def create_output_dir(self):
        os.makedirs(self.output_dir, exist_ok=True)
        
    def load_default_iocs(self):
        """Carga IOCs de ejemplo para demostración"""
        self.iocs = {
            'ips': [
                '192.168.1.666',  # IP sospechosa ficticia
                '10.0.0.666',
                '172.16.1.666',
                '185.220.101.15',  # Ejemplo Tor exit node
                '198.96.155.3'
            ],
            'domains': [
                'malware-example.com',
                'phishing-test.org',
                'c2-server.net',
                'suspicious-domain.tk',
                'fake-bank.xyz'
            ],
            'hashes': [
                'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3',  # SHA256 ejemplo
                '5d41402abc4b2a76b9719d911017c592',  # MD5 ejemplo
                'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d'  # SHA1 ejemplo
            ],
            'urls': [
                'http://malware-download.com/payload.exe',
                'https://phishing-site.com/login',
                'http://c2-command.net/beacon'
            ],
            'email_addresses': [
                'phishing@fake-bank.com',
                'malware@suspicious-domain.tk',
                'spam@malicious-sender.org'
            ],
            'file_paths': [
                'C:\\Windows\\Temp\\malware.exe',
                '/tmp/.hidden_backdoor',
                'C:\\Users\\Public\\payload.bat'
            ]
        }
    
    def load_iocs_from_file(self, filename):
        """Carga IOCs desde archivo JSON"""
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
                self.iocs.update(data)
            print(f"[+] IOCs cargados desde {filename}")
        except Exception as e:
            print(f"[!] Error cargando IOCs: {e}")
    
    def download_threat_feed(self, feed_url):
        """Descarga feed de amenazas (simulado)"""
        print(f"[+] Descargando feed desde {feed_url}")
        
        # Simulación - en un caso real se descargaría de feeds como:
        # - MISP
        # - AlienVault OTX
        # - VirusTotal
        # - Abuse.ch
        
        simulated_feed = {
            'ips': ['1.2.3.4', '5.6.7.8'],
            'domains': ['evil.com', 'malware.net'],
            'hashes': ['abc123def456', '789ghi012jkl']
        }
        
        for category, items in simulated_feed.items():
            if category in self.iocs:
                self.iocs[category].extend(items)
        
        print(f"[+] Feed actualizado con {sum(len(v) for v in simulated_feed.values())} IOCs")
    
    def scan_text_for_iocs(self, text):
        """Busca IOCs en texto dado"""
        print("[+] Analizando texto en busca de IOCs...")
        
        # Buscar IPs
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        found_ips = re.findall(ip_pattern, text)
        
        for ip in found_ips:
            if ip in self.iocs['ips']:
                self.matches.append({
                    'type': 'ip',
                    'value': ip,
                    'context': 'text_analysis',
                    'timestamp': datetime.now().isoformat()
                })
        
        # Buscar dominios
        domain_pattern = r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z]{2,6})\b'
        found_domains = re.findall(domain_pattern, text)
        
        for domain_match in found_domains:
            domain = '.'.join(domain_match)
            if domain in self.iocs['domains']:
                self.matches.append({
                    'type': 'domain',
                    'value': domain,
                    'context': 'text_analysis',
                    'timestamp': datetime.now().isoformat()
                })
        
        # Buscar emails
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        found_emails = re.findall(email_pattern, text)
        
        for email in found_emails:
            if email in self.iocs['email_addresses']:
                self.matches.append({
                    'type': 'email',
                    'value': email,
                    'context': 'text_analysis',
                    'timestamp': datetime.now().isoformat()
                })
        
        # Buscar URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        found_urls = re.findall(url_pattern, text)
        
        for url in found_urls:
            if url in self.iocs['urls']:
                self.matches.append({
                    'type': 'url',
                    'value': url,
                    'context': 'text_analysis',
                    'timestamp': datetime.now().isoformat()
                })
    
    def scan_file_for_hashes(self, filepath):
        """Calcula hashes de archivo y compara con IOCs"""
        if not os.path.exists(filepath):
            print(f"[!] Archivo no encontrado: {filepath}")
            return
        
        print(f"[+] Calculando hashes para {filepath}")
        
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
                
                # Calcular diferentes hashes
                md5_hash = hashlib.md5(content).hexdigest()
                sha1_hash = hashlib.sha1(content).hexdigest()
                sha256_hash = hashlib.sha256(content).hexdigest()
                
                hashes = [md5_hash, sha1_hash, sha256_hash]
                
                for hash_value in hashes:
                    if hash_value in self.iocs['hashes']:
                        self.matches.append({
                            'type': 'hash',
                            'value': hash_value,
                            'context': f'file_hash:{filepath}',
                            'timestamp': datetime.now().isoformat()
                        })
                
                print(f"[+] MD5: {md5_hash}")
                print(f"[+] SHA1: {sha1_hash}")
                print(f"[+] SHA256: {sha256_hash}")
                
        except Exception as e:
            print(f"[!] Error calculando hashes: {e}")
    
    def scan_log_file(self, log_file):
        """Escanea archivo de log en busca de IOCs"""
        if not os.path.exists(log_file):
            print(f"[!] Log file no encontrado: {log_file}")
            return
        
        print(f"[+] Escaneando log file: {log_file}")
        
        try:
            with open(log_file, 'r') as f:
                content = f.read()
                self.scan_text_for_iocs(content)
                
        except Exception as e:
            print(f"[!] Error leyendo log file: {e}")
    
    def generate_ioc_report(self):
        """Genera reporte de matches encontrados"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_iocs_loaded': sum(len(v) for v in self.iocs.values()),
            'total_matches': len(self.matches),
            'matches_by_type': {},
            'matches': self.matches,
            'iocs_summary': {k: len(v) for k, v in self.iocs.items()},
            'recommendations': []
        }
        
        # Agrupar matches por tipo
        for match in self.matches:
            match_type = match['type']
            if match_type not in report['matches_by_type']:
                report['matches_by_type'][match_type] = 0
            report['matches_by_type'][match_type] += 1
        
        # Generar recomendaciones
        if report['total_matches'] > 0:
            report['recommendations'].extend([
                "Investigar inmediatamente todos los IOCs encontrados",
                "Verificar contexto y legitimidad de los matches",
                "Implementar bloqueo preventivo si se confirma malware",
                "Revisar logs adicionales para actividad relacionada"
            ])
        else:
            report['recommendations'].append("No se encontraron IOCs conocidos en el análisis")
        
        # Guardar reporte
        report_file = os.path.join(self.output_dir, f"ioc_analysis_{int(datetime.now().timestamp())}.json")
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Reporte guardado en: {report_file}")
        return report_file
    
    def print_summary(self):
        """Imprime resumen de análisis"""
        print("\n" + "="*50)
        print("IOC ANALYSIS SUMMARY")
        print("="*50)
        print(f"IOCs cargados: {sum(len(v) for v in self.iocs.values())}")
        print(f"Matches encontrados: {len(self.matches)}")
        
        if self.matches:
            print("\nMATCHES DETECTADOS:")
            for match in self.matches:
                print(f"  [{match['type'].upper()}] {match['value']} ({match['context']})")
        else:
            print("\n[✓] No se encontraron IOCs maliciosos")

def main():
    parser = argparse.ArgumentParser(description="IOC Matcher - Análisis de Indicadores de Compromiso")
    parser.add_argument("-f", "--file", help="Archivo para escanear hashes")
    parser.add_argument("-l", "--log", help="Log file para analizar")
    parser.add_argument("-t", "--text", help="Texto para analizar")
    parser.add_argument("--iocs", help="Archivo JSON con IOCs personalizados")
    parser.add_argument("--feed", help="URL de threat feed (simulado)")
    parser.add_argument("-o", "--output", help="Directorio de salida")
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("🔵 BOFA IOC Matcher")
    print("Análisis de Indicadores de Compromiso")
    print("=" * 60)
    
    matcher = IOCMatcher()
    
    if args.output:
        matcher.output_dir = args.output
    matcher.create_output_dir()
    
    # Cargar IOCs
    if args.iocs:
        matcher.load_iocs_from_file(args.iocs)
    else:
        matcher.load_default_iocs()
    
    # Descargar feed si se especifica
    if args.feed:
        matcher.download_threat_feed(args.feed)
    
    # Realizar análisis según parámetros
    if args.file:
        matcher.scan_file_for_hashes(args.file)
    
    if args.log:
        matcher.scan_log_file(args.log)
    
    if args.text:
        matcher.scan_text_for_iocs(args.text)
    
    # Si no se especifica nada, hacer análisis de ejemplo
    if not any([args.file, args.log, args.text]):
        print("[+] Ejecutando análisis de ejemplo...")
        example_text = """
        Connection established to 185.220.101.15:8080
        Downloading from http://malware-download.com/payload.exe
        Email received from phishing@fake-bank.com
        Suspicious domain resolved: c2-server.net
        """
        matcher.scan_text_for_iocs(example_text)
    
    # Generar reporte y mostrar resumen
    matcher.generate_ioc_report()
    matcher.print_summary()

if __name__ == "__main__":
    main()
