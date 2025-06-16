
#!/usr/bin/env python3
"""
Web Discover - Subdomain and Web Service Discovery Tool
Author: @descambiado (David Hernández Jiménez)
BOFA - Best Of All Cybersecurity Suite
Educational/Professional Use Only
"""

import requests
import socket
import argparse
import sys
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import time

class WebDiscover:
    def __init__(self, target_domain, timeout=5, threads=50):
        self.target_domain = target_domain
        self.timeout = timeout
        self.threads = threads
        self.found_subdomains = []
        
        # Common subdomain wordlist
        self.subdomains = [
            'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2',
            'smtp', 'secure', 'vpn', 'admin', 'portal', 'api', 'app', 'dev',
            'test', 'staging', 'demo', 'shop', 'store', 'ftp', 'cpanel',
            'whm', 'webdisk', 'mx', 'pop', 'imap', 'cloud', 'support'
        ]
    
    def check_subdomain(self, subdomain):
        """Verifica si un subdominio existe y es accesible via HTTP/HTTPS"""
        full_domain = f"{subdomain}.{self.target_domain}"
        
        try:
            # Verificar resolución DNS
            socket.gethostbyname(full_domain)
            
            # Probar HTTP y HTTPS
            protocols = ['http', 'https']
            results = []
            
            for protocol in protocols:
                url = f"{protocol}://{full_domain}"
                try:
                    response = requests.get(url, timeout=self.timeout, verify=False, 
                                          allow_redirects=True)
                    
                    result = {
                        'subdomain': full_domain,
                        'url': url,
                        'status_code': response.status_code,
                        'title': self.extract_title(response.text),
                        'server': response.headers.get('Server', 'Unknown'),
                        'content_length': len(response.content)
                    }
                    results.append(result)
                    
                except requests.exceptions.RequestException:
                    continue
            
            return results
            
        except socket.gaierror:
            return []
    
    def extract_title(self, html_content):
        """Extrae el título de la página HTML"""
        try:
            start = html_content.lower().find('<title>')
            if start != -1:
                start += 7
                end = html_content.lower().find('</title>', start)
                if end != -1:
                    return html_content[start:end].strip()
        except:
            pass
        return "No title found"
    
    def scan_subdomains(self):
        """Escanea todos los subdominios usando hilos múltiples"""
        print(f"🔍 Iniciando escaneo de subdominios para {self.target_domain}")
        print(f"⚙️  Usando {self.threads} hilos, timeout {self.timeout}s")
        print("-" * 60)
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_subdomain = {
                executor.submit(self.check_subdomain, sub): sub 
                for sub in self.subdomains
            }
            
            for future in as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                try:
                    results = future.result()
                    if results:
                        for result in results:
                            self.found_subdomains.append(result)
                            print(f"✅ {result['subdomain']} - {result['status_code']} - {result['server']}")
                except Exception as e:
                    continue
    
    def generate_report(self, output_format='json'):
        """Genera reporte de resultados"""
        if output_format == 'json':
            return json.dumps(self.found_subdomains, indent=2)
        else:
            report = f"\n📊 REPORTE WEB DISCOVER - {self.target_domain}\n"
            report += "=" * 50 + "\n"
            report += f"Total subdominios encontrados: {len(self.found_subdomains)}\n\n"
            
            for result in self.found_subdomains:
                report += f"🌐 {result['subdomain']}\n"
                report += f"   URL: {result['url']}\n"
                report += f"   Estado: {result['status_code']}\n"
                report += f"   Servidor: {result['server']}\n"
                report += f"   Título: {result['title']}\n"
                report += f"   Tamaño: {result['content_length']} bytes\n"
                report += "-" * 30 + "\n"
            
            return report

def main():
    parser = argparse.ArgumentParser(
        description="Web Discover - Herramienta de descubrimiento web y subdominios",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  python3 web_discover.py -d example.com
  python3 web_discover.py -d target.com -t 10 --threads 100
  python3 web_discover.py -d example.com -o results.json --format json
        """
    )
    
    parser.add_argument('-d', '--domain', required=True, 
                       help='Dominio objetivo para escanear')
    parser.add_argument('-t', '--timeout', type=int, default=5,
                       help='Timeout para conexiones (default: 5s)')
    parser.add_argument('--threads', type=int, default=50,
                       help='Número de hilos (default: 50)')
    parser.add_argument('-o', '--output', 
                       help='Archivo de salida para guardar resultados')
    parser.add_argument('--format', choices=['json', 'text'], default='text',
                       help='Formato de salida (default: text)')
    
    args = parser.parse_args()
    
    # Banner
    print("\n🛡️  BOFA - Web Discover v1.0")
    print("Desarrollado por @descambiado")
    print("=" * 40)
    
    try:
        scanner = WebDiscover(args.domain, args.timeout, args.threads)
        scanner.scan_subdomains()
        
        # Generar reporte
        report = scanner.generate_report(args.format)
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(report)
            print(f"\n💾 Resultados guardados en: {args.output}")
        else:
            print(report)
            
    except KeyboardInterrupt:
        print("\n⚠️  Escaneo interrumpido por el usuario")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
