
#!/usr/bin/env python3
"""
SQL Injection Learning Script
Desarrollado por @descambiado para BOFA Study Mode
"""

import requests
import time
from colorama import Fore, Style, init

init(autoreset=True)

def print_banner():
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════╗
║                     SQL INJECTION TRAINER                       ║
║                    Modo Estudio - BOFA                          ║
╚══════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)

def basic_injection_demo():
    print(f"{Fore.YELLOW}📚 Demostración: Payloads básicos de SQL Injection{Style.RESET_ALL}")
    
    payloads = [
        "' OR 1=1--",
        "\" OR 1=1--", 
        "admin'--",
        "' UNION SELECT NULL,NULL--",
        "' AND 1=2 UNION SELECT username,password FROM users--"
    ]
    
    for i, payload in enumerate(payloads, 1):
        print(f"{Fore.GREEN}[{i}]{Fore.WHITE} Payload: {Fore.CYAN}{payload}{Style.RESET_ALL}")
        print(f"    Descripción: {get_payload_description(payload)}")
        time.sleep(2)

def get_payload_description(payload):
    descriptions = {
        "' OR 1=1--": "Bypass de autenticación básico",
        "\" OR 1=1--": "Bypass con comillas dobles",
        "admin'--": "Comentario de línea SQL",
        "' UNION SELECT NULL,NULL--": "Union-based SQLi básico",
        "' AND 1=2 UNION SELECT username,password FROM users--": "Extracción de datos"
    }
    return descriptions.get(payload, "Payload de inyección SQL")

def interactive_test():
    print(f"\n{Fore.YELLOW}🧪 Laboratorio Interactivo{Style.RESET_ALL}")
    print(f"{Fore.WHITE}Simularemos ataques contra una aplicación vulnerable...{Style.RESET_ALL}")
    
    # Simular aplicación vulnerable
    vulnerable_queries = [
        "SELECT * FROM users WHERE username = '{}' AND password = '{}'",
        "SELECT id,name FROM products WHERE category = '{}'",
        "SELECT * FROM news WHERE id = {}"
    ]
    
    for i, query in enumerate(vulnerable_queries, 1):
        print(f"\n{Fore.CYAN}Consulta {i}: {query}{Style.RESET_ALL}")
        user_input = input(f"{Fore.YELLOW}Introduce tu payload: {Style.RESET_ALL}")
        
        if user_input.strip():
            simulate_injection(query, user_input)
        else:
            print(f"{Fore.RED}❌ Payload vacío{Style.RESET_ALL}")

def simulate_injection(query, payload):
    print(f"{Fore.MAGENTA}🔍 Ejecutando: {query.format(payload)}{Style.RESET_ALL}")
    
    # Simular respuesta según el payload
    if "OR 1=1" in payload:
        print(f"{Fore.GREEN}✅ Éxito: Bypass de autenticación logrado{Style.RESET_ALL}")
    elif "UNION" in payload.upper():
        print(f"{Fore.GREEN}✅ Éxito: Union-based injection detectado{Style.RESET_ALL}")
        print(f"{Fore.CYAN}📊 Datos extraídos: admin:hash123, user:hash456{Style.RESET_ALL}")
    elif "--" in payload:
        print(f"{Fore.YELLOW}⚠️  Comentario SQL detectado{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}❌ Payload no efectivo{Style.RESET_ALL}")

def prevention_tips():
    print(f"\n{Fore.YELLOW}🛡️  Consejos de Prevención:{Style.RESET_ALL}")
    tips = [
        "Usar prepared statements/parameterized queries",
        "Validar y sanitizar todas las entradas",
        "Implementar un WAF (Web Application Firewall)",
        "Aplicar el principio de menor privilegio en la DB",
        "Realizar auditorías de código regulares"
    ]
    
    for i, tip in enumerate(tips, 1):
        print(f"{Fore.GREEN}[{i}]{Fore.WHITE} {tip}{Style.RESET_ALL}")
        time.sleep(1)

def main():
    print_banner()
    
    print(f"{Fore.CYAN}🎓 Iniciando lección de SQL Injection...{Style.RESET_ALL}")
    time.sleep(2)
    
    basic_injection_demo()
    interactive_test()
    prevention_tips()
    
    print(f"\n{Fore.CYAN}🎉 ¡Lección completada!{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}📈 Has ganado 100 puntos de estudio{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
