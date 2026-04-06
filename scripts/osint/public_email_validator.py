
#!/usr/bin/env python3
"""
Public Email Validator & Breach Checker
Desarrollado por @descambiado para BOFA v2.3.0
OSINT: Verifica emails con HaveIBeenPwned y valida dominios
"""

import requests
import argparse
import json
import time
import re
import dns.resolver
from datetime import datetime
import hashlib

from core import cooperative_sleep, raise_if_cancelled

class PublicEmailValidator:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.hibp_api_url = "https://haveibeenpwned.com/api/v3"
        self.session = requests.Session()
        self.results = []
        
    def print_banner(self):
        print("""
╔══════════════════════════════════════════════════════════════════╗
║              Public Email Validator & Breach Checker            ║
║                    HERRAMIENTA EDUCATIVA                         ║
║                   Por @descambiado - BOFA                       ║
╚══════════════════════════════════════════════════════════════════╝
        """)
        
    def validate_email_format(self, email):
        """Valida formato básico del email"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
        
    def check_domain_validity(self, domain):
        """Verifica si el dominio existe y tiene registros MX"""
        try:
            # Verificar registros MX
            mx_records = dns.resolver.resolve(domain, 'MX')
            mx_exists = len(mx_records) > 0
            
            # Verificar registro A
            try:
                a_records = dns.resolver.resolve(domain, 'A')
                a_exists = len(a_records) > 0
            except:
                a_exists = False
                
            return {
                "domain_exists": True,
                "mx_records": mx_exists,
                "a_records": a_exists,
                "mx_count": len(mx_records) if mx_exists else 0
            }
            
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] Error verificando dominio {domain}: {e}")
            return {
                "domain_exists": False,
                "mx_records": False,
                "a_records": False,
                "mx_count": 0
            }
            
    def simulate_hibp_check(self, email):
        """Simula verificación con HaveIBeenPwned (datos ficticios)"""
        print(f"[INFO] Simulando verificación HIBP para: {email}")
        print("⚠️  NOTA: Datos simulados - para uso real usar API de HIBP\n")
        
        # Hash SHA-1 del email para simular consulta real
        email_hash = hashlib.sha1(email.encode()).hexdigest()
        
        # Simular respuesta basada en hash (consistente)
        hash_mod = int(email_hash[-2:], 16) % 10
        
        if hash_mod < 3:  # 30% probabilidad de breach
            breaches = [
                {
                    "Name": "Adobe",
                    "Title": "Adobe",
                    "Domain": "adobe.com",
                    "BreachDate": "2013-10-04",
                    "AddedDate": "2013-12-04T00:00Z",
                    "ModifiedDate": "2022-05-15T23:52Z",
                    "PwnCount": 152445165,
                    "Description": "Simulated breach data for educational purposes",
                    "DataClasses": ["Email addresses", "Password hints", "Passwords", "Usernames"]
                }
            ]
            
            if hash_mod == 0:  # Casos más graves
                breaches.append({
                    "Name": "Collection1",
                    "Title": "Collection #1", 
                    "Domain": "",
                    "BreachDate": "2019-01-07",
                    "AddedDate": "2019-01-16T21:46Z",
                    "ModifiedDate": "2019-01-16T21:46Z",
                    "PwnCount": 772904991,
                    "Description": "Simulated collection breach for educational purposes",
                    "DataClasses": ["Email addresses", "Passwords"]
                })
                
            return breaches
        else:
            return []  # No breaches found
            
    def analyze_email_reputation(self, email):
        """Analiza reputación del email basado en dominio y patrones"""
        domain = email.split('@')[1]
        local_part = email.split('@')[0]
        
        reputation_score = 50  # Base score
        flags = []
        
        # Dominios comunes (más confiables)
        trusted_domains = ['gmail.com', 'outlook.com', 'yahoo.com', 'hotmail.com']
        if domain in trusted_domains:
            reputation_score += 20
            flags.append("TRUSTED_DOMAIN")
            
        # Dominios temporales/desechables (menos confiables)
        temp_domains = ['10minutemail.com', 'tempmail.org', 'guerrillamail.com']
        if domain in temp_domains:
            reputation_score -= 30
            flags.append("TEMP_EMAIL")
            
        # Patrones sospechosos en local part
        if len(local_part) < 3:
            reputation_score -= 10
            flags.append("SHORT_LOCAL")
            
        if re.match(r'^[a-z]+\d+$', local_part):
            reputation_score -= 5
            flags.append("PATTERN_SUSPICIOUS")
            
        if '.' in local_part and len(local_part.split('.')) > 3:
            reputation_score -= 5
            flags.append("MULTIPLE_DOTS")
            
        # Números excesivos
        if sum(c.isdigit() for c in local_part) > len(local_part) * 0.5:
            reputation_score -= 10
            flags.append("EXCESSIVE_NUMBERS")
            
        return {
            "reputation_score": max(0, min(100, reputation_score)),
            "flags": flags
        }
        
    def process_email(self, email):
        """Procesa un email completo"""
        print(f"[INFO] Procesando: {email}")
        
        result = {
            "email": email,
            "timestamp": datetime.now().isoformat(),
            "valid_format": False,
            "domain_info": {},
            "breaches": [],
            "reputation": {},
            "recommendations": []
        }
        
        # Validar formato
        if not self.validate_email_format(email):
            print(f"[ERROR] Formato de email inválido: {email}")
            return result
            
        result["valid_format"] = True
        domain = email.split('@')[1]
        
        # Verificar dominio
        print(f"[CHECK] Verificando dominio: {domain}")
        result["domain_info"] = self.check_domain_validity(domain)
        
        if not result["domain_info"]["domain_exists"]:
            print(f"[WARNING] Dominio no existe: {domain}")
            result["recommendations"].append("INVALID_DOMAIN")
            return result
            
        # Verificar breaches (simulado)
        print(f"[CHECK] Verificando breaches...")
        result["breaches"] = self.simulate_hibp_check(email)
        
        # Analizar reputación
        print(f"[CHECK] Analizando reputación...")
        result["reputation"] = self.analyze_email_reputation(email)
        
        # Generar recomendaciones
        if result["breaches"]:
            result["recommendations"].append("FOUND_IN_BREACHES")
        if result["reputation"]["reputation_score"] < 30:
            result["recommendations"].append("LOW_REPUTATION")
        if not result["domain_info"]["mx_records"]:
            result["recommendations"].append("NO_MX_RECORDS")
            
        return result
        
    def generate_report(self):
        """Genera reporte consolidado"""
        if not self.results:
            return
            
        print("\n" + "="*60)
        print("REPORTE DE VALIDACIÓN - EMAIL OSINT")
        print("="*60)
        
        total_emails = len(self.results)
        valid_emails = sum(1 for r in self.results if r["valid_format"])
        compromised_emails = sum(1 for r in self.results if r["breaches"])
        
        print(f"\n📊 RESUMEN GENERAL:")
        print(f"Emails procesados: {total_emails}")
        print(f"Emails válidos: {valid_emails}")
        print(f"Emails comprometidos: {compromised_emails}")
        
        if valid_emails > 0:
            avg_reputation = sum(r["reputation"]["reputation_score"] for r in self.results if r["valid_format"]) / valid_emails
            print(f"Reputación promedio: {avg_reputation:.1f}/100")
            
        print(f"\n🔍 EMAILS COMPROMETIDOS:")
        for result in self.results:
            if result["breaches"]:
                print(f"\n📧 {result['email']}")
                for breach in result["breaches"]:
                    print(f"  • {breach['Title']} ({breach['BreachDate']}) - {breach['PwnCount']:,} cuentas")
                    
        print(f"\n⚠️  RECOMENDACIONES:")
        all_recommendations = []
        for result in self.results:
            all_recommendations.extend(result["recommendations"])
            
        unique_recommendations = set(all_recommendations)
        for rec in unique_recommendations:
            count = all_recommendations.count(rec)
            print(f"  • {rec}: {count} email(s)")
            
    def export_results(self, filename=None):
        """Exporta resultados a JSON"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"email_validation_{timestamp}.json"
            
        with open(filename, "w", encoding="utf-8") as f:
            json.dump({
                "metadata": {
                    "tool": "BOFA Public Email Validator",
                    "processed_at": datetime.now().isoformat(),
                    "total_emails": len(self.results)
                },
                "results": self.results
            }, f, indent=2, ensure_ascii=False)
            
        print(f"[INFO] Resultados exportados a: {filename}")
        return filename
        
    def run(self, emails):
        """Ejecuta validación completa"""
        self.print_banner()
        
        print("⚠️  AVISO: Herramienta OSINT educativa")
        print("Usar solo con emails propios o con autorización\n")
        
        for email in emails:
            try:
                raise_if_cancelled()
                result = self.process_email(email.strip())
                self.results.append(result)
                
                if self.verbose:
                    status = "✅ VÁLIDO" if result["valid_format"] else "❌ INVÁLIDO"
                    breaches = f"🔴 {len(result['breaches'])} breaches" if result["breaches"] else "✅ Sin breaches"
                    print(f"[RESULT] {email} - {status} - {breaches}")
                    
                cooperative_sleep(1)  # Rate limiting
                
            except Exception as e:
                print(f"[ERROR] Error procesando {email}: {e}")
                
        self.generate_report()
        return True

def main():
    parser = argparse.ArgumentParser(description="Public Email Validator & Breach Checker")
    parser.add_argument("--emails", required=True, help="Email(s) a verificar (separados por espacios)")
    parser.add_argument("--output", help="Archivo de salida JSON")
    parser.add_argument("-v", "--verbose", action="store_true", help="Modo verbose")
    
    args = parser.parse_args()
    emails_list = args.emails.split()
    
    validator = PublicEmailValidator(args.verbose)
    
    try:
        success = validator.run(emails_list)
        
        if success and validator.results:
            validator.export_results(args.output)
            
    except KeyboardInterrupt:
        print("\n[INFO] Validación interrumpida por el usuario")
    except Exception as e:
        print(f"[ERROR] Error durante la ejecución: {e}")

if __name__ == "__main__":
    main()
