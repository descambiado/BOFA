
#!/usr/bin/env python3
"""
Telegram User Scraper (Public Groups)
Desarrollado por @descambiado para BOFA v2.3.0
OSINT: Extrae información de usuarios de grupos públicos de Telegram
"""

import asyncio
import argparse
import json
import csv
import sys
from datetime import datetime
import re

# Nota: En una implementación real se usaría telethon
# Para la simulación educativa, usamos datos mock

class TelegramUserScraper:
    def __init__(self, api_id=None, api_hash=None, phone=None, verbose=False):
        self.api_id = api_id
        self.api_hash = api_hash
        self.phone = phone
        self.verbose = verbose
        self.scraped_users = []
        
    def print_banner(self):
        print("""
╔══════════════════════════════════════════════════════════════════╗
║                Telegram User Scraper (OSINT)                    ║
║                    HERRAMIENTA EDUCATIVA                         ║
║                   Por @descambiado - BOFA                       ║
╚══════════════════════════════════════════════════════════════════╝
        """)
        
    def validate_group_url(self, group_url):
        """Valida formato de URL de grupo de Telegram"""
        patterns = [
            r'^https://t\.me/[a-zA-Z0-9_]+$',
            r'^@[a-zA-Z0-9_]+$',
            r'^[a-zA-Z0-9_]+$'
        ]
        
        for pattern in patterns:
            if re.match(pattern, group_url):
                return True
                
        return False
        
    async def simulate_group_scraping(self, group_identifier):
        """Simula scraping de grupo público de Telegram"""
        print(f"[INFO] Simulando scraping del grupo: {group_identifier}")
        print("⚠️  NOTA: Esta es una simulación con datos ficticios\n")
        
        # Datos simulados de usuarios ficticios
        simulated_users = [
            {
                "id": 123456789,
                "username": "user_example1",
                "first_name": "John",
                "last_name": "Doe",
                "phone": None,
                "is_bot": False,
                "is_verified": False,
                "is_premium": False,
                "last_seen": "recently",
                "bio": "Crypto enthusiast",
                "profile_photo": True
            },
            {
                "id": 987654321,
                "username": "crypto_trader_pro",
                "first_name": "Alice",
                "last_name": "Smith",
                "phone": None,
                "is_bot": False,
                "is_verified": True,
                "is_premium": True,
                "last_seen": "within_week",
                "bio": "Professional trader | DM for signals",
                "profile_photo": True
            },
            {
                "id": 456789123,
                "username": None,
                "first_name": "Anonymous",
                "last_name": "User",
                "phone": None,
                "is_bot": False,
                "is_verified": False,
                "is_premium": False,
                "last_seen": "long_time_ago",
                "bio": "",
                "profile_photo": False
            },
            {
                "id": 789123456,
                "username": "bot_helper",
                "first_name": "Helper",
                "last_name": "Bot",
                "phone": None,
                "is_bot": True,
                "is_verified": True,
                "is_premium": False,
                "last_seen": "online",
                "bio": "Automated helper bot for the group",
                "profile_photo": True
            }
        ]
        
        print("[INFO] Procesando usuarios del grupo...")
        
        for i, user in enumerate(simulated_users):
            # Simular delay de API
            await asyncio.sleep(0.5)
            
            # Añadir metadatos de scraping
            user["scraped_at"] = datetime.now().isoformat()
            user["group_source"] = group_identifier
            user["privacy_score"] = self.calculate_privacy_score(user)
            
            self.scraped_users.append(user)
            
            if self.verbose:
                username_display = user["username"] or "[Sin username]"
                print(f"[SCRAPED] {i+1}/4 - {username_display} ({user['first_name']})")
                
        return len(simulated_users)
        
    def calculate_privacy_score(self, user):
        """Calcula puntuación de privacidad del usuario"""
        score = 0
        
        # Factores que reducen privacidad
        if user["username"]:
            score += 2
        if user["last_name"]:
            score += 1
        if user["bio"]:
            score += 1
        if user["profile_photo"]:
            score += 1
        if user["is_verified"]:
            score += 1
            
        # Factores que aumentan privacidad
        if not user["username"]:
            score -= 2
        if user["last_seen"] == "long_time_ago":
            score -= 1
            
        return max(0, min(10, score))
        
    def analyze_users(self):
        """Analiza usuarios scrapeados"""
        if not self.scraped_users:
            return
            
        print("\n[INFO] Analizando usuarios scrapeados...")
        
        analysis = {
            "total_users": len(self.scraped_users),
            "users_with_username": sum(1 for u in self.scraped_users if u["username"]),
            "verified_users": sum(1 for u in self.scraped_users if u["is_verified"]),
            "premium_users": sum(1 for u in self.scraped_users if u["is_premium"]),
            "bots": sum(1 for u in self.scraped_users if u["is_bot"]),
            "users_with_bio": sum(1 for u in self.scraped_users if u["bio"]),
            "avg_privacy_score": sum(u["privacy_score"] for u in self.scraped_users) / len(self.scraped_users)
        }
        
        return analysis
        
    def export_results(self, format_type="json", filename=None):
        """Exporta resultados en formato especificado"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"telegram_scraping_{timestamp}"
            
        if format_type == "json":
            filename += ".json"
            with open(filename, "w", encoding="utf-8") as f:
                json.dump({
                    "metadata": {
                        "scraped_at": datetime.now().isoformat(),
                        "tool": "BOFA Telegram User Scraper",
                        "total_users": len(self.scraped_users)
                    },
                    "users": self.scraped_users
                }, f, indent=2, ensure_ascii=False)
                
        elif format_type == "csv":
            filename += ".csv"
            with open(filename, "w", newline="", encoding="utf-8") as f:
                if self.scraped_users:
                    writer = csv.DictWriter(f, fieldnames=self.scraped_users[0].keys())
                    writer.writeheader()
                    writer.writerows(self.scraped_users)
                    
        print(f"[INFO] Resultados exportados a: {filename}")
        return filename
        
    def generate_report(self, analysis):
        """Genera reporte de análisis"""
        print("\n" + "="*60)
        print("REPORTE DE SCRAPING - TELEGRAM OSINT")
        print("="*60)
        
        print(f"\n📊 ESTADÍSTICAS GENERALES:")
        print(f"Total de usuarios: {analysis['total_users']}")
        print(f"Usuarios con username: {analysis['users_with_username']} ({analysis['users_with_username']/analysis['total_users']*100:.1f}%)")
        print(f"Usuarios verificados: {analysis['verified_users']}")
        print(f"Usuarios premium: {analysis['premium_users']}")
        print(f"Bots detectados: {analysis['bots']}")
        print(f"Usuarios con biografía: {analysis['users_with_bio']}")
        print(f"Puntuación promedio de privacidad: {analysis['avg_privacy_score']:.1f}/10")
        
        print(f"\n🔍 HALLAZGOS OSINT:")
        high_value_targets = [u for u in self.scraped_users if u["privacy_score"] >= 4 and not u["is_bot"]]
        print(f"Usuarios de alto valor OSINT: {len(high_value_targets)}")
        
        for user in high_value_targets:
            username_display = user["username"] or "[Sin username público]"
            print(f"  • {username_display} - Privacy Score: {user['privacy_score']}")
            
        print(f"\n⚠️  CONSIDERACIONES ÉTICAS:")
        print("- Información obtenida de grupos públicos únicamente")
        print("- Respetar términos de servicio de Telegram")
        print("- No usar para acoso o actividades maliciosas")
        print("- Considerar normativas de protección de datos")
        
    async def run(self, group_identifier):
        """Ejecuta el scraping completo"""
        self.print_banner()
        
        print("⚠️  AVISO: Esta herramienta es para OSINT educativo")
        print("Solo usar en grupos públicos y con fines legítimos\n")
        
        if not self.validate_group_url(group_identifier):
            print(f"[ERROR] Formato de grupo inválido: {group_identifier}")
            print("Formatos válidos: @username, https://t.me/username, username")
            return False
            
        try:
            users_found = await self.simulate_group_scraping(group_identifier)
            analysis = self.analyze_users()
            self.generate_report(analysis)
            
            return True
            
        except Exception as e:
            print(f"[ERROR] Error durante el scraping: {e}")
            return False

def main():
    parser = argparse.ArgumentParser(description="Telegram User Scraper (OSINT)")
    parser.add_argument("--group", required=True, help="Identificador del grupo (@username, URL, o username)")
    parser.add_argument("--api-id", help="API ID de Telegram (para implementación real)")
    parser.add_argument("--api-hash", help="API Hash de Telegram (para implementación real)")
    parser.add_argument("--phone", help="Número de teléfono (para implementación real)")
    parser.add_argument("--export", choices=["json", "csv"], default="json", help="Formato de exportación")
    parser.add_argument("--output", help="Archivo de salida")
    parser.add_argument("-v", "--verbose", action="store_true", help="Modo verbose")
    
    args = parser.parse_args()
    
    print("📝 NOTA: Esta es una versión educativa con datos simulados")
    print("Para uso real, implementar con telethon y credenciales API válidas\n")
    
    scraper = TelegramUserScraper(
        args.api_id, 
        args.api_hash, 
        args.phone, 
        args.verbose
    )
    
    try:
        success = asyncio.run(scraper.run(args.group))
        
        if success and scraper.scraped_users:
            scraper.export_results(args.export, args.output)
            
    except KeyboardInterrupt:
        print("\n[INFO] Scraping interrumpido por el usuario")
    except Exception as e:
        print(f"[ERROR] Error durante la ejecución: {e}")

if __name__ == "__main__":
    main()
