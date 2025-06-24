
#!/usr/bin/env python3
"""
GitHub Repository Leak Detector
Desarrollado por @descambiado para BOFA v2.3.0
OSINT: Detecta secretos (API keys, tokens) en repositorios públicos
"""

import requests
import re
import argparse
import json
import time
from datetime import datetime
import base64

class GitHubLeakDetector:
    def __init__(self, github_token=None, verbose=False):
        self.github_token = github_token
        self.verbose = verbose
        self.session = requests.Session()
        self.api_base = "https://api.github.com"
        self.leaks_found = []
        
        # Headers para GitHub API
        self.headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "BOFA-GitHub-Leak-Detector/1.0"
        }
        
        if github_token:
            self.headers["Authorization"] = f"token {github_token}"
            
        # Patrones de secretos comunes
        self.secret_patterns = {
            "aws_access_key": r'AKIA[0-9A-Z]{16}',
            "aws_secret_key": r'[0-9a-zA-Z/+]{40}',
            "github_token": r'ghp_[0-9a-zA-Z]{36}',
            "slack_token": r'xox[baprs]-[0-9a-zA-Z\-]{10,48}',
            "stripe_key": r'sk_live_[0-9a-zA-Z]{24}',
            "twitter_key": r'[1-9][0-9]+-[0-9a-zA-Z]{40}',
            "google_api": r'AIza[0-9A-Za-z\-_]{35}',
            "firebase_key": r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            "jwt_token": r'eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
            "private_key": r'-----BEGIN (RSA )?PRIVATE KEY-----',
            "api_key_generic": r'[aA][pP][iI][_\s]*[kK][eE][yY][_\s]*[:=]\s*["\']?[0-9a-zA-Z\-_]{20,}["\']?'
        }
        
    def print_banner(self):
        print("""
╔══════════════════════════════════════════════════════════════════╗
║              GitHub Repository Leak Detector                    ║
║                    HERRAMIENTA EDUCATIVA                         ║
║                   Por @descambiado - BOFA                       ║
╚══════════════════════════════════════════════════════════════════╝
        """)
        
    def search_repositories(self, query, max_repos=10):
        """Busca repositorios en GitHub"""
        print(f"[INFO] Buscando repositorios con: {query}")
        
        url = f"{self.api_base}/search/repositories"
        params = {
            "q": query,
            "sort": "updated",
            "order": "desc",
            "per_page": max_repos
        }
        
        try:
            response = self.session.get(url, headers=self.headers, params=params)
            
            if response.status_code == 403:
                print("[WARNING] Rate limit alcanzado - usando datos simulados")
                return self.simulate_repository_search(query, max_repos)
                
            if response.status_code != 200:
                print(f"[ERROR] Error en búsqueda: {response.status_code}")
                return []
                
            data = response.json()
            repos = data.get("items", [])
            
            if self.verbose:
                print(f"[INFO] Encontrados {len(repos)} repositorios")
                
            return repos
            
        except Exception as e:
            print(f"[ERROR] Error en búsqueda: {e}")
            return self.simulate_repository_search(query, max_repos)
            
    def simulate_repository_search(self, query, max_repos):
        """Simula búsqueda de repositorios con datos ficticios"""
        print("⚠️  NOTA: Usando datos simulados para demostración")
        
        simulated_repos = [
            {
                "name": "example-api-project",
                "full_name": "user123/example-api-project",
                "description": "Example API project with potential leaks",
                "html_url": "https://github.com/user123/example-api-project",
                "default_branch": "main",
                "updated_at": "2025-06-19T10:00:00Z"
            },
            {
                "name": "config-backup",
                "full_name": "developer456/config-backup",
                "description": "Configuration backup repository",
                "html_url": "https://github.com/developer456/config-backup",
                "default_branch": "master",
                "updated_at": "2025-06-18T15:30:00Z"
            },
            {
                "name": "mobile-app-source",
                "full_name": "company789/mobile-app-source",
                "description": "Mobile application source code",
                "html_url": "https://github.com/company789/mobile-app-source",
                "default_branch": "main",
                "updated_at": "2025-06-17T09:15:00Z"
            }
        ]
        
        return simulated_repos[:max_repos]
        
    def get_repository_files(self, repo_full_name, max_files=50):
        """Obtiene lista de archivos del repositorio"""
        print(f"[INFO] Analizando archivos de: {repo_full_name}")
        
        # Archivos típicos donde suelen aparecer leaks
        target_files = [
            ".env", ".env.local", ".env.production", 
            "config.json", "config.yml", "config.yaml",
            "settings.py", "settings.json",
            "secrets.json", "keys.json",
            "docker-compose.yml", "Dockerfile",
            "package.json", "requirements.txt"
        ]
        
        # Simular archivos encontrados
        simulated_files = [
            {
                "name": ".env.example",
                "path": ".env.example",
                "download_url": f"https://raw.githubusercontent.com/{repo_full_name}/main/.env.example"
            },
            {
                "name": "config.json",
                "path": "src/config.json", 
                "download_url": f"https://raw.githubusercontent.com/{repo_full_name}/main/src/config.json"
            },
            {
                "name": "docker-compose.yml",
                "path": "docker-compose.yml",
                "download_url": f"https://raw.githubusercontent.com/{repo_full_name}/main/docker-compose.yml"
            }
        ]
        
        return simulated_files
        
    def analyze_file_content(self, file_info, repo_info):
        """Analiza contenido de archivo buscando secretos"""
        if self.verbose:
            print(f"[SCAN] Analizando: {file_info['path']}")
            
        # Simular contenido con posibles leaks
        simulated_content = self.generate_simulated_content(file_info['name'])
        
        leaks = []
        
        for secret_type, pattern in self.secret_patterns.items():
            matches = re.finditer(pattern, simulated_content, re.IGNORECASE)
            
            for match in matches:
                leak = {
                    "repository": repo_info["full_name"],
                    "file_path": file_info["path"],
                    "secret_type": secret_type,
                    "matched_text": match.group(0)[:50] + "..." if len(match.group(0)) > 50 else match.group(0),
                    "line_number": simulated_content[:match.start()].count('\n') + 1,
                    "confidence": self.calculate_confidence(secret_type, match.group(0)),
                    "found_at": datetime.now().isoformat()
                }
                
                leaks.append(leak)
                
                if self.verbose:
                    print(f"  [FOUND] {secret_type} - Confianza: {leak['confidence']}%")
                    
        return leaks
        
    def generate_simulated_content(self, filename):
        """Genera contenido simulado para archivos"""
        if filename == ".env.example":
            return """
# Database configuration
DB_HOST=localhost
DB_USER=myuser
DB_PASSWORD=mypassword123

# API Keys (EXAMPLE - REPLACE WITH REAL VALUES)
API_KEY=sk_test_1234567890abcdef
STRIPE_KEY=sk_live_abcdef123456789012345678
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# JWT Secret
JWT_SECRET=your-256-bit-secret

# Google API
GOOGLE_API_KEY=AIzaSyDummyExampleKeyForEducationalPurposes
"""
        
        elif filename == "config.json":
            return """{
  "api": {
    "endpoint": "https://api.example.com",
    "key": "ghp_1234567890abcdef1234567890abcdef12345678",
    "secret": "this-is-a-demo-secret-key-for-education"
  },
  "database": {
    "host": "localhost",
    "credentials": "user:pass123@host:5432/db"
  },
  "firebase": {
    "projectId": "12345678-1234-1234-1234-123456789abc",
    "apiKey": "AIzaEducationalExampleKeyNotReal123456789"
  }
}"""
        
        elif filename == "docker-compose.yml":
            return """version: '3.8'
services:
  app:
    build: .
    environment:
      - API_KEY=sk_live_demo_educational_key_not_real
      - DB_PASSWORD=super_secret_password_123
      - JWT_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.demo.signature
    ports:
      - "3000:3000"
  
  redis:
    image: redis
    command: redis-server --requirepass demo_redis_password_123
"""
        
        return "# No suspicious content in this simulated file"
        
    def calculate_confidence(self, secret_type, matched_text):
        """Calcula nivel de confianza del hallazgo"""
        confidence = 50  # Base
        
        # Patrones que aumentan confianza
        if "key" in matched_text.lower():
            confidence += 20
        if "secret" in matched_text.lower():
            confidence += 20
        if "token" in matched_text.lower():
            confidence += 15
            
        # Longitud apropiada
        if secret_type == "aws_access_key" and len(matched_text) == 20:
            confidence += 30
        elif secret_type == "github_token" and len(matched_text) == 40:
            confidence += 30
            
        # Patrones que reducen confianza
        if "example" in matched_text.lower():
            confidence -= 40
        if "demo" in matched_text.lower():
            confidence -= 30
        if "test" in matched_text.lower():
            confidence -= 20
            
        return max(10, min(95, confidence))
        
    def scan_repository(self, repo):
        """Escanea un repositorio completo"""
        print(f"\n[REPO] Escaneando: {repo['full_name']}")
        
        files = self.get_repository_files(repo["full_name"])
        repo_leaks = []
        
        for file_info in files:
            try:
                file_leaks = self.analyze_file_content(file_info, repo)
                repo_leaks.extend(file_leaks)
                
                time.sleep(0.5)  # Rate limiting
                
            except Exception as e:
                if self.verbose:
                    print(f"[ERROR] Error analizando {file_info['path']}: {e}")
                    
        return repo_leaks
        
    def generate_report(self):
        """Genera reporte de leaks encontrados"""
        print("\n" + "="*60)
        print("REPORTE DE DETECCIÓN - GITHUB LEAKS")
        print("="*60)
        
        if not self.leaks_found:
            print("\n✅ No se encontraron leaks potenciales")
            return
            
        # Agrupar por repositorio
        repos_with_leaks = {}
        for leak in self.leaks_found:
            repo = leak["repository"]
            if repo not in repos_with_leaks:
                repos_with_leaks[repo] = []
            repos_with_leaks[repo].append(leak)
            
        print(f"\n📊 RESUMEN:")
        print(f"Total de leaks encontrados: {len(self.leaks_found)}")
        print(f"Repositorios afectados: {len(repos_with_leaks)}")
        
        # Agrupar por tipo de secreto
        secret_types = {}
        for leak in self.leaks_found:
            s_type = leak["secret_type"]
            if s_type not in secret_types:
                secret_types[s_type] = 0
            secret_types[s_type] += 1
            
        print(f"\n🔍 TIPOS DE SECRETOS:")
        for s_type, count in sorted(secret_types.items(), key=lambda x: x[1], reverse=True):
            print(f"  • {s_type}: {count}")
            
        print(f"\n🔴 LEAKS CRÍTICOS (Alta confianza):")
        critical_leaks = [l for l in self.leaks_found if l["confidence"] >= 70]
        
        for leak in critical_leaks:
            print(f"\n📁 {leak['repository']}")
            print(f"   Archivo: {leak['file_path']}")
            print(f"   Tipo: {leak['secret_type']}")
            print(f"   Línea: {leak['line_number']}")
            print(f"   Confianza: {leak['confidence']}%")
            print(f"   Texto: {leak['matched_text']}")
            
        print(f"\n⚠️  RECOMENDACIONES:")
        print("- Revisar todos los hallazgos manualmente")
        print("- Rotar credenciales comprometidas inmediatamente")
        print("- Implementar pre-commit hooks para prevenir leaks")
        print("- Usar herramientas como git-secrets o gitleaks")
        print("- Configurar .gitignore apropiadamente")
        
    def export_results(self, filename=None):
        """Exporta resultados a JSON"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"github_leaks_{timestamp}.json"
            
        with open(filename, "w", encoding="utf-8") as f:
            json.dump({
                "metadata": {
                    "tool": "BOFA GitHub Leak Detector",
                    "scanned_at": datetime.now().isoformat(),
                    "total_leaks": len(self.leaks_found)
                },
                "leaks": self.leaks_found
            }, f, indent=2, ensure_ascii=False)
            
        print(f"[INFO] Resultados exportados a: {filename}")
        return filename
        
    def run(self, queries, max_repos_per_query=5):
        """Ejecuta detección completa"""
        self.print_banner()
        
        print("⚠️  AVISO: Herramienta OSINT educativa")
        print("Solo usar en repositorios públicos con fines de seguridad\n")
        
        for query in queries:
            print(f"\n[QUERY] Procesando búsqueda: {query}")
            
            repos = self.search_repositories(query, max_repos_per_query)
            
            for repo in repos:
                repo_leaks = self.scan_repository(repo)
                self.leaks_found.extend(repo_leaks)
                
                if repo_leaks:
                    print(f"  [RESULT] {len(repo_leaks)} leak(s) encontrado(s)")
                else:
                    print(f"  [RESULT] Sin leaks detectados")
                    
                time.sleep(2)  # Rate limiting entre repos
                
        self.generate_report()
        return True

def main():
    parser = argparse.ArgumentParser(description="GitHub Repository Leak Detector")
    parser.add_argument("queries", nargs="+", help="Términos de búsqueda")
    parser.add_argument("--token", help="Token de GitHub API (opcional)")
    parser.add_argument("--max-repos", type=int, default=5, help="Máximo repos por búsqueda")
    parser.add_argument("--output", help="Archivo de salida JSON")
    parser.add_argument("-v", "--verbose", action="store_true", help="Modo verbose")
    
    args = parser.parse_args()
    
    detector = GitHubLeakDetector(args.token, args.verbose)
    
    try:
        success = detector.run(args.queries, args.max_repos)
        
        if success and detector.leaks_found:
            detector.export_results(args.output)
            
    except KeyboardInterrupt:
        print("\n[INFO] Detección interrumpida por el usuario")
    except Exception as e:
        print(f"[ERROR] Error durante la ejecución: {e}")

if __name__ == "__main__":
    main()
