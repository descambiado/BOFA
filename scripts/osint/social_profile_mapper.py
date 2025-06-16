
#!/usr/bin/env python3
"""
Social Profile Mapper - OSINT Profile Discovery Tool
Author: @descambiado (David Hernández Jiménez)
BOFA - Best Of All Cybersecurity Suite
Educational/Professional Use Only - Public Metadata Only
"""

import requests
import json
import argparse
import time
import sys
from urllib.parse import quote
import random

class SocialProfileMapper:
    def __init__(self, timeout=10, delay_range=(1, 3)):
        self.timeout = timeout
        self.delay_range = delay_range
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        # Platform configurations (public endpoints only)
        self.platforms = {
            'github': {
                'url': 'https://api.github.com/users/{}',
                'method': 'api',
                'fields': ['login', 'name', 'company', 'location', 'bio', 'public_repos', 'followers', 'following', 'created_at']
            },
            'twitter': {
                'url': 'https://twitter.com/{}',
                'method': 'check_existence',
                'indicator': 'This account doesn\'t exist'
            },
            'instagram': {
                'url': 'https://www.instagram.com/{}/',
                'method': 'check_existence',
                'indicator': 'Sorry, this page isn\'t available'
            },
            'linkedin': {
                'url': 'https://www.linkedin.com/in/{}',
                'method': 'check_existence',
                'indicator': 'This LinkedIn profile is not available'
            },
            'youtube': {
                'url': 'https://www.youtube.com/@{}',
                'method': 'check_existence',
                'indicator': 'This channel does not exist'
            },
            'tiktok': {
                'url': 'https://www.tiktok.com/@{}',
                'method': 'check_existence',
                'indicator': 'Couldn\'t find this account'
            },
            'reddit': {
                'url': 'https://www.reddit.com/user/{}',
                'method': 'check_existence',
                'indicator': 'Sorry, nobody on Reddit goes by that name'
            },
            'pinterest': {
                'url': 'https://www.pinterest.com/{}/',
                'method': 'check_existence',
                'indicator': 'Sorry, we couldn\'t find any Pins for this search'
            }
        }
        
        self.found_profiles = []
    
    def random_delay(self):
        """Añade un delay aleatorio entre requests"""
        delay = random.uniform(self.delay_range[0], self.delay_range[1])
        time.sleep(delay)
    
    def check_github_profile(self, username):
        """Verifica perfil de GitHub usando API pública"""
        try:
            url = self.platforms['github']['url'].format(username)
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                profile_info = {
                    'platform': 'GitHub',
                    'username': username,
                    'url': f"https://github.com/{username}",
                    'exists': True,
                    'metadata': {}
                }
                
                # Extraer información pública
                for field in self.platforms['github']['fields']:
                    if field in data and data[field]:
                        profile_info['metadata'][field] = data[field]
                
                return profile_info
            else:
                return {'platform': 'GitHub', 'username': username, 'exists': False}
                
        except Exception as e:
            print(f"⚠️  Error al verificar GitHub: {str(e)}")
            return {'platform': 'GitHub', 'username': username, 'exists': False, 'error': str(e)}
    
    def check_profile_existence(self, platform, username):
        """Verifica existencia de perfil basado en respuesta HTTP"""
        try:
            config = self.platforms[platform]
            url = config['url'].format(username)
            
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            
            # Determinar si el perfil existe
            exists = True
            if response.status_code == 404:
                exists = False
            elif 'indicator' in config and config['indicator'].lower() in response.text.lower():
                exists = False
            
            profile_info = {
                'platform': platform.title(),
                'username': username,
                'url': url,
                'exists': exists,
                'status_code': response.status_code
            }
            
            if exists:
                # Intentar extraer título de la página
                try:
                    title_start = response.text.lower().find('<title>')
                    if title_start != -1:
                        title_start += 7
                        title_end = response.text.lower().find('</title>', title_start)
                        if title_end != -1:
                            title = response.text[title_start:title_end].strip()
                            profile_info['page_title'] = title
                except:
                    pass
            
            return profile_info
            
        except Exception as e:
            return {
                'platform': platform.title(),
                'username': username,
                'exists': False,
                'error': str(e)
            }
    
    def search_profiles(self, username):
        """Busca perfiles en todas las plataformas"""
        print(f"🔍 Buscando perfiles para: {username}")
        print("-" * 50)
        
        for platform, config in self.platforms.items():
            print(f"🌐 Verificando {platform.title()}...", end=' ')
            
            if config['method'] == 'api':
                if platform == 'github':
                    result = self.check_github_profile(username)
            else:
                result = self.check_profile_existence(platform, username)
            
            if result['exists']:
                self.found_profiles.append(result)
                print(f"✅ ENCONTRADO")
                
                # Mostrar metadata si está disponible
                if 'metadata' in result and result['metadata']:
                    for key, value in result['metadata'].items():
                        print(f"   📋 {key}: {value}")
                elif 'page_title' in result:
                    print(f"   📋 Título: {result['page_title']}")
            else:
                print("❌ No encontrado")
            
            # Delay entre requests
            self.random_delay()
        
        return self.found_profiles
    
    def search_variations(self, base_username):
        """Busca variaciones del nombre de usuario"""
        variations = [
            base_username,
            base_username.lower(),
            base_username.upper(),
            base_username.replace(' ', ''),
            base_username.replace(' ', '_'),
            base_username.replace(' ', '-'),
            base_username.replace('.', ''),
            f"{base_username}1",
            f"{base_username}_official"
        ]
        
        # Eliminar duplicados manteniendo orden
        unique_variations = []
        for var in variations:
            if var not in unique_variations and var.strip():
                unique_variations.append(var)
        
        all_results = []
        
        for variation in unique_variations[:5]:  # Limitar a 5 variaciones
            print(f"\n🔄 Probando variación: {variation}")
            results = self.search_profiles(variation)
            all_results.extend(results)
            
            if len(results) > 0:
                print(f"✅ Encontrados {len(results)} perfiles para '{variation}'")
        
        return all_results
    
    def generate_report(self, output_format='text'):
        """Genera reporte de resultados"""
        if output_format == 'json':
            return json.dumps(self.found_profiles, indent=2, ensure_ascii=False)
        else:
            report = "\n📊 REPORTE SOCIAL PROFILE MAPPER\n"
            report += "=" * 50 + "\n"
            report += f"Total perfiles encontrados: {len(self.found_profiles)}\n\n"
            
            for profile in self.found_profiles:
                report += f"🌐 {profile['platform']}\n"
                report += f"   👤 Usuario: {profile['username']}\n"
                report += f"   🔗 URL: {profile['url']}\n"
                
                if 'metadata' in profile and profile['metadata']:
                    report += "   📋 Información pública:\n"
                    for key, value in profile['metadata'].items():
                        report += f"      • {key}: {value}\n"
                elif 'page_title' in profile:
                    report += f"   📋 Título: {profile['page_title']}\n"
                
                report += "-" * 30 + "\n"
            
            return report

def main():
    parser = argparse.ArgumentParser(
        description="Social Profile Mapper - Herramienta OSINT para descubrimiento de perfiles",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  python3 social_profile_mapper.py -u "john_doe"
  python3 social_profile_mapper.py -u "Jane Smith" --variations
  python3 social_profile_mapper.py -u "target_user" -o results.json --format json

⚠️  AVISO LEGAL:
Esta herramienta solo accede a información pública disponible.
Úsala de manera ética y respetando los términos de servicio de cada plataforma.
        """
    )
    
    parser.add_argument('-u', '--username', required=True,
                       help='Nombre de usuario o alias a buscar')
    parser.add_argument('--variations', action='store_true',
                       help='Buscar variaciones del nombre de usuario')
    parser.add_argument('-o', '--output',
                       help='Archivo de salida para guardar resultados')
    parser.add_argument('--format', choices=['json', 'text'], default='text',
                       help='Formato de salida (default: text)')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Timeout para requests (default: 10s)')
    
    args = parser.parse_args()
    
    # Banner
    print("\n🛡️  BOFA - Social Profile Mapper v1.0")
    print("Desarrollado por @descambiado")
    print("⚠️  Solo información pública - Uso ético")
    print("=" * 50)
    
    try:
        mapper = SocialProfileMapper(timeout=args.timeout)
        
        if args.variations:
            results = mapper.search_variations(args.username)
        else:
            results = mapper.search_profiles(args.username)
        
        # Generar reporte
        report = mapper.generate_report(args.format)
        
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"\n💾 Resultados guardados en: {args.output}")
        else:
            print(report)
            
        print(f"\n🎯 Búsqueda completada: {len(results)} perfiles encontrados")
        
    except KeyboardInterrupt:
        print("\n⚠️  Búsqueda interrumpida por el usuario")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
