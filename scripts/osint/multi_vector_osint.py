
#!/usr/bin/env python3
"""
Multi-Vector OSINT - Advanced Target Profiling Tool
Developed by @descambiado for BOFA Suite

Revolutionary OSINT tool that performs comprehensive target profiling
using multiple intelligence vectors and correlation techniques.
"""

import os
import sys
import json
import time
import hashlib
import requests
import argparse
from datetime import datetime
from urllib.parse import urlparse, urljoin
import base64
from pathlib import Path

class MultiVectorOSINT:
    def __init__(self):
        self.version = "1.0.0"
        self.author = "@descambiado"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.results = {
            'target_info': {},
            'social_profiles': [],
            'email_intelligence': {},
            'username_variations': [],
            'metadata_analysis': {},
            'relationship_map': {},
            'geolocation_data': {},
            'threat_intelligence': {},
            'timeline': []
        }
        
    def print_banner(self):
        print("\n" + "="*70)
        print("🔍 MULTI-VECTOR OSINT - Advanced Target Profiling")
        print("="*70)
        print(f"Version: {self.version} | Author: {self.author}")
        print("Comprehensive intelligence gathering and correlation")
        print("="*70)
        
    def log_activity(self, activity, level="INFO"):
        """Log OSINT activities with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{level}] {activity}")
        
        # Add to timeline
        self.results['timeline'].append({
            'timestamp': timestamp,
            'activity': activity,
            'level': level
        })
        
    def generate_username_variations(self, base_name, surname=None):
        """Generate common username variations"""
        self.log_activity(f"🎭 Generating username variations for: {base_name}")
        
        variations = set()
        base_lower = base_name.lower()
        
        # Basic variations
        variations.add(base_lower)
        variations.add(base_name)
        variations.add(base_name.capitalize())
        
        if surname:
            surname_lower = surname.lower()
            # Name combinations
            variations.add(f"{base_lower}{surname_lower}")
            variations.add(f"{base_lower}.{surname_lower}")
            variations.add(f"{base_lower}_{surname_lower}")
            variations.add(f"{base_lower}-{surname_lower}")
            variations.add(f"{surname_lower}{base_lower}")
            variations.add(f"{surname_lower}.{base_lower}")
            variations.add(f"{surname_lower}_{base_lower}")
            
            # Initial combinations
            variations.add(f"{base_lower[0]}{surname_lower}")
            variations.add(f"{base_lower}{surname_lower[0]}")
            variations.add(f"{base_lower[0]}.{surname_lower}")
            variations.add(f"{base_lower}.{surname_lower[0]}")
            
        # Common number suffixes
        for num in ['1', '2', '123', '2023', '2024', '01', '99']:
            variations.add(f"{base_lower}{num}")
            if surname:
                variations.add(f"{base_lower}{surname_lower}{num}")
                
        # Common prefixes/suffixes
        for prefix in ['the', 'mr', 'ms']:
            variations.add(f"{prefix}{base_lower}")
            
        for suffix in ['official', 'real', 'true', 'pro']:
            variations.add(f"{base_lower}{suffix}")
            
        self.results['username_variations'] = list(variations)
        self.log_activity(f"Generated {len(variations)} username variations")
        
        return list(variations)
        
    def search_social_platforms(self, usernames):
        """Search for profiles across social platforms"""
        self.log_activity("📱 Starting social platform reconnaissance")
        
        # Major social platforms with their URL patterns
        platforms = {
            'GitHub': 'https://github.com/{}',
            'Twitter': 'https://twitter.com/{}',
            'Instagram': 'https://instagram.com/{}',
            'LinkedIn': 'https://linkedin.com/in/{}',
            'Facebook': 'https://facebook.com/{}',
            'Reddit': 'https://reddit.com/user/{}',
            'YouTube': 'https://youtube.com/@{}',
            'TikTok': 'https://tiktok.com/@{}',
            'Pinterest': 'https://pinterest.com/{}',
            'Tumblr': 'https://{}.tumblr.com',
            'Medium': 'https://medium.com/@{}',
            'DeviantArt': 'https://{}.deviantart.com',
            'Flickr': 'https://flickr.com/people/{}',
            'SoundCloud': 'https://soundcloud.com/{}',
            'Twitch': 'https://twitch.tv/{}',
            'Spotify': 'https://open.spotify.com/user/{}',
            'Steam': 'https://steamcommunity.com/id/{}',
            'Discord': 'https://discord.com/users/{}',
            'Telegram': 'https://t.me/{}',
            'WhatsApp': 'https://wa.me/{}',
        }
        
        found_profiles = []
        
        for username in usernames[:10]:  # Limit to prevent rate limiting
            self.log_activity(f"🔍 Checking username: {username}")
            
            for platform, url_pattern in platforms.items():
                try:
                    url = url_pattern.format(username)
                    
                    # Use HEAD request to check existence
                    response = self.session.head(url, timeout=5, allow_redirects=True)
                    
                    if response.status_code == 200:
                        profile_data = {
                            'platform': platform,
                            'username': username,
                            'url': url,
                            'status_code': response.status_code,
                            'found_at': datetime.now().isoformat()
                        }
                        
                        # Try to get additional metadata
                        try:
                            get_response = self.session.get(url, timeout=5)
                            if get_response.status_code == 200:
                                profile_data['content_length'] = len(get_response.content)
                                # Basic content analysis
                                content = get_response.text.lower()
                                if 'followers' in content:
                                    profile_data['has_followers'] = True
                                if 'posts' in content or 'tweets' in content:
                                    profile_data['has_posts'] = True
                        except:
                            pass
                            
                        found_profiles.append(profile_data)
                        self.log_activity(f"✅ Found profile: {platform} - {username}")
                        
                    time.sleep(0.5)  # Rate limiting
                    
                except Exception as e:
                    continue
                    
        self.results['social_profiles'] = found_profiles
        self.log_activity(f"Social platform search completed: {len(found_profiles)} profiles found")
        
        return found_profiles
        
    def analyze_email_intelligence(self, email):
        """Analyze email for intelligence gathering"""
        self.log_activity(f"📧 Analyzing email intelligence: {email}")
        
        email_data = {
            'email': email,
            'domain': email.split('@')[1] if '@' in email else None,
            'username': email.split('@')[0] if '@' in email else None,
            'analysis_timestamp': datetime.now().isoformat()
        }
        
        if email_data['domain']:
            # Analyze domain
            domain = email_data['domain']
            email_data['domain_analysis'] = self.analyze_domain(domain)
            
            # Check for common email providers
            common_providers = {
                'gmail.com': 'Google',
                'yahoo.com': 'Yahoo',
                'hotmail.com': 'Microsoft',
                'outlook.com': 'Microsoft',
                'protonmail.com': 'ProtonMail',
                'tutanota.com': 'Tutanota',
                'aol.com': 'AOL',
                'icloud.com': 'Apple'
            }
            
            email_data['provider'] = common_providers.get(domain.lower(), 'Unknown/Custom')
            
            # Security assessment
            if domain.lower() in ['protonmail.com', 'tutanota.com', 'guerrillamail.com']:
                email_data['privacy_focused'] = True
            
            # Check for disposable email patterns
            disposable_patterns = ['temp', 'throw', 'fake', '10min', 'guerrilla']
            if any(pattern in domain.lower() for pattern in disposable_patterns):
                email_data['likely_disposable'] = True
                
        # Username analysis
        if email_data['username']:
            username = email_data['username']
            email_data['username_analysis'] = {
                'length': len(username),
                'has_numbers': any(c.isdigit() for c in username),
                'has_dots': '.' in username,
                'has_underscores': '_' in username,
                'has_hyphens': '-' in username,
                'appears_random': len(username) > 15 and any(c.isdigit() for c in username)
            }
            
        self.results['email_intelligence'] = email_data
        return email_data
        
    def analyze_domain(self, domain):
        """Analyze domain for intelligence"""
        self.log_activity(f"🌐 Analyzing domain: {domain}")
        
        domain_data = {
            'domain': domain,
            'analysis_timestamp': datetime.now().isoformat()
        }
        
        try:
            # Try to get basic domain info (simplified)
            # In a real implementation, you might use WHOIS, DNS lookups, etc.
            
            # Check if domain is reachable
            test_url = f"https://{domain}"
            try:
                response = self.session.head(test_url, timeout=5)
                domain_data['reachable'] = True
                domain_data['status_code'] = response.status_code
                domain_data['server'] = response.headers.get('Server', 'Unknown')
            except:
                domain_data['reachable'] = False
                
            # Analyze domain structure
            parts = domain.split('.')
            domain_data['subdomain_count'] = len(parts) - 2 if len(parts) > 2 else 0
            domain_data['tld'] = parts[-1] if parts else None
            
            # Check for suspicious TLDs
            suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'bit', 'onion']
            if domain_data['tld'] in suspicious_tlds:
                domain_data['suspicious_tld'] = True
                
        except Exception as e:
            domain_data['analysis_error'] = str(e)
            
        return domain_data
        
    def perform_metadata_analysis(self, target_data):
        """Analyze metadata from various sources"""
        self.log_activity("🔬 Performing metadata analysis")
        
        metadata = {
            'analysis_timestamp': datetime.now().isoformat(),
            'target_hash': hashlib.sha256(str(target_data).encode()).hexdigest()[:16],
            'data_sources': [],
            'patterns': [],
            'confidence_scores': {}
        }
        
        # Analyze patterns in usernames
        if self.results['username_variations']:
            username_patterns = self.analyze_username_patterns(self.results['username_variations'])
            metadata['username_patterns'] = username_patterns
            
        # Analyze social media patterns
        if self.results['social_profiles']:
            social_patterns = self.analyze_social_patterns(self.results['social_profiles'])
            metadata['social_patterns'] = social_patterns
            
        # Cross-reference analysis
        metadata['cross_references'] = self.find_cross_references()
        
        self.results['metadata_analysis'] = metadata
        return metadata
        
    def analyze_username_patterns(self, usernames):
        """Analyze patterns in username variations"""
        patterns = {
            'common_separators': [],
            'number_usage': [],
            'length_distribution': {},
            'character_patterns': []
        }
        
        for username in usernames:
            # Check separators
            if '.' in username:
                patterns['common_separators'].append('dot')
            if '_' in username:
                patterns['common_separators'].append('underscore')
            if '-' in username:
                patterns['common_separators'].append('hyphen')
                
            # Check numbers
            numbers = ''.join([c for c in username if c.isdigit()])
            if numbers:
                patterns['number_usage'].append(numbers)
                
            # Length distribution
            length = len(username)
            patterns['length_distribution'][length] = patterns['length_distribution'].get(length, 0) + 1
            
        return patterns
        
    def analyze_social_patterns(self, profiles):
        """Analyze patterns in social media profiles"""
        patterns = {
            'platform_preferences': {},
            'username_consistency': {},
            'activity_indicators': []
        }
        
        for profile in profiles:
            platform = profile['platform']
            patterns['platform_preferences'][platform] = patterns['platform_preferences'].get(platform, 0) + 1
            
            username = profile['username']
            if username not in patterns['username_consistency']:
                patterns['username_consistency'][username] = []
            patterns['username_consistency'][username].append(platform)
            
            if profile.get('has_followers'):
                patterns['activity_indicators'].append(f"{platform}_has_followers")
            if profile.get('has_posts'):
                patterns['activity_indicators'].append(f"{platform}_has_posts")
                
        return patterns
        
    def find_cross_references(self):
        """Find cross-references between different data sources"""
        cross_refs = {
            'email_username_matches': [],
            'social_consistency': [],
            'pattern_correlations': []
        }
        
        # Check email-username consistency
        if self.results['email_intelligence'].get('username'):
            email_username = self.results['email_intelligence']['username']
            for profile in self.results['social_profiles']:
                if profile['username'] == email_username:
                    cross_refs['email_username_matches'].append(profile['platform'])
                    
        # Check username consistency across platforms
        username_platforms = {}
        for profile in self.results['social_profiles']:
            username = profile['username']
            if username not in username_platforms:
                username_platforms[username] = []
            username_platforms[username].append(profile['platform'])
            
        for username, platforms in username_platforms.items():
            if len(platforms) > 1:
                cross_refs['social_consistency'].append({
                    'username': username,
                    'platforms': platforms,
                    'consistency_score': len(platforms)
                })
                
        return cross_refs
        
    def generate_relationship_map(self):
        """Generate a relationship map of discovered data"""
        self.log_activity("🕸️  Generating relationship map")
        
        relationships = {
            'primary_identity': {},
            'connected_accounts': [],
            'pattern_links': [],
            'confidence_levels': {}
        }
        
        # Determine primary identity
        if self.results['email_intelligence']:
            relationships['primary_identity']['email'] = self.results['email_intelligence']['email']
            
        # Map connected accounts
        for profile in self.results['social_profiles']:
            account = {
                'platform': profile['platform'],
                'username': profile['username'],
                'url': profile['url'],
                'confidence': 'high' if profile.get('has_posts') or profile.get('has_followers') else 'medium'
            }
            relationships['connected_accounts'].append(account)
            
        # Calculate overall confidence
        total_sources = len(self.results['social_profiles'])
        if total_sources > 5:
            relationships['overall_confidence'] = 'high'
        elif total_sources > 2:
            relationships['overall_confidence'] = 'medium'
        else:
            relationships['overall_confidence'] = 'low'
            
        self.results['relationship_map'] = relationships
        return relationships
        
    def export_results(self, output_format='json', filename=None):
        """Export results in various formats"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"osint_report_{timestamp}"
            
        if output_format == 'json':
            filename += '.json'
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
                
        elif output_format == 'html':
            filename += '.html'
            html_content = self.generate_html_report()
            with open(filename, 'w') as f:
                f.write(html_content)
                
        self.log_activity(f"📊 Results exported to: {filename}")
        return filename
        
    def generate_html_report(self):
        """Generate HTML report"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Multi-Vector OSINT Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; }}
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; }}
                .profile {{ background: #f8f9fa; margin: 10px 0; padding: 10px; }}
                .timestamp {{ color: #666; font-size: 0.9em; }}
                .confidence {{ font-weight: bold; }}
                .high {{ color: #27ae60; }}
                .medium {{ color: #f39c12; }}
                .low {{ color: #e74c3c; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔍 Multi-Vector OSINT Report</h1>
                <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                <p>Version: {self.version} | Author: {self.author}</p>
            </div>
            
            <div class="section">
                <h2>📧 Email Intelligence</h2>
                <p><strong>Email:</strong> {self.results['email_intelligence'].get('email', 'N/A')}</p>
                <p><strong>Provider:</strong> {self.results['email_intelligence'].get('provider', 'N/A')}</p>
                <p><strong>Domain:</strong> {self.results['email_intelligence'].get('domain', 'N/A')}</p>
            </div>
            
            <div class="section">
                <h2>📱 Social Media Profiles</h2>
        """
        
        for profile in self.results['social_profiles']:
            html += f"""
                <div class="profile">
                    <strong>{profile['platform']}:</strong> 
                    <a href="{profile['url']}" target="_blank">{profile['username']}</a>
                    <span class="timestamp">Found: {profile['found_at']}</span>
                </div>
            """
            
        html += f"""
            </div>
            
            <div class="section">
                <h2>🕸️  Relationship Map</h2>
                <p><strong>Connected Accounts:</strong> {len(self.results['social_profiles'])}</p>
                <p><strong>Overall Confidence:</strong> 
                   <span class="confidence {self.results['relationship_map'].get('overall_confidence', 'low')}">
                   {self.results['relationship_map'].get('overall_confidence', 'low').upper()}
                   </span>
                </p>
            </div>
            
            <div class="section">
                <h2>📋 Investigation Timeline</h2>
        """
        
        for event in self.results['timeline']:
            html += f"""
                <p><span class="timestamp">[{event['timestamp']}]</span> {event['activity']}</p>
            """
            
        html += """
            </div>
            
            <div class="section">
                <h2>⚠️ Legal Notice</h2>
                <p>This report was generated for authorized security research and education purposes only. 
                All information gathered is from publicly available sources. Use responsibly and ethically.</p>
            </div>
        </body>
        </html>
        """
        
        return html

def main():
    parser = argparse.ArgumentParser(description="Multi-Vector OSINT - Advanced Target Profiling")
    parser.add_argument('-e', '--email', help='Target email address')
    parser.add_argument('-u', '--username', help='Target username')
    parser.add_argument('-n', '--name', help='Target first name')
    parser.add_argument('-s', '--surname', help='Target surname')
    parser.add_argument('-o', '--output', help='Output filename (without extension)')
    parser.add_argument('-f', '--format', choices=['json', 'html'], default='html',
                       help='Output format (default: html)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--delay', type=float, default=1.0,
                       help='Delay between requests in seconds (default: 1.0)')
    
    args = parser.parse_args()
    
    if not any([args.email, args.username, args.name]):
        print("❌ At least one target identifier required (email, username, or name)")
        return 1
        
    osint = MultiVectorOSINT()
    osint.print_banner()
    
    print(f"\n🎯 Target Information:")
    if args.email:
        print(f"   Email: {args.email}")
    if args.username:
        print(f"   Username: {args.username}")
    if args.name:
        print(f"   Name: {args.name} {args.surname or ''}")
        
    print(f"\n⚠️  IMPORTANT:")
    print(f"   • This tool accesses only PUBLIC information")
    print(f"   • Use for authorized research and education only")
    print(f"   • Respect privacy and applicable laws")
    print(f"   • Some platforms may rate limit requests")
    
    confirm = input(f"\n🔍 Start OSINT investigation? (y/N): ")
    if confirm.lower() != 'y':
        print("Investigation cancelled.")
        return 0
        
    try:
        # Email analysis
        if args.email:
            osint.analyze_email_intelligence(args.email)
            
        # Generate username variations
        usernames = []
        if args.username:
            usernames.append(args.username)
        if args.name:
            usernames.extend(osint.generate_username_variations(args.name, args.surname))
        elif args.email:
            email_username = args.email.split('@')[0]
            usernames.extend(osint.generate_username_variations(email_username))
            
        # Social media search
        if usernames:
            osint.search_social_platforms(usernames)
            
        # Metadata analysis
        target_data = {
            'email': args.email,
            'username': args.username,
            'name': args.name,
            'surname': args.surname
        }
        osint.perform_metadata_analysis(target_data)
        
        # Generate relationship map
        osint.generate_relationship_map()
        
        # Export results
        output_file = osint.export_results(args.format, args.output)
        
        # Summary
        print(f"\n🎯 INVESTIGATION SUMMARY:")
        print(f"   • Social Profiles Found: {len(osint.results['social_profiles'])}")
        print(f"   • Username Variations: {len(osint.results['username_variations'])}")
        print(f"   • Overall Confidence: {osint.results['relationship_map'].get('overall_confidence', 'unknown').upper()}")
        print(f"   • Report Saved: {output_file}")
        
        if args.verbose:
            print(f"\n📱 Found Profiles:")
            for profile in osint.results['social_profiles']:
                print(f"   • {profile['platform']}: {profile['url']}")
                
        print(f"\n✅ Multi-Vector OSINT investigation completed!")
        
    except KeyboardInterrupt:
        print(f"\n⚠️  Investigation interrupted by user")
        return 1
    except Exception as e:
        print(f"\n❌ Investigation error: {e}")
        return 1
        
    return 0

if __name__ == "__main__":
    sys.exit(main())
