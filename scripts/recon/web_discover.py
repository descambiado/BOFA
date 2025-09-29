#!/usr/bin/env python3
"""
Web Discovery Tool - Advanced Web Reconnaissance
BOFA Suite v2.5.1 - Educational/Professional Use Only
"""

import requests
import argparse
import json
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor

class WebDiscoveryTool:
    def __init__(self):
        self.common_paths = [
            "admin", "login", "dashboard", "config", "backup",
            "robots.txt", "sitemap.xml", "phpinfo.php", 
            "wp-admin", "api", "uploads", "files"
        ]
        
    def check_path(self, base_url: str, path: str) -> dict:
        """Check if path exists"""
        try:
            url = urljoin(base_url, path)
            response = requests.get(url, timeout=5, allow_redirects=False)
            return {
                'path': path,
                'url': url,
                'status_code': response.status_code,
                'size': len(response.content)
            }
        except:
            return None

    def discover(self, base_url: str) -> dict:
        """Perform web discovery"""
        print(f"🔍 Discovering: {base_url}")
        
        results = {'found_paths': [], 'total_checked': len(self.common_paths)}
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(self.check_path, base_url, path) for path in self.common_paths]
            
            for future in futures:
                result = future.result()
                if result and result['status_code'] in [200, 301, 302, 403]:
                    results['found_paths'].append(result)
                    status = "✅" if result['status_code'] == 200 else "🔒"
                    print(f"{status} {result['url']} ({result['status_code']})")
        
        return results

def main():
    parser = argparse.ArgumentParser(description="Web Discovery Tool")
    parser.add_argument('--url', required=True, help='Target URL')
    parser.add_argument('--output', help='Output file')
    args = parser.parse_args()
    
    tool = WebDiscoveryTool()
    results = tool.discover(args.url)
    
    print(f"\n📊 Found {len(results['found_paths'])} interesting paths")
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"💾 Results saved to: {args.output}")

if __name__ == "__main__":
    main()