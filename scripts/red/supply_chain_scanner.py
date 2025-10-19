#!/usr/bin/env python3
"""
Supply Chain Security Scanner
Analyzes software dependencies for vulnerabilities and supply chain risks
"""

import json
import argparse
import re
from typing import Dict, List, Any
from datetime import datetime

class SupplyChainScanner:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.vulnerabilities = []
        
    def analyze_requirements_txt(self, content: str) -> Dict[str, Any]:
        """Analyze Python requirements.txt"""
        results = {
            'total_packages': 0,
            'vulnerabilities': [],
            'suspicious': []
        }
        
        vulnerable_packages = {
            'pyyaml': ['<5.4', 'Code execution vulnerability'],
            'django': ['<2.2.28', 'SQL injection'],
            'pillow': ['<8.3.2', 'Buffer overflow']
        }
        
        lines = content.strip().split('\n')
        for line in lines:
            if line.strip() and not line.startswith('#'):
                results['total_packages'] += 1
                match = re.match(r'([a-zA-Z0-9_-]+)([=<>!]+)?(.*)', line)
                if match:
                    pkg = match.group(1).lower()
                    if pkg in vulnerable_packages:
                        results['vulnerabilities'].append({
                            'package': pkg,
                            'severity': 'HIGH',
                            'reason': vulnerable_packages[pkg][1]
                        })
        
        return results
    
    def generate_sbom(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate Software Bill of Materials"""
        return {
            'sbom_version': '1.0',
            'timestamp': datetime.now().isoformat(),
            'results': results
        }

def main():
    parser = argparse.ArgumentParser(description='Supply Chain Scanner')
    parser.add_argument('--requirements', help='Path to requirements.txt')
    parser.add_argument('--output', help='Output JSON file')
    args = parser.parse_args()
    
    scanner = SupplyChainScanner()
    
    if args.requirements:
        with open(args.requirements, 'r') as f:
            content = f.read()
        results = scanner.analyze_requirements_txt(content)
        print(f"\n[+] Python Analysis:")
        print(f"    Total packages: {results['total_packages']}")
        print(f"    Vulnerabilities: {len(results['vulnerabilities'])}")
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)

if __name__ == '__main__':
    main()
