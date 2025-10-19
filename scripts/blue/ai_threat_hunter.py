#!/usr/bin/env python3
"""
AI-Powered Threat Hunter
Uses ML techniques to detect anomalies in security logs
"""

import json
import argparse
from typing import Dict, List, Any
from datetime import datetime
from collections import Counter

class AIThreatHunter:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.anomalies = []
        
    def analyze_auth_logs(self, logs: List[str]) -> Dict[str, Any]:
        """Analyze authentication logs"""
        results = {
            'total_events': len(logs),
            'failed_logins': [],
            'brute_force_attempts': []
        }
        
        failed_attempts = Counter()
        
        for log in logs:
            if 'Failed password' in log or 'authentication failure' in log.lower():
                import re
                ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', log)
                if ip_match:
                    ip = ip_match.group(1)
                    failed_attempts[ip] += 1
        
        for ip, count in failed_attempts.items():
            if count >= 5:
                results['brute_force_attempts'].append({
                    'ip': ip,
                    'attempts': count,
                    'severity': 'HIGH'
                })
        
        return results

def main():
    parser = argparse.ArgumentParser(description='AI Threat Hunter')
    parser.add_argument('--auth-logs', help='Path to auth logs')
    parser.add_argument('--output', help='Output file')
    args = parser.parse_args()
    
    hunter = AIThreatHunter()
    
    if args.auth_logs:
        with open(args.auth_logs, 'r') as f:
            logs = f.readlines()
        results = hunter.analyze_auth_logs(logs)
        print(f"\n[+] Authentication Analysis:")
        print(f"    Brute force attempts: {len(results['brute_force_attempts'])}")
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)

if __name__ == '__main__':
    main()
