#!/usr/bin/env python3
"""
Log Guardian - Real-time Security Log Monitor
BOFA Suite v2.5.1 - Educational/Professional Use Only
"""

import os
import re
import json
import time
import argparse
from datetime import datetime
from typing import Dict, List, Any
from collections import defaultdict

class LogGuardian:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.alerts = []
        self.patterns = {
            'brute_force': r'Failed password for .+ from (\d+\.\d+\.\d+\.\d+)',
            'privilege_escalation': r'sudo.*COMMAND=',
            'port_scan': r'SYN.*flags.*multiple',
            'suspicious_login': r'Accepted password for root',
            'file_access': r'(unauthorized|denied).*access',
            'malware_signature': r'(trojan|backdoor|malware|virus)',
            'data_exfil': r'(wget|curl|nc).*(\d+\.\d+\.\d+\.\d+)',
            'sql_injection': r'(union.*select|or.*1=1)',
        }
        
    def analyze_log_file(self, filepath: str) -> Dict[str, Any]:
        """Analyze a log file for security threats"""
        print(f"🔍 Analyzing: {filepath}")
        
        detections = defaultdict(list)
        ip_activity = defaultdict(int)
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            for line_num, line in enumerate(lines, 1):
                for threat_type, pattern in self.patterns.items():
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match:
                        detection = {
                            'line': line_num,
                            'type': threat_type,
                            'content': line.strip()[:200],
                            'timestamp': datetime.now().isoformat(),
                            'severity': self._get_severity(threat_type)
                        }
                        
                        if match.groups():
                            detection['extracted_data'] = match.group(1)
                            ip_activity[match.group(1)] += 1
                        
                        detections[threat_type].append(detection)
                        
                        if self.verbose:
                            severity_icon = "🔴" if detection['severity'] == "HIGH" else "🟡"
                            print(f"{severity_icon} Line {line_num}: {threat_type} detected")
            
            suspicious_ips = {ip: count for ip, count in ip_activity.items() if count >= 5}
            
            results = {
                'file': filepath,
                'total_lines': len(lines),
                'detections': dict(detections),
                'suspicious_ips': suspicious_ips,
                'threat_summary': {threat: len(items) for threat, items in detections.items()},
                'analysis_time': datetime.now().isoformat()
            }
            
            return results
            
        except Exception as e:
            return {'error': str(e), 'file': filepath}
    
    def _get_severity(self, threat_type: str) -> str:
        """Determine severity level"""
        high_severity = ['privilege_escalation', 'malware_signature', 'data_exfil']
        return "HIGH" if threat_type in high_severity else "MEDIUM"
    
    def generate_report(self, results: Dict[str, Any]) -> str:
        """Generate security report"""
        report = []
        report.append("\n" + "="*60)
        report.append("🛡️  LOG GUARDIAN SECURITY REPORT")
        report.append("="*60)
        report.append(f"\n📄 File: {results.get('file', 'N/A')}")
        report.append(f"📊 Total Lines: {results.get('total_lines', 0)}")
        
        threat_summary = results.get('threat_summary', {})
        if threat_summary:
            report.append("\n🎯 THREAT SUMMARY:")
            for threat, count in sorted(threat_summary.items(), key=lambda x: x[1], reverse=True):
                report.append(f"   • {threat}: {count} incidents")
        
        report.append("\n" + "="*60 + "\n")
        return "\n".join(report)

def main():
    parser = argparse.ArgumentParser(description="Log Guardian - Security Log Monitor")
    parser.add_argument('--file', required=True, help='Log file to analyze')
    parser.add_argument('--output', help='Output report file (JSON)')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    guardian = LogGuardian(verbose=args.verbose)
    results = guardian.analyze_log_file(args.file)
    
    print(guardian.generate_report(results))
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"💾 Report saved: {args.output}")

if __name__ == '__main__':
    main()
