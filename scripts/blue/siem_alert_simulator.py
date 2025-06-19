
#!/usr/bin/env python3
"""
SIEM Alert Simulator - Blue Team Defense Training Tool
Developed by @descambiado for BOFA Suite
Educational and authorized testing only
"""

import json
import random
import time
from datetime import datetime, timedelta
import argparse
import sys
import ipaddress

class SIEMAlertSimulator:
    def __init__(self):
        self.version = "1.0"
        self.author = "@descambiado"
        self.alert_templates = self.load_alert_templates()
        
    def print_banner(self):
        banner = """
╔══════════════════════════════════════════════════════════════════╗
║                 SIEM ALERT SIMULATOR v1.0                       ║
║              Blue Team Defense Training Tool                     ║
║                    By @descambiado                               ║
╚══════════════════════════════════════════════════════════════════╝
        """
        print(banner)
        
    def load_alert_templates(self):
        """Load predefined alert templates"""
        return {
            'brute_force': {
                'severity': 'HIGH',
                'category': 'Authentication',
                'mitre_id': 'T1110',
                'description': 'Multiple failed login attempts detected',
                'indicators': ['failed_logins', 'source_ip', 'username']
            },
            'malware_detection': {
                'severity': 'CRITICAL',
                'category': 'Malware',
                'mitre_id': 'T1204',
                'description': 'Malicious file execution detected',
                'indicators': ['file_hash', 'process_name', 'host']
            },
            'lateral_movement': {
                'severity': 'HIGH',
                'category': 'Lateral Movement',
                'mitre_id': 'T1021',
                'description': 'Suspicious lateral movement activity',
                'indicators': ['source_host', 'target_host', 'protocol']
            },
            'data_exfiltration': {
                'severity': 'CRITICAL',
                'category': 'Exfiltration',
                'mitre_id': 'T1041',
                'description': 'Unusual data transfer detected',
                'indicators': ['bytes_transferred', 'destination', 'protocol']
            },
            'privilege_escalation': {
                'severity': 'HIGH',
                'category': 'Privilege Escalation',
                'mitre_id': 'T1068',
                'description': 'Privilege escalation attempt detected',
                'indicators': ['user', 'process', 'privilege_gained']
            }
        }
    
    def generate_random_ip(self):
        """Generate random IP address"""
        return str(ipaddress.IPv4Address(random.randint(0, 2**32 - 1)))
    
    def generate_malware_hash(self):
        """Generate fake malware hash"""
        return ''.join(random.choices('0123456789abcdef', k=64))
    
    def generate_brute_force_alert(self):
        """Generate brute force attack alert"""
        template = self.alert_templates['brute_force']
        
        usernames = ['admin', 'administrator', 'root', 'user', 'guest', 'service']
        source_ips = [self.generate_random_ip() for _ in range(3)]
        
        alert = {
            'alert_id': f"BF_{random.randint(10000, 99999)}",
            'timestamp': datetime.now().isoformat(),
            'severity': template['severity'],
            'category': template['category'],
            'mitre_attack': template['mitre_id'],
            'title': template['description'],
            'details': {
                'source_ip': random.choice(source_ips),
                'target_username': random.choice(usernames),
                'failed_attempts': random.randint(10, 100),
                'time_window': f"{random.randint(1, 10)} minutes",
                'protocols': ['SSH', 'RDP', 'SMB'][random.randint(0, 2)]
            },
            'risk_score': random.randint(70, 95),
            'status': 'ACTIVE'
        }
        
        return alert
    
    def generate_malware_alert(self):
        """Generate malware detection alert"""
        template = self.alert_templates['malware_detection']
        
        malware_names = ['Trojan.Generic', 'Backdoor.Agent', 'Ransomware.Cryptor', 'Worm.AutoRun']
        processes = ['svchost.exe', 'explorer.exe', 'chrome.exe', 'notepad.exe']
        
        alert = {
            'alert_id': f"MW_{random.randint(10000, 99999)}",
            'timestamp': datetime.now().isoformat(),
            'severity': template['severity'],
            'category': template['category'],
            'mitre_attack': template['mitre_id'],
            'title': template['description'],
            'details': {
                'malware_name': random.choice(malware_names),
                'file_hash': self.generate_malware_hash(),
                'file_path': f"C:\\Users\\{random.choice(['Admin', 'User', 'Guest'])}\\AppData\\Local\\malware.exe",
                'process_name': random.choice(processes),
                'host': f"WORKSTATION-{random.randint(1, 50):02d}",
                'quarantined': random.choice([True, False])
            },
            'risk_score': random.randint(85, 100),
            'status': 'ACTIVE'
        }
        
        return alert
    
    def generate_lateral_movement_alert(self):
        """Generate lateral movement alert"""
        template = self.alert_templates['lateral_movement']
        
        alert = {
            'alert_id': f"LM_{random.randint(10000, 99999)}",
            'timestamp': datetime.now().isoformat(),
            'severity': template['severity'],
            'category': template['category'],
            'mitre_attack': template['mitre_id'],
            'title': template['description'],
            'details': {
                'source_host': f"WS-{random.randint(1, 100):03d}",
                'target_host': f"SRV-{random.randint(1, 20):02d}",
                'protocol': random.choice(['SMB', 'WMI', 'PowerShell', 'RDP']),
                'user_account': f"corp\\user{random.randint(1, 100)}",
                'connections': random.randint(5, 25),
                'time_span': f"{random.randint(1, 60)} minutes"
            },
            'risk_score': random.randint(60, 90),
            'status': 'INVESTIGATING'
        }
        
        return alert
    
    def generate_data_exfiltration_alert(self):
        """Generate data exfiltration alert"""
        template = self.alert_templates['data_exfiltration']
        
        alert = {
            'alert_id': f"DE_{random.randint(10000, 99999)}",
            'timestamp': datetime.now().isoformat(),
            'severity': template['severity'],
            'category': template['category'],
            'mitre_attack': template['mitre_id'],
            'title': template['description'],
            'details': {
                'source_host': f"FS-{random.randint(1, 10):02d}",
                'destination_ip': self.generate_random_ip(),
                'bytes_transferred': f"{random.randint(100, 5000)} MB",
                'protocol': random.choice(['HTTPS', 'FTP', 'DNS', 'ICMP']),
                'duration': f"{random.randint(5, 120)} minutes",
                'files_accessed': random.randint(50, 500)
            },
            'risk_score': random.randint(80, 100),
            'status': 'CRITICAL'
        }
        
        return alert
    
    def generate_privilege_escalation_alert(self):
        """Generate privilege escalation alert"""
        template = self.alert_templates['privilege_escalation']
        
        alert = {
            'alert_id': f"PE_{random.randint(10000, 99999)}",
            'timestamp': datetime.now().isoformat(),
            'severity': template['severity'],
            'category': template['category'],
            'mitre_attack': template['mitre_id'],
            'title': template['description'],
            'details': {
                'user_account': f"corp\\user{random.randint(1, 100)}",
                'original_privileges': 'User',
                'escalated_privileges': random.choice(['Administrator', 'SYSTEM', 'Domain Admin']),
                'method': random.choice(['Token Impersonation', 'UAC Bypass', 'Service Misconfiguration']),
                'host': f"WS-{random.randint(1, 100):03d}",
                'process': random.choice(['powershell.exe', 'cmd.exe', 'rundll32.exe'])
            },
            'risk_score': random.randint(75, 95),
            'status': 'ACTIVE'
        }
        
        return alert
    
    def simulate_alert_storm(self, count=10, alert_types=None):
        """Simulate multiple alerts for training"""
        if alert_types is None:
            alert_types = list(self.alert_templates.keys())
        
        alerts = []
        generators = {
            'brute_force': self.generate_brute_force_alert,
            'malware_detection': self.generate_malware_alert,
            'lateral_movement': self.generate_lateral_movement_alert,
            'data_exfiltration': self.generate_data_exfiltration_alert,
            'privilege_escalation': self.generate_privilege_escalation_alert
        }
        
        print(f"[+] Generating {count} security alerts...")
        
        for i in range(count):
            alert_type = random.choice(alert_types)
            alert = generators[alert_type]()
            alerts.append(alert)
            
            print(f"[{i+1:02d}] {alert['severity']} - {alert['title']} (ID: {alert['alert_id']})")
            
            # Random delay between alerts
            time.sleep(random.uniform(0.1, 0.5))
        
        return alerts
    
    def generate_false_positives(self, count=5):
        """Generate false positive alerts for training"""
        false_positives = []
        
        fp_scenarios = [
            {
                'type': 'Scheduled Task',
                'description': 'Legitimate scheduled maintenance task flagged as suspicious',
                'severity': 'MEDIUM'
            },
            {
                'type': 'Software Update',
                'description': 'Automatic software update process triggered AV alert',
                'severity': 'LOW'
            },
            {
                'type': 'Admin Activity',
                'description': 'Legitimate administrator activity flagged as privilege escalation',
                'severity': 'MEDIUM'
            },
            {
                'type': 'Backup Process',
                'description': 'Regular backup process triggered data exfiltration alert',
                'severity': 'LOW'
            }
        ]
        
        for i in range(count):
            scenario = random.choice(fp_scenarios)
            fp_alert = {
                'alert_id': f"FP_{random.randint(10000, 99999)}",
                'timestamp': datetime.now().isoformat(),
                'severity': scenario['severity'],
                'category': 'False Positive',
                'title': scenario['description'],
                'type': scenario['type'],
                'resolution': 'Whitelist created',
                'analyst_notes': 'Confirmed legitimate activity after investigation'
            }
            false_positives.append(fp_alert)
        
        return false_positives
    
    def export_alerts(self, alerts, filename=None):
        """Export alerts to JSON file"""
        if filename is None:
            filename = f"siem_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        export_data = {
            'metadata': {
                'generated_by': 'BOFA SIEM Alert Simulator',
                'version': self.version,
                'timestamp': datetime.now().isoformat(),
                'total_alerts': len(alerts)
            },
            'alerts': alerts,
            'statistics': self.generate_statistics(alerts)
        }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        print(f"[+] Alerts exported to: {filename}")
        return filename
    
    def generate_statistics(self, alerts):
        """Generate alert statistics"""
        stats = {
            'total_alerts': len(alerts),
            'by_severity': {},
            'by_category': {},
            'by_status': {},
            'average_risk_score': 0
        }
        
        risk_scores = []
        
        for alert in alerts:
            # Severity distribution
            severity = alert.get('severity', 'UNKNOWN')
            stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1
            
            # Category distribution
            category = alert.get('category', 'UNKNOWN')
            stats['by_category'][category] = stats['by_category'].get(category, 0) + 1
            
            # Status distribution
            status = alert.get('status', 'UNKNOWN')
            stats['by_status'][status] = stats['by_status'].get(status, 0) + 1
            
            # Risk scores
            if 'risk_score' in alert:
                risk_scores.append(alert['risk_score'])
        
        if risk_scores:
            stats['average_risk_score'] = sum(risk_scores) / len(risk_scores)
        
        return stats

def main():
    parser = argparse.ArgumentParser(description="SIEM Alert Simulator - Blue Team Defense Training Tool")
    parser.add_argument("-c", "--count", type=int, default=10, help="Number of alerts to generate")
    parser.add_argument("-t", "--types", nargs="+", 
                       choices=['brute_force', 'malware_detection', 'lateral_movement', 'data_exfiltration', 'privilege_escalation'],
                       help="Alert types to generate")
    parser.add_argument("-f", "--false-positives", type=int, default=0, help="Include false positives")
    parser.add_argument("-o", "--output", help="Output filename")
    parser.add_argument("--real-time", action="store_true", help="Real-time alert simulation")
    parser.add_argument("--help-mitre", action="store_true", help="Show MITRE ATT&CK mappings")
    
    if len(sys.argv) == 1:
        parser.print_help()
        return
        
    args = parser.parse_args()
    
    if args.help_mitre:
        print("""
MITRE ATT&CK TECHNIQUE MAPPINGS:
===============================

T1110 - Brute Force:
  - Password attacks against user accounts
  - Credential stuffing attempts
  - Dictionary attacks

T1204 - User Execution:
  - Malicious file execution
  - Email attachment execution
  - Drive-by downloads

T1021 - Remote Services:
  - Lateral movement via SMB/WMI
  - RDP session hijacking
  - Service exploitation

T1041 - Exfiltration Over C2 Channel:
  - Data theft via command channels
  - Covert data transmission
  - Protocol tunneling

T1068 - Exploitation for Privilege Escalation:
  - Local privilege escalation
  - Kernel exploits
  - Service misconfigurations
        """)
        return
    
    simulator = SIEMAlertSimulator()
    simulator.print_banner()
    
    print("[!] EDUCATIONAL SIMULATION - Training alerts only")
    print("[!] For blue team training and SIEM tuning\n")
    
    if args.real_time:
        print("[+] Starting real-time alert simulation...")
        print("[+] Press Ctrl+C to stop\n")
        
        try:
            while True:
                alert_type = random.choice(args.types or list(simulator.alert_templates.keys()))
                generators = {
                    'brute_force': simulator.generate_brute_force_alert,
                    'malware_detection': simulator.generate_malware_alert,
                    'lateral_movement': simulator.generate_lateral_movement_alert,
                    'data_exfiltration': simulator.generate_data_exfiltration_alert,
                    'privilege_escalation': simulator.generate_privilege_escalation_alert
                }
                
                alert = generators[alert_type]()
                print(f"[{datetime.now().strftime('%H:%M:%S')}] {alert['severity']} - {alert['title']} (ID: {alert['alert_id']})")
                
                time.sleep(random.uniform(2, 10))
                
        except KeyboardInterrupt:
            print("\n[+] Real-time simulation stopped")
            return
    
    # Generate alert storm
    alerts = simulator.simulate_alert_storm(args.count, args.types)
    
    # Add false positives if requested
    if args.false_positives > 0:
        fp_alerts = simulator.generate_false_positives(args.false_positives)
        alerts.extend(fp_alerts)
        print(f"[+] Added {args.false_positives} false positive alerts")
    
    # Export results
    filename = simulator.export_alerts(alerts, args.output)
    
    # Show statistics
    stats = simulator.generate_statistics(alerts)
    print(f"\n{'='*60}")
    print("ALERT SIMULATION SUMMARY")
    print(f"{'='*60}")
    print(f"Total Alerts: {stats['total_alerts']}")
    print(f"Average Risk Score: {stats['average_risk_score']:.1f}")
    print("\nSeverity Distribution:")
    for severity, count in stats['by_severity'].items():
        print(f"  {severity}: {count}")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()
