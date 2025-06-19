
#!/usr/bin/env python3
"""
Log Baseliner - Behavioral Analysis and Anomaly Detection Tool
Developed by @descambiado for BOFA Suite
Educational and authorized testing only
"""

import json
import re
import statistics
from collections import defaultdict, Counter
from datetime import datetime, timedelta
import argparse
import sys
import os

class LogBaseliner:
    def __init__(self):
        self.version = "1.0"
        self.author = "@descambiado"
        self.baseline_data = {}
        self.anomalies = []
        
    def print_banner(self):
        banner = """
╔══════════════════════════════════════════════════════════════════╗
║                   LOG BASELINER v1.0                            ║
║              Behavioral Analysis & Anomaly Detection             ║
║                    By @descambiado                               ║
╚══════════════════════════════════════════════════════════════════╝
        """
        print(banner)
        
    def parse_auth_logs(self, log_file_path):
        """Parse authentication logs for baseline creation"""
        log_entries = []
        
        # Sample log patterns
        patterns = {
            'ssh_login': r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sshd.*Accepted.*for (\w+) from ([\d\.]+)',
            'ssh_failed': r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sshd.*Failed.*for (\w+) from ([\d\.]+)',
            'sudo_cmd': r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sudo.*(\w+).*COMMAND=(.*)',
            'su_switch': r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*su.*session opened for user (\w+)',
        }
        
        # Generate sample log data if file doesn't exist
        if not os.path.exists(log_file_path):
            print(f"[*] Generating sample log data for analysis...")
            sample_logs = self.generate_sample_logs()
        else:
            with open(log_file_path, 'r') as f:
                sample_logs = f.readlines()
        
        for line in sample_logs:
            for log_type, pattern in patterns.items():
                match = re.search(pattern, line)
                if match:
                    entry = {
                        'timestamp': match.group(1),
                        'type': log_type,
                        'raw_line': line.strip()
                    }
                    
                    if log_type in ['ssh_login', 'ssh_failed']:
                        entry['username'] = match.group(2)
                        entry['source_ip'] = match.group(3)
                    elif log_type == 'sudo_cmd':
                        entry['username'] = match.group(2)
                        entry['command'] = match.group(3)
                    elif log_type == 'su_switch':
                        entry['username'] = match.group(2)
                    
                    log_entries.append(entry)
                    break
        
        return log_entries
    
    def generate_sample_logs(self):
        """Generate sample log entries for demonstration"""
        import random
        
        users = ['admin', 'jdoe', 'alice', 'bob', 'service']
        ips = ['192.168.1.100', '192.168.1.101', '10.0.0.50', '172.16.1.10']
        commands = ['/bin/ls', '/usr/bin/ps', '/bin/cat /etc/passwd', '/usr/bin/netstat']
        
        sample_logs = []
        base_time = datetime.now() - timedelta(days=7)
        
        # Generate normal activity patterns
        for day in range(7):
            current_date = base_time + timedelta(days=day)
            
            # Normal SSH logins (business hours)
            for hour in range(8, 18):
                for _ in range(random.randint(2, 8)):
                    timestamp = current_date.replace(hour=hour, minute=random.randint(0, 59))
                    user = random.choice(users[:3])  # Normal users
                    ip = random.choice(ips[:2])  # Internal IPs
                    
                    log_line = f"{timestamp.strftime('%b %d %H:%M:%S')} server sshd[12345]: Accepted password for {user} from {ip} port 22 ssh2"
                    sample_logs.append(log_line)
            
            # Some failed attempts (normal level)
            for _ in range(random.randint(1, 3)):
                timestamp = current_date.replace(hour=random.randint(0, 23), minute=random.randint(0, 59))
                user = random.choice(['admin', 'root', 'test'])
                ip = random.choice(ips)
                
                log_line = f"{timestamp.strftime('%b %d %H:%M:%S')} server sshd[12346]: Failed password for {user} from {ip} port 22 ssh2"
                sample_logs.append(log_line)
            
            # Sudo commands
            for _ in range(random.randint(5, 15)):
                timestamp = current_date.replace(hour=random.randint(8, 18), minute=random.randint(0, 59))
                user = random.choice(users[:3])
                command = random.choice(commands[:2])  # Normal commands
                
                log_line = f"{timestamp.strftime('%b %d %H:%M:%S')} server sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={command}"
                sample_logs.append(log_line)
        
        # Add some anomalous activity for detection
        anomaly_time = datetime.now() - timedelta(hours=2)
        
        # Brute force attempt
        for _ in range(25):
            timestamp = anomaly_time + timedelta(minutes=random.randint(0, 10))
            log_line = f"{timestamp.strftime('%b %d %H:%M:%S')} server sshd[12347]: Failed password for admin from 203.0.113.10 port 22 ssh2"
            sample_logs.append(log_line)
        
        # Suspicious commands
        for _ in range(3):
            timestamp = anomaly_time + timedelta(minutes=random.randint(15, 30))
            user = 'admin'
            suspicious_cmd = random.choice(['/bin/cat /etc/shadow', '/usr/bin/netstat -tulpn', '/bin/ps aux | grep ssh'])
            
            log_line = f"{timestamp.strftime('%b %d %H:%M:%S')} server sudo: {user} : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND={suspicious_cmd}"
            sample_logs.append(log_line)
        
        return sample_logs
    
    def create_baseline(self, log_entries):
        """Create behavioral baseline from log entries"""
        print("[+] Creating behavioral baseline...")
        
        baseline = {
            'user_activity': defaultdict(lambda: {
                'login_times': [],
                'source_ips': [],
                'commands': [],
                'login_frequency': 0,
                'failed_logins': 0
            }),
            'ip_activity': defaultdict(lambda: {
                'users': [],
                'login_attempts': 0,
                'failed_attempts': 0,
                'first_seen': None,
                'last_seen': None
            }),
            'time_patterns': defaultdict(int),
            'command_patterns': defaultdict(int),
            'failure_patterns': defaultdict(int)
        }
        
        for entry in log_entries:
            timestamp = entry['timestamp']
            entry_type = entry['type']
            
            # Extract hour for time pattern analysis
            try:
                time_obj = datetime.strptime(f"2024 {timestamp}", "%Y %b %d %H:%M:%S")
                hour = time_obj.hour
                baseline['time_patterns'][hour] += 1
            except:
                continue
            
            if 'username' in entry:
                username = entry['username']
                
                if entry_type == 'ssh_login':
                    baseline['user_activity'][username]['login_frequency'] += 1
                    baseline['user_activity'][username]['login_times'].append(hour)
                    if 'source_ip' in entry:
                        baseline['user_activity'][username]['source_ips'].append(entry['source_ip'])
                        
                        # IP activity tracking
                        ip = entry['source_ip']
                        baseline['ip_activity'][ip]['users'].append(username)
                        baseline['ip_activity'][ip]['login_attempts'] += 1
                        baseline['ip_activity'][ip]['last_seen'] = timestamp
                        if baseline['ip_activity'][ip]['first_seen'] is None:
                            baseline['ip_activity'][ip]['first_seen'] = timestamp
                
                elif entry_type == 'ssh_failed':
                    baseline['user_activity'][username]['failed_logins'] += 1
                    baseline['failure_patterns'][username] += 1
                    if 'source_ip' in entry:
                        baseline['ip_activity'][entry['source_ip']]['failed_attempts'] += 1
                
                elif entry_type == 'sudo_cmd' and 'command' in entry:
                    command = entry['command']
                    baseline['user_activity'][username]['commands'].append(command)
                    baseline['command_patterns'][command] += 1
        
        # Calculate statistics
        for username, data in baseline['user_activity'].items():
            if data['login_times']:
                data['avg_login_hour'] = statistics.mean(data['login_times'])
                data['login_hour_stddev'] = statistics.stdev(data['login_times']) if len(data['login_times']) > 1 else 0
            
            data['unique_ips'] = len(set(data['source_ips']))
            data['unique_commands'] = len(set(data['commands']))
        
        self.baseline_data = baseline
        print(f"[+] Baseline created with {len(log_entries)} log entries")
        return baseline
    
    def detect_anomalies(self, new_log_entries, sensitivity=0.7):
        """Detect anomalies against established baseline"""
        print(f"[+] Detecting anomalies with sensitivity: {sensitivity}")
        
        anomalies = []
        
        for entry in new_log_entries:
            entry_anomalies = []
            
            if 'username' in entry:
                username = entry['username']
                baseline_user = self.baseline_data['user_activity'].get(username, {})
                
                # Time-based anomalies
                try:
                    time_obj = datetime.strptime(f"2024 {entry['timestamp']}", "%Y %b %d %H:%M:%S")
                    hour = time_obj.hour
                    
                    if baseline_user.get('avg_login_hour'):
                        avg_hour = baseline_user['avg_login_hour']
                        stddev = baseline_user.get('login_hour_stddev', 3)
                        
                        if abs(hour - avg_hour) > (2 * stddev * sensitivity):
                            entry_anomalies.append({
                                'type': 'unusual_time',
                                'severity': 'MEDIUM',
                                'description': f"Login at unusual time: {hour}:00 (normal: {avg_hour:.1f}±{stddev:.1f})"
                            })
                except:
                    pass
                
                # IP-based anomalies
                if entry['type'] in ['ssh_login', 'ssh_failed'] and 'source_ip' in entry:
                    source_ip = entry['source_ip']
                    known_ips = set(baseline_user.get('source_ips', []))
                    
                    if source_ip not in known_ips:
                        entry_anomalies.append({
                            'type': 'new_source_ip',
                            'severity': 'HIGH',
                            'description': f"Login from new IP: {source_ip}"
                        })
                    
                    # Check for brute force patterns
                    ip_data = self.baseline_data['ip_activity'].get(source_ip, {})
                    failure_rate = ip_data.get('failed_attempts', 0) / max(ip_data.get('login_attempts', 1), 1)
                    
                    if failure_rate > 0.8 and ip_data.get('failed_attempts', 0) > 10:
                        entry_anomalies.append({
                            'type': 'brute_force_pattern',
                            'severity': 'CRITICAL',
                            'description': f"High failure rate from {source_ip}: {failure_rate:.1%}"
                        })
                
                # Command-based anomalies
                if entry['type'] == 'sudo_cmd' and 'command' in entry:
                    command = entry['command']
                    user_commands = set(baseline_user.get('commands', []))
                    
                    if command not in user_commands:
                        # Check if it's a suspicious command
                        suspicious_patterns = [
                            '/etc/shadow', '/etc/passwd', 'netstat', 'ps aux',
                            'whoami', 'id', 'uname', '/proc/', 'history'
                        ]
                        
                        if any(pattern in command for pattern in suspicious_patterns):
                            entry_anomalies.append({
                                'type': 'suspicious_command',
                                'severity': 'HIGH',
                                'description': f"Suspicious new command: {command}"
                            })
                        else:
                            entry_anomalies.append({
                                'type': 'new_command',
                                'severity': 'LOW',
                                'description': f"New command executed: {command}"
                            })
                
                # New user anomaly
                if username not in self.baseline_data['user_activity']:
                    entry_anomalies.append({
                        'type': 'new_user',
                        'severity': 'MEDIUM',
                        'description': f"Activity from new user: {username}"
                    })
            
            if entry_anomalies:
                anomaly = {
                    'timestamp': entry['timestamp'],
                    'log_entry': entry,
                    'anomalies': entry_anomalies,
                    'risk_score': self.calculate_risk_score(entry_anomalies)
                }
                anomalies.append(anomaly)
        
        self.anomalies = anomalies
        return anomalies
    
    def calculate_risk_score(self, anomaly_list):
        """Calculate risk score based on anomaly types"""
        score_map = {
            'CRITICAL': 40,
            'HIGH': 25,
            'MEDIUM': 15,
            'LOW': 5
        }
        
        total_score = sum(score_map.get(anomaly['severity'], 0) for anomaly in anomaly_list)
        return min(total_score, 100)
    
    def generate_report(self, anomalies):
        """Generate comprehensive anomaly detection report"""
        report = {
            'metadata': {
                'generated_by': 'BOFA Log Baseliner',
                'version': self.version,
                'timestamp': datetime.now().isoformat(),
                'total_anomalies': len(anomalies)
            },
            'baseline_summary': {
                'unique_users': len(self.baseline_data['user_activity']),
                'unique_ips': len(self.baseline_data['ip_activity']),
                'total_commands': len(self.baseline_data['command_patterns']),
                'peak_activity_hour': max(self.baseline_data['time_patterns'], key=self.baseline_data['time_patterns'].get) if self.baseline_data['time_patterns'] else 'Unknown'
            },
            'anomaly_analysis': {
                'high_risk_anomalies': [a for a in anomalies if a['risk_score'] >= 50],
                'by_type': defaultdict(int),
                'by_severity': defaultdict(int),
                'top_risk_scores': sorted([a['risk_score'] for a in anomalies], reverse=True)[:10]
            },
            'anomalies': anomalies,
            'recommendations': [
                "Investigate high-risk anomalies immediately",
                "Review new user activity for legitimacy",
                "Monitor suspicious command executions",
                "Implement additional monitoring for new source IPs",
                "Consider implementing MFA for unusual time logins",
                "Regular baseline updates recommended"
            ]
        }
        
        # Calculate anomaly type statistics
        for anomaly in anomalies:
            for sub_anomaly in anomaly['anomalies']:
                report['anomaly_analysis']['by_type'][sub_anomaly['type']] += 1
                report['anomaly_analysis']['by_severity'][sub_anomaly['severity']] += 1
        
        # Save report
        report_file = f"log_baseline_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Report saved to: {report_file}")
        return report

def main():
    parser = argparse.ArgumentParser(description="Log Baseliner - Behavioral Analysis and Anomaly Detection Tool")
    parser.add_argument("-f", "--file", help="Log file path (uses sample data if not provided)")
    parser.add_argument("-b", "--baseline", help="Create baseline from log file")
    parser.add_argument("-a", "--analyze", help="Analyze new logs against baseline")
    parser.add_argument("-s", "--sensitivity", type=float, default=0.7, help="Anomaly detection sensitivity (0.1-1.0)")
    parser.add_argument("--save-baseline", help="Save baseline to file")
    parser.add_argument("--load-baseline", help="Load baseline from file")
    parser.add_argument("--demo", action="store_true", help="Run demonstration with sample data")
    
    if len(sys.argv) == 1:
        parser.print_help()
        return
        
    args = parser.parse_args()
    
    baseliner = LogBaseliner()
    baseliner.print_banner()
    
    print("[!] EDUCATIONAL SIMULATION - Behavioral analysis training")
    print("[!] For authorized security monitoring and analysis\n")
    
    if args.demo:
        print("[+] Running demonstration with sample data...")
        
        # Create baseline from sample data
        sample_logs = baseliner.parse_auth_logs("/nonexistent/path")
        baseline = baseliner.create_baseline(sample_logs[:200])  # Use first 200 entries for baseline
        
        # Analyze remaining entries for anomalies
        new_entries = sample_logs[200:]  # Use remaining entries as "new" data
        anomalies = baseliner.detect_anomalies(new_entries, args.sensitivity)
        
        # Generate report
        report = baseliner.generate_report(anomalies)
        
        # Display summary
        print(f"\n{'='*60}")
        print("LOG BASELINE ANALYSIS SUMMARY")
        print(f"{'='*60}")
        print(f"Baseline Entries: 200")
        print(f"Analysis Entries: {len(new_entries)}")
        print(f"Anomalies Detected: {len(anomalies)}")
        print(f"High Risk Anomalies: {len([a for a in anomalies if a['risk_score'] >= 50])}")
        print(f"Average Risk Score: {sum(a['risk_score'] for a in anomalies) / len(anomalies):.1f}" if anomalies else "Average Risk Score: 0")
        print(f"{'='*60}")
        
        # Show top anomalies
        if anomalies:
            print("\nTOP ANOMALIES:")
            for i, anomaly in enumerate(sorted(anomalies, key=lambda x: x['risk_score'], reverse=True)[:5], 1):
                print(f"{i}. Risk Score: {anomaly['risk_score']} - {anomaly['timestamp']}")
                for sub_anomaly in anomaly['anomalies']:
                    print(f"   {sub_anomaly['severity']}: {sub_anomaly['description']}")
        
        return
    
    # Handle other command line options
    if args.baseline:
        log_entries = baseliner.parse_auth_logs(args.baseline)
        baseline = baseliner.create_baseline(log_entries)
        
        if args.save_baseline:
            with open(args.save_baseline, 'w') as f:
                json.dump(baseline, f, indent=2)
            print(f"[+] Baseline saved to: {args.save_baseline}")
    
    elif args.analyze:
        if args.load_baseline:
            with open(args.load_baseline, 'r') as f:
                baseliner.baseline_data = json.load(f)
            print(f"[+] Baseline loaded from: {args.load_baseline}")
        
        new_entries = baseliner.parse_auth_logs(args.analyze)
        anomalies = baseliner.detect_anomalies(new_entries, args.sensitivity)
        report = baseliner.generate_report(anomalies)
        
        print(f"\n[+] Detected {len(anomalies)} anomalies")
        for anomaly in anomalies[:10]:  # Show first 10
            print(f"[!] {anomaly['timestamp']} - Risk: {anomaly['risk_score']}")

if __name__ == "__main__":
    main()
