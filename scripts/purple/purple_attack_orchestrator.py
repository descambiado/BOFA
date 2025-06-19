
#!/usr/bin/env python3
"""
Purple Attack Orchestrator - Coordinated Red vs Blue Training Tool
Developed by @descambiado for BOFA Suite
Educational and authorized testing only
"""

import json
import subprocess
import time
import random
import threading
from datetime import datetime, timedelta
import argparse
import sys
import os

class PurpleAttackOrchestrator:
    def __init__(self):
        self.version = "1.0"
        self.author = "@descambiado"
        self.scenarios = self.load_attack_scenarios()
        self.blue_team_alerts = []
        self.red_team_actions = []
        
    def print_banner(self):
        banner = """
╔══════════════════════════════════════════════════════════════════╗
║              PURPLE ATTACK ORCHESTRATOR v1.0                    ║
║              Coordinated Red vs Blue Training                    ║
║                    By @descambiado                               ║
╚══════════════════════════════════════════════════════════════════╝
        """
        print(banner)
        
    def load_attack_scenarios(self):
        """Load predefined attack scenarios"""
        return {
            'credential_harvesting': {
                'name': 'Credential Harvesting Campaign',
                'duration': 30,  # minutes
                'phases': [
                    {'name': 'Initial Access', 'duration': 5, 'mitre': 'T1078'},
                    {'name': 'Credential Dumping', 'duration': 10, 'mitre': 'T1003'},
                    {'name': 'Lateral Movement', 'duration': 10, 'mitre': 'T1021'},
                    {'name': 'Persistence', 'duration': 5, 'mitre': 'T1053'}
                ],
                'detection_points': ['Failed Login Attempts', 'LSASS Access', 'Unusual Network Traffic', 'New Scheduled Tasks'],
                'difficulty': 'MEDIUM'
            },
            'advanced_persistent_threat': {
                'name': 'Advanced Persistent Threat Simulation',
                'duration': 60,
                'phases': [
                    {'name': 'Reconnaissance', 'duration': 10, 'mitre': 'T1087'},
                    {'name': 'Initial Compromise', 'duration': 15, 'mitre': 'T1566'},
                    {'name': 'Establish Foothold', 'duration': 15, 'mitre': 'T1055'},
                    {'name': 'Data Collection', 'duration': 15, 'mitre': 'T1005'},
                    {'name': 'Exfiltration', 'duration': 5, 'mitre': 'T1041'}
                ],
                'detection_points': ['Suspicious Email', 'Process Injection', 'File System Changes', 'Network Anomalies'],
                'difficulty': 'HIGH'
            },
            'insider_threat': {
                'name': 'Malicious Insider Simulation',
                'duration': 45,
                'phases': [
                    {'name': 'Privilege Abuse', 'duration': 15, 'mitre': 'T1078'},
                    {'name': 'Data Access', 'duration': 20, 'mitre': 'T1005'},
                    {'name': 'Covert Exfiltration', 'duration': 10, 'mitre': 'T1048'}
                ],
                'detection_points': ['Unusual Data Access', 'Off-Hours Activity', 'Large File Transfers'],
                'difficulty': 'MEDIUM'
            },
            'ransomware_attack': {
                'name': 'Ransomware Campaign Simulation',
                'duration': 40,
                'phases': [
                    {'name': 'Initial Infection', 'duration': 5, 'mitre': 'T1204'},
                    {'name': 'System Discovery', 'duration': 10, 'mitre': 'T1082'},
                    {'name': 'File Encryption Prep', 'duration': 15, 'mitre': 'T1486'},
                    {'name': 'Ransom Demand', 'duration': 10, 'mitre': 'T1491'}
                ],
                'detection_points': ['Suspicious File Activity', 'System Information Gathering', 'Mass File Modifications'],
                'difficulty': 'HIGH'
            }
        }
    
    def simulate_red_team_action(self, phase, scenario_name):
        """Simulate red team attack action"""
        action = {
            'timestamp': datetime.now().isoformat(),
            'scenario': scenario_name,
            'phase': phase['name'],
            'mitre_technique': phase['mitre'],
            'status': 'EXECUTED',
            'artifacts': []
        }
        
        # Simulate different types of actions based on phase
        if 'Access' in phase['name']:
            action['artifacts'] = [
                f"Login attempt from IP: 192.168.{random.randint(1, 254)}.{random.randint(1, 254)}",
                f"User agent: {random.choice(['Mozilla/5.0', 'curl/7.68.0', 'Python-requests/2.25.1'])}",
                f"Authentication method: {random.choice(['Password', 'Certificate', 'Token'])}"
            ]
        elif 'Credential' in phase['name']:
            action['artifacts'] = [
                f"Process accessed: lsass.exe (PID: {random.randint(1000, 9999)})",
                f"Memory dump created: C:\\temp\\lsass_{random.randint(1000, 9999)}.dmp",
                f"Credentials extracted: {random.randint(5, 25)} accounts"
            ]
        elif 'Movement' in phase['name']:
            action['artifacts'] = [
                f"SMB connection to: \\\\SRV-{random.randint(1, 10):02d}\\C$",
                f"Remote execution via: {random.choice(['WMI', 'PowerShell', 'PsExec'])}",
                f"Target host: WORKSTATION-{random.randint(1, 50):02d}"
            ]
        elif 'Persistence' in phase['name']:
            action['artifacts'] = [
                f"Scheduled task created: {random.choice(['WindowsUpdate', 'SystemMaintenance', 'BackupTask'])}",
                f"Registry key modified: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                f"Service installed: {random.choice(['WinDefender', 'SystemHelper', 'UpdateService'])}"
            ]
        
        self.red_team_actions.append(action)
        return action
    
    def simulate_blue_team_detection(self, red_action, detection_delay=None):
        """Simulate blue team detection based on red team action"""
        if detection_delay is None:
            detection_delay = random.uniform(0.5, 5.0)  # Random detection delay
        
        # Simulate detection probability
        detection_probability = random.uniform(0.3, 0.9)
        detected = random.random() < detection_probability
        
        alert = {
            'timestamp': (datetime.fromisoformat(red_action['timestamp']) + timedelta(minutes=detection_delay)).isoformat(),
            'detected': detected,
            'red_action_id': red_action.get('id', 'unknown'),
            'scenario': red_action['scenario'],
            'phase': red_action['phase'],
            'detection_delay': detection_delay,
            'confidence': random.uniform(0.6, 0.95) if detected else 0
        }
        
        if detected:
            alert.update({
                'alert_type': random.choice(['High', 'Medium', 'Low']),
                'description': f"Suspicious activity detected in {red_action['phase']}",
                'mitre_technique': red_action['mitre_technique'],
                'recommended_actions': [
                    'Isolate affected systems',
                    'Collect forensic evidence',
                    'Reset compromised credentials',
                    'Monitor for lateral movement'
                ]
            })
        else:
            alert.update({
                'alert_type': 'Missed',
                'description': f"Activity in {red_action['phase']} went undetected",
                'improvement_suggestions': [
                    'Enhance monitoring coverage',
                    'Tune detection rules',
                    'Implement additional data sources',
                    'Review alert thresholds'
                ]
            })
        
        self.blue_team_alerts.append(alert)
        return alert
    
    def execute_scenario(self, scenario_name, speed_multiplier=1.0):
        """Execute a complete purple team scenario"""
        if scenario_name not in self.scenarios:
            print(f"[!] Unknown scenario: {scenario_name}")
            return
        
        scenario = self.scenarios[scenario_name]
        print(f"[+] Starting Purple Team Exercise: {scenario['name']}")
        print(f"[+] Estimated duration: {scenario['duration']} minutes")
        print(f"[+] Difficulty: {scenario['difficulty']}")
        print(f"[+] Speed multiplier: {speed_multiplier}x")
        
        exercise_start = datetime.now()
        
        for i, phase in enumerate(scenario['phases'], 1):
            print(f"\n{'='*60}")
            print(f"PHASE {i}: {phase['name']} (MITRE: {phase['mitre']})")
            print(f"{'='*60}")
            
            # Execute red team action
            print(f"[RED] Executing {phase['name']}...")
            red_action = self.simulate_red_team_action(phase, scenario_name)
            red_action['id'] = f"RED_{i:02d}_{int(time.time())}"
            
            print(f"[RED] Action completed: {red_action['status']}")
            for artifact in red_action['artifacts']:
                print(f"[RED]   - {artifact}")
            
            # Simulate blue team detection with delay
            time.sleep(random.uniform(1, 3) / speed_multiplier)
            
            print(f"[BLUE] Monitoring for suspicious activity...")
            alert = self.simulate_blue_team_detection(red_action)
            
            if alert['detected']:
                print(f"[BLUE] 🚨 ALERT TRIGGERED: {alert['alert_type']} confidence")
                print(f"[BLUE] Detection delay: {alert['detection_delay']:.1f} minutes")
                print(f"[BLUE] Description: {alert['description']}")
                print(f"[BLUE] Recommended actions:")
                for action in alert['recommended_actions']:
                    print(f"[BLUE]   - {action}")
            else:
                print(f"[BLUE] ❌ No detection - Activity missed")
                print(f"[BLUE] Improvement needed:")
                for suggestion in alert['improvement_suggestions']:
                    print(f"[BLUE]   - {suggestion}")
            
            # Phase duration simulation
            phase_duration = phase['duration'] / speed_multiplier
            print(f"\n[*] Phase duration: {phase_duration:.1f} minutes (simulated)")
            time.sleep(min(phase_duration * 6, 30))  # Max 30 seconds per phase
        
        # Exercise completion
        exercise_end = datetime.now()
        exercise_duration = (exercise_end - exercise_start).total_seconds() / 60
        
        print(f"\n{'='*60}")
        print("PURPLE TEAM EXERCISE COMPLETED")
        print(f"{'='*60}")
        print(f"Scenario: {scenario['name']}")
        print(f"Exercise Duration: {exercise_duration:.1f} minutes")
        print(f"Red Team Actions: {len(self.red_team_actions)}")
        print(f"Blue Team Detections: {len([a for a in self.blue_team_alerts if a['detected']])}")
        print(f"Detection Rate: {len([a for a in self.blue_team_alerts if a['detected']]) / len(self.blue_team_alerts) * 100:.1f}%")
        
        return self.generate_exercise_report(scenario_name, exercise_start, exercise_end)
    
    def generate_exercise_report(self, scenario_name, start_time, end_time):
        """Generate comprehensive exercise report"""
        scenario = self.scenarios[scenario_name]
        detected_alerts = [a for a in self.blue_team_alerts if a['detected']]
        missed_alerts = [a for a in self.blue_team_alerts if not a['detected']]
        
        report = {
            'metadata': {
                'scenario': scenario_name,
                'exercise_name': scenario['name'],
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_minutes': (end_time - start_time).total_seconds() / 60,
                'generated_by': 'BOFA Purple Attack Orchestrator',
                'version': self.version
            },
            'scenario_details': scenario,
            'performance_metrics': {
                'total_red_actions': len(self.red_team_actions),
                'total_blue_alerts': len(self.blue_team_alerts),
                'detections': len(detected_alerts),
                'missed_detections': len(missed_alerts),
                'detection_rate': len(detected_alerts) / len(self.blue_team_actions) * 100 if self.blue_team_alerts else 0,
                'average_detection_delay': sum(a['detection_delay'] for a in detected_alerts) / len(detected_alerts) if detected_alerts else 0,
                'average_confidence': sum(a['confidence'] for a in detected_alerts) / len(detected_alerts) if detected_alerts else 0
            },
            'timeline': {
                'red_team_actions': self.red_team_actions,
                'blue_team_alerts': self.blue_team_alerts
            },
            'lessons_learned': {
                'strong_detections': [
                    f"Successfully detected {phase}" for phase in set(a['phase'] for a in detected_alerts)
                ],
                'detection_gaps': [
                    f"Missed detection in {phase}" for phase in set(a['phase'] for a in missed_alerts)
                ],
                'recommendations': [
                    "Improve detection coverage for missed phases",
                    "Reduce average detection delay",
                    "Increase confidence levels in alerts",
                    "Implement additional monitoring for gaps identified",
                    "Regular purple team exercises recommended"
                ]
            },
            'mitre_coverage': {
                'techniques_simulated': list(set(action['mitre_technique'] for action in self.red_team_actions)),
                'techniques_detected': list(set(alert['mitre_technique'] for alert in detected_alerts if 'mitre_technique' in alert)),
                'coverage_percentage': len(set(alert.get('mitre_technique') for alert in detected_alerts if alert.get('mitre_technique'))) / len(set(action['mitre_technique'] for action in self.red_team_actions)) * 100 if self.red_team_actions else 0
            }
        }
        
        # Save report
        report_file = f"purple_exercise_report_{scenario_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Exercise report saved to: {report_file}")
        return report
    
    def list_scenarios(self):
        """List available attack scenarios"""
        print("\nAVAILABLE PURPLE TEAM SCENARIOS:")
        print("=" * 60)
        
        for name, scenario in self.scenarios.items():
            print(f"\n📋 Scenario: {name}")
            print(f"   Name: {scenario['name']}")
            print(f"   Duration: {scenario['duration']} minutes")
            print(f"   Difficulty: {scenario['difficulty']}")
            print(f"   Phases: {len(scenario['phases'])}")
            print(f"   Detection Points: {len(scenario['detection_points'])}")
            
            print("   ATTACK PHASES:")
            for i, phase in enumerate(scenario['phases'], 1):
                print(f"     {i}. {phase['name']} ({phase['mitre']}) - {phase['duration']}min")
    
    def interactive_mode(self):
        """Run interactive purple team exercise"""
        print("\n🟣 PURPLE TEAM INTERACTIVE MODE")
        print("=" * 60)
        
        self.list_scenarios()
        
        while True:
            print(f"\nAvailable scenarios: {', '.join(self.scenarios.keys())}")
            scenario = input("\nSelect scenario (or 'quit' to exit): ").strip()
            
            if scenario.lower() == 'quit':
                break
            
            if scenario not in self.scenarios:
                print("[!] Invalid scenario. Please try again.")
                continue
            
            try:
                speed = float(input("Speed multiplier (1.0 = normal, 2.0 = 2x faster): ") or "1.0")
            except ValueError:
                speed = 1.0
            
            print(f"\n[+] Starting scenario: {scenario}")
            report = self.execute_scenario(scenario, speed)
            
            print("\n" + "="*60)
            print("EXERCISE SUMMARY")
            print("="*60)
            print(f"Detection Rate: {report['performance_metrics']['detection_rate']:.1f}%")
            print(f"Average Detection Delay: {report['performance_metrics']['average_detection_delay']:.1f} minutes")
            print(f"MITRE ATT&CK Coverage: {report['mitre_coverage']['coverage_percentage']:.1f}%")
            
            continue_exercise = input("\nRun another scenario? (y/n): ").strip().lower()
            if continue_exercise != 'y':
                break

def main():
    parser = argparse.ArgumentParser(description="Purple Attack Orchestrator - Coordinated Red vs Blue Training Tool")
    parser.add_argument("-s", "--scenario", help="Run specific scenario")
    parser.add_argument("-l", "--list", action="store_true", help="List available scenarios")
    parser.add_argument("-i", "--interactive", action="store_true", help="Interactive mode")
    parser.add_argument("--speed", type=float, default=1.0, help="Speed multiplier for scenario execution")
    parser.add_argument("--help-purple", action="store_true", help="Show purple team methodology")
    
    if len(sys.argv) == 1:
        parser.print_help()
        return
        
    args = parser.parse_args()
    
    if args.help_purple:
        print("""
PURPLE TEAM METHODOLOGY:
=======================

Purple Team combines Red Team (offensive) and Blue Team (defensive) 
activities to improve overall security posture through collaborative testing.

KEY PRINCIPLES:
1. Coordinated Attack Simulation
   - Red team executes realistic attack scenarios
   - Blue team monitors and responds in real-time
   - Communication between teams throughout exercise

2. Detection Validation
   - Test existing security controls
   - Identify detection gaps
   - Measure response effectiveness

3. Continuous Improvement
   - Document lessons learned
   - Update detection rules
   - Enhance monitoring capabilities

EXERCISE PHASES:
1. Planning - Define scenarios and objectives
2. Execution - Run coordinated attack/defense
3. Analysis - Review detection effectiveness
4. Improvement - Implement fixes and enhancements

BENEFITS:
- Improved detection capabilities
- Faster incident response
- Better security team collaboration
- Realistic security validation
- Measurable security improvements
        """)
        return
    
    orchestrator = PurpleAttackOrchestrator()
    orchestrator.print_banner()
    
    print("[!] EDUCATIONAL SIMULATION - Purple team training exercise")
    print("[!] For authorized security training and validation only\n")
    
    if args.list:
        orchestrator.list_scenarios()
    elif args.interactive:
        orchestrator.interactive_mode()
    elif args.scenario:
        if args.scenario in orchestrator.scenarios:
            orchestrator.execute_scenario(args.scenario, args.speed)
        else:
            print(f"[!] Unknown scenario: {args.scenario}")
            orchestrator.list_scenarios()
    else:
        print("[!] Please specify --scenario, --list, or --interactive")
        orchestrator.list_scenarios()

if __name__ == "__main__":
    main()
