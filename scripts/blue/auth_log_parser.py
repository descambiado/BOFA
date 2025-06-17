
#!/usr/bin/env python3
"""
Authentication Log Parser
Advanced authentication event analysis for security monitoring
Desarrollado por @descambiado para BOFA
"""

import re
import sys
import json
from datetime import datetime
from collections import defaultdict, Counter

def print_banner():
    banner = """
╔══════════════════════════════════════════════════════════════════╗
║                   AUTHENTICATION LOG PARSER                     ║
║              Security Event Analysis & Detection                ║
╚══════════════════════════════════════════════════════════════════╝
"""
    print(banner)

class AuthLogParser:
    def __init__(self):
        self.events = []
        self.patterns = {
            'ssh_success': r'Accepted \w+ for (\w+) from ([\d\.]+) port (\d+)',
            'ssh_failure': r'Failed password for (\w+) from ([\d\.]+) port (\d+)',
            'sudo_success': r'(\w+) : TTY=\w+ ; PWD=.* ; USER=root ; COMMAND=(.*)',
            'sudo_failure': r'(\w+) : command not allowed',
            'login_success': r'session opened for user (\w+)',
            'login_failure': r'authentication failure.*user=(\w+)',
            'invalid_user': r'Invalid user (\w+) from ([\d\.]+)',
            'brute_force': r'Failed password for invalid user (\w+) from ([\d\.]+)'
        }
        
    def parse_log_file(self, log_file):
        """Parsea archivo de log de autenticación"""
        try:
            with open(log_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    self.parse_line(line.strip(), line_num)
        except FileNotFoundError:
            print(f"[-] Error: Archivo {log_file} no encontrado")
            return False
        except Exception as e:
            print(f"[-] Error leyendo archivo: {str(e)}")
            return False
        return True
    
    def parse_line(self, line, line_num):
        """Parsea una línea individual del log"""
        # Extraer timestamp
        timestamp_match = re.search(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', line)
        timestamp = timestamp_match.group(1) if timestamp_match else "Unknown"
        
        # Extraer hostname
        hostname_match = re.search(r'^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(\w+)', line)
        hostname = hostname_match.group(1) if hostname_match else "Unknown"
        
        # Analizar cada patrón
        for event_type, pattern in self.patterns.items():
            match = re.search(pattern, line)
            if match:
                event = {
                    'line_number': line_num,
                    'timestamp': timestamp,
                    'hostname': hostname,
                    'event_type': event_type,
                    'raw_line': line,
                    'parsed_data': match.groups()
                }
                self.events.append(event)
                break
    
    def analyze_events(self):
        """Analiza eventos para detectar patrones sospechosos"""
        analysis = {
            'total_events': len(self.events),
            'event_summary': Counter(),
            'suspicious_activity': [],
            'ip_analysis': defaultdict(list),
            'user_analysis': defaultdict(list),
            'recommendations': []
        }
        
        # Contar tipos de eventos
        for event in self.events:
            analysis['event_summary'][event['event_type']] += 1
            
            # Análisis por IP
            if len(event['parsed_data']) > 1 and '.' in str(event['parsed_data'][1]):
                ip = event['parsed_data'][1]
                analysis['ip_analysis'][ip].append(event)
            
            # Análisis por usuario
            if len(event['parsed_data']) > 0:
                user = event['parsed_data'][0]
                analysis['user_analysis'][user].append(event)
        
        # Detectar actividad sospechosa
        self.detect_brute_force_attacks(analysis)
        self.detect_privilege_escalation(analysis)
        self.detect_unusual_access_patterns(analysis)
        
        # Generar recomendaciones
        self.generate_recommendations(analysis)
        
        return analysis
    
    def detect_brute_force_attacks(self, analysis):
        """Detecta ataques de fuerza bruta"""
        threshold = 5  # 5 o más intentos fallidos
        
        for ip, events in analysis['ip_analysis'].items():
            failed_attempts = [e for e in events if 'failure' in e['event_type'] or 'invalid' in e['event_type']]
            
            if len(failed_attempts) >= threshold:
                analysis['suspicious_activity'].append({
                    'type': 'Brute Force Attack',
                    'description': f"IP {ip} tiene {len(failed_attempts)} intentos fallidos",
                    'severity': 'HIGH' if len(failed_attempts) > 10 else 'MEDIUM',
                    'ip': ip,
                    'failed_attempts': len(failed_attempts)
                })
    
    def detect_privilege_escalation(self, analysis):
        """Detecta intentos de escalada de privilegios"""
        for user, events in analysis['user_analysis'].items():
            sudo_events = [e for e in events if 'sudo' in e['event_type']]
            failed_sudo = [e for e in sudo_events if 'failure' in e['event_type']]
            
            if len(failed_sudo) > 3:
                analysis['suspicious_activity'].append({
                    'type': 'Privilege Escalation Attempt',
                    'description': f"Usuario {user} tiene {len(failed_sudo)} intentos sudo fallidos",
                    'severity': 'MEDIUM',
                    'user': user,
                    'failed_sudo_attempts': len(failed_sudo)
                })
    
    def detect_unusual_access_patterns(self, analysis):
        """Detecta patrones de acceso inusuales"""
        # Accesos fuera de horario laboral
        unusual_hours = []
        for event in self.events:
            if 'success' in event['event_type']:
                # Extraer hora del timestamp
                time_match = re.search(r'(\d{2}):(\d{2}):(\d{2})', event['timestamp'])
                if time_match:
                    hour = int(time_match.group(1))
                    # Considerar 22:00 - 06:00 como horario inusual
                    if hour >= 22 or hour <= 6:
                        unusual_hours.append(event)
        
        if len(unusual_hours) > 0:
            analysis['suspicious_activity'].append({
                'type': 'Unusual Access Hours',
                'description': f"{len(unusual_hours)} accesos exitosos fuera del horario laboral",
                'severity': 'LOW',
                'count': len(unusual_hours)
            })
    
    def generate_recommendations(self, analysis):
        """Genera recomendaciones de seguridad"""
        recommendations = []
        
        # Basado en análisis de eventos
        if analysis['event_summary'].get('ssh_failure', 0) > 10:
            recommendations.append("Considerar implementar fail2ban para SSH")
        
        if analysis['event_summary'].get('invalid_user', 0) > 5:
            recommendations.append("Revisar configuración SSH - muchos usuarios inválidos")
        
        if len(analysis['suspicious_activity']) > 0:
            recommendations.append("Revisar actividad sospechosa detectada")
            recommendations.append("Considerar implementar monitoreo en tiempo real")
        
        if analysis['event_summary'].get('sudo_failure', 0) > 0:
            recommendations.append("Revisar políticas de sudo y privilegios de usuarios")
        
        analysis['recommendations'] = recommendations
    
    def generate_report(self, analysis):
        """Genera reporte detallado"""
        print("\n" + "="*70)
        print("                    REPORTE DE ANÁLISIS")
        print("="*70)
        
        print(f"\n[+] Total de eventos analizados: {analysis['total_events']}")
        
        print(f"\n[+] Resumen por tipo de evento:")
        for event_type, count in analysis['event_summary'].items():
            print(f"    - {event_type}: {count}")
        
        print(f"\n[+] Actividad sospechosa detectada: {len(analysis['suspicious_activity'])}")
        for activity in analysis['suspicious_activity']:
            severity_color = {
                'HIGH': '🔴',
                'MEDIUM': '🟡', 
                'LOW': '🟢'
            }.get(activity['severity'], '⚪')
            
            print(f"    {severity_color} [{activity['severity']}] {activity['type']}")
            print(f"      {activity['description']}")
        
        print(f"\n[+] IPs más activas:")
        sorted_ips = sorted(analysis['ip_analysis'].items(), 
                          key=lambda x: len(x[1]), reverse=True)[:5]
        for ip, events in sorted_ips:
            print(f"    - {ip}: {len(events)} eventos")
        
        print(f"\n[+] Usuarios más activos:")
        sorted_users = sorted(analysis['user_analysis'].items(),
                            key=lambda x: len(x[1]), reverse=True)[:5]
        for user, events in sorted_users:
            print(f"    - {user}: {len(events)} eventos")
        
        print(f"\n[+] Recomendaciones de seguridad:")
        for i, rec in enumerate(analysis['recommendations'], 1):
            print(f"    {i}. {rec}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 auth_log_parser.py <log_file>")
        print("\nEjemplos de archivos de log:")
        print("  - /var/log/auth.log (Ubuntu/Debian)")
        print("  - /var/log/secure (CentOS/RHEL)")
        print("  - /var/log/messages (algunos sistemas)")
        return
    
    log_file = sys.argv[1]
    
    print_banner()
    print(f"[+] Analizando archivo: {log_file}")
    
    parser = AuthLogParser()
    
    if parser.parse_log_file(log_file):
        print(f"[+] Log parseado exitosamente - {len(parser.events)} eventos encontrados")
        
        analysis = parser.analyze_events()
        parser.generate_report(analysis)
        
        # Guardar reporte JSON
        report_file = f"auth_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(report_file, 'w') as f:
                json.dump(analysis, f, indent=2, default=str)
            print(f"\n[+] Reporte detallado guardado en: {report_file}")
        except Exception as e:
            print(f"\n[-] Error guardando reporte: {str(e)}")
    else:
        print("[-] Error procesando el archivo de log")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help']:
        print("Authentication Log Parser")
        print("Analiza logs de autenticación para detectar actividad sospechosa")
        print("\nCaracterísticas:")
        print("- Detección de ataques de fuerza bruta")
        print("- Análisis de escalada de privilegios")
        print("- Patrones de acceso inusuales")
        print("- Reporte JSON detallado")
        print("\nUso: python3 auth_log_parser.py /var/log/auth.log")
    else:
        main()
