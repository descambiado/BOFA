
#!/usr/bin/env python3
"""
Log Guardian - Advanced Log Monitoring and Alert System
Author: @descambiado (David Hernández Jiménez)
BOFA - Best Of All Cybersecurity Suite
Educational/Professional Use Only
"""

import os
import re
import time
import json
import argparse
import sys
from datetime import datetime, timedelta
from collections import defaultdict, deque
import threading
from pathlib import Path

class LogGuardian:
    def __init__(self, config_file=None):
        self.running = False
        self.alerts = []
        self.stats = defaultdict(int)
        self.recent_events = deque(maxlen=1000)
        
        # Default configuration
        self.config = {
            'log_files': [
                '/var/log/auth.log',
                '/var/log/syslog',
                '/var/log/secure',
                '/var/log/messages'
            ],
            'alert_rules': {
                'failed_login': {
                    'pattern': r'Failed password for .* from (\d+\.\d+\.\d+\.\d+)',
                    'threshold': 5,
                    'time_window': 300,  # 5 minutes
                    'severity': 'HIGH',
                    'description': 'Multiple failed login attempts'
                },
                'sudo_usage': {
                    'pattern': r'sudo:.*COMMAND=(.+)',
                    'threshold': 1,
                    'time_window': 60,
                    'severity': 'MEDIUM',
                    'description': 'Sudo command executed'
                },
                'root_login': {
                    'pattern': r'Accepted .* for root from (\d+\.\d+\.\d+\.\d+)',
                    'threshold': 1,
                    'time_window': 60,
                    'severity': 'CRITICAL',
                    'description': 'Root login detected'
                },
                'port_scan': {
                    'pattern': r'kernel:.*SRC=(\d+\.\d+\.\d+\.\d+).*DPT=(\d+)',
                    'threshold': 20,
                    'time_window': 60,
                    'severity': 'HIGH',
                    'description': 'Potential port scan detected'
                },
                'service_failure': {
                    'pattern': r'systemd.*Failed to start (.+)',
                    'threshold': 3,
                    'time_window': 180,
                    'severity': 'MEDIUM',
                    'description': 'Service failure detected'
                },
                'disk_full': {
                    'pattern': r'No space left on device',
                    'threshold': 1,
                    'time_window': 60,
                    'severity': 'HIGH',
                    'description': 'Disk space exhausted'
                }
            },
            'output': {
                'console': True,
                'file': None,
                'syslog': False
            },
            'monitoring': {
                'interval': 1,
                'max_alerts_per_hour': 100
            }
        }
        
        # Load custom config if provided
        if config_file and os.path.exists(config_file):
            self.load_config(config_file)
        
        # Tracking for rate limiting
        self.alert_counts = defaultdict(lambda: deque())
        self.rule_triggers = defaultdict(lambda: deque())
    
    def load_config(self, config_file):
        """Carga configuración desde archivo JSON"""
        try:
            with open(config_file, 'r') as f:
                custom_config = json.load(f)
                self.config.update(custom_config)
            print(f"✅ Configuración cargada desde {config_file}")
        except Exception as e:
            print(f"⚠️  Error cargando configuración: {e}")
    
    def save_default_config(self, filename):
        """Guarda configuración por defecto"""
        try:
            with open(filename, 'w') as f:
                json.dump(self.config, f, indent=2)
            print(f"✅ Configuración por defecto guardada en {filename}")
        except Exception as e:
            print(f"❌ Error guardando configuración: {e}")
    
    def get_available_log_files(self):
        """Obtiene archivos de log disponibles"""
        available = []
        for log_file in self.config['log_files']:
            if os.path.exists(log_file) and os.access(log_file, os.R_OK):
                available.append(log_file)
            else:
                print(f"⚠️  Log file no disponible: {log_file}")
        return available
    
    def parse_log_line(self, line, source_file):
        """Parsea una línea de log"""
        timestamp = datetime.now()
        
        # Intentar extraer timestamp del log
        timestamp_patterns = [
            r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',  # Aug 15 14:30:22
            r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})',   # 2024-08-15T14:30:22
        ]
        
        for pattern in timestamp_patterns:
            match = re.search(pattern, line)
            if match:
                try:
                    if 'T' in match.group(1):
                        timestamp = datetime.fromisoformat(match.group(1))
                    else:
                        # Para logs tipo syslog sin año
                        current_year = datetime.now().year
                        time_str = f"{current_year} {match.group(1)}"
                        timestamp = datetime.strptime(time_str, "%Y %b %d %H:%M:%S")
                except:
                    pass
                break
        
        return {
            'timestamp': timestamp,
            'line': line.strip(),
            'source': source_file
        }
    
    def check_alert_rules(self, log_entry):
        """Verifica reglas de alerta contra entrada de log"""
        alerts_triggered = []
        
        for rule_name, rule_config in self.config['alert_rules'].items():
            pattern = rule_config['pattern']
            match = re.search(pattern, log_entry['line'])
            
            if match:
                current_time = datetime.now()
                time_window = rule_config['time_window']
                threshold = rule_config['threshold']
                
                # Limpiar triggers antiguos
                cutoff_time = current_time - timedelta(seconds=time_window)
                self.rule_triggers[rule_name] = deque([
                    trigger for trigger in self.rule_triggers[rule_name]
                    if trigger['timestamp'] > cutoff_time
                ])
                
                # Añadir nuevo trigger
                trigger_data = {
                    'timestamp': current_time,
                    'match': match.groups() if match.groups() else match.group(0),
                    'log_entry': log_entry
                }
                self.rule_triggers[rule_name].append(trigger_data)
                
                # Verificar si se supera el threshold
                if len(self.rule_triggers[rule_name]) >= threshold:
                    alert = self.create_alert(rule_name, rule_config, self.rule_triggers[rule_name])
                    if self.should_send_alert(alert):
                        alerts_triggered.append(alert)
                        self.stats[f'alerts_{rule_name}'] += 1
        
        return alerts_triggered
    
    def create_alert(self, rule_name, rule_config, triggers):
        """Crea alerta basada en regla y triggers"""
        latest_trigger = triggers[-1]
        
        # Extraer información específica según el tipo de regla
        details = {}
        if rule_name == 'failed_login' and latest_trigger['match']:
            details['source_ip'] = latest_trigger['match'][0]
            details['attempt_count'] = len(triggers)
        elif rule_name == 'port_scan' and latest_trigger['match']:
            details['source_ip'] = latest_trigger['match'][0]
            details['target_port'] = latest_trigger['match'][1]
            details['packet_count'] = len(triggers)
        elif rule_name == 'sudo_usage' and latest_trigger['match']:
            details['command'] = latest_trigger['match'][0]
        elif rule_name == 'root_login' and latest_trigger['match']:
            details['source_ip'] = latest_trigger['match'][0]
        
        alert = {
            'id': f"{rule_name}_{int(time.time())}",
            'timestamp': datetime.now(),
            'rule': rule_name,
            'severity': rule_config['severity'],
            'description': rule_config['description'],
            'trigger_count': len(triggers),
            'time_window': rule_config['time_window'],
            'details': details,
            'source_file': latest_trigger['log_entry']['source'],
            'sample_log': latest_trigger['log_entry']['line']
        }
        
        return alert
    
    def should_send_alert(self, alert):
        """Determina si debe enviarse la alerta (rate limiting)"""
        current_time = datetime.now()
        max_alerts = self.config['monitoring']['max_alerts_per_hour']
        
        # Limpiar contadores antiguos (última hora)
        cutoff_time = current_time - timedelta(hours=1)
        self.alert_counts[alert['rule']] = deque([
            timestamp for timestamp in self.alert_counts[alert['rule']]
            if timestamp > cutoff_time
        ])
        
        # Verificar si excede el límite
        if len(self.alert_counts[alert['rule']]) >= max_alerts:
            return False
        
        # Añadir timestamp actual
        self.alert_counts[alert['rule']].append(current_time)
        return True
    
    def send_alert(self, alert):
        """Envía alerta según configuración"""
        alert_msg = self.format_alert(alert)
        
        if self.config['output']['console']:
            print(alert_msg)
        
        if self.config['output']['file']:
            try:
                with open(self.config['output']['file'], 'a') as f:
                    f.write(f"{alert_msg}\n")
            except Exception as e:
                print(f"❌ Error escribiendo a archivo: {e}")
        
        # Guardar en memoria para estadísticas
        self.alerts.append(alert)
        self.recent_events.append({
            'type': 'alert',
            'data': alert,
            'timestamp': datetime.now()
        })
    
    def format_alert(self, alert):
        """Formatea alerta para visualización"""
        severity_colors = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢'
        }
        
        color = severity_colors.get(alert['severity'], '⚪')
        timestamp = alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
        
        msg = f"\n{color} ALERTA {alert['severity']} - {alert['rule'].upper()}"
        msg += f"\n⏰ Tiempo: {timestamp}"
        msg += f"\n📋 Descripción: {alert['description']}"
        msg += f"\n🔢 Triggers: {alert['trigger_count']} en {alert['time_window']}s"
        msg += f"\n📁 Archivo: {alert['source_file']}"
        
        if alert['details']:
            msg += f"\n📊 Detalles:"
            for key, value in alert['details'].items():
                msg += f"\n   • {key}: {value}"
        
        msg += f"\n📝 Log ejemplo: {alert['sample_log'][:100]}..."
        msg += f"\n🆔 ID: {alert['id']}"
        msg += "\n" + "="*60
        
        return msg
    
    def monitor_logs(self):
        """Función principal de monitoreo"""
        available_logs = self.get_available_log_files()
        
        if not available_logs:
            print("❌ No hay archivos de log disponibles para monitorear")
            return
        
        print(f"🔍 Monitoreando archivos: {', '.join(available_logs)}")
        print(f"⚙️  Reglas activas: {len(self.config['alert_rules'])}")
        print("👀 Presiona Ctrl+C para detener")
        print("="*60)
        
        # Abrir archivos y posicionarse al final
        file_handles = {}
        for log_file in available_logs:
            try:
                f = open(log_file, 'r')
                f.seek(0, 2)  # Ir al final del archivo
                file_handles[log_file] = f
            except Exception as e:
                print(f"⚠️  Error abriendo {log_file}: {e}")
        
        self.running = True
        
        try:
            while self.running:
                for log_file, file_handle in file_handles.items():
                    try:
                        line = file_handle.readline()
                        if line:
                            log_entry = self.parse_log_line(line, log_file)
                            
                            # Verificar reglas de alerta
                            alerts = self.check_alert_rules(log_entry)
                            for alert in alerts:
                                self.send_alert(alert)
                            
                            # Actualizar estadísticas
                            self.stats['lines_processed'] += 1
                            
                            # Guardar evento reciente
                            self.recent_events.append({
                                'type': 'log_entry',
                                'data': log_entry,
                                'timestamp': datetime.now()
                            })
                    
                    except Exception as e:
                        print(f"⚠️  Error procesando {log_file}: {e}")
                
                time.sleep(self.config['monitoring']['interval'])
        
        except KeyboardInterrupt:
            print("\n⚠️  Deteniendo monitoreo...")
        finally:
            self.running = False
            for file_handle in file_handles.values():
                file_handle.close()
    
    def show_statistics(self):
        """Muestra estadísticas del monitoreo"""
        print("\n📊 ESTADÍSTICAS DE LOG GUARDIAN")
        print("="*40)
        print(f"📝 Líneas procesadas: {self.stats['lines_processed']}")
        print(f"🚨 Total alertas: {len(self.alerts)}")
        
        # Alertas por tipo
        alert_types = defaultdict(int)
        for alert in self.alerts[-50:]:  # Últimas 50 alertas
            alert_types[alert['rule']] += 1
        
        if alert_types:
            print("\n🔔 Alertas por tipo (últimas 50):")
            for rule, count in alert_types.items():
                print(f"   • {rule}: {count}")
        
        # Eventos recientes
        if self.recent_events:
            print(f"\n📋 Últimos eventos ({len(self.recent_events)}):")
            for event in list(self.recent_events)[-10:]:
                timestamp = event['timestamp'].strftime('%H:%M:%S')
                if event['type'] == 'alert':
                    print(f"   🚨 {timestamp} - ALERTA: {event['data']['rule']}")
                else:
                    print(f"   📝 {timestamp} - LOG: {event['data']['source']}")

def main():
    parser = argparse.ArgumentParser(
        description="Log Guardian - Sistema avanzado de monitoreo de logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  python3 log_guardian.py --monitor
  python3 log_guardian.py --config custom_config.json --monitor  
  python3 log_guardian.py --generate-config config.json
  python3 log_guardian.py --monitor --output alerts.log

Archivos de log por defecto:
  - /var/log/auth.log (autenticación)
  - /var/log/syslog (sistema general)
  - /var/log/secure (CentOS/RHEL)
  - /var/log/messages (mensajes del sistema)
        """
    )
    
    parser.add_argument('--monitor', action='store_true',
                       help='Iniciar monitoreo en tiempo real')
    parser.add_argument('--config',
                       help='Archivo de configuración personalizada')
    parser.add_argument('--generate-config',
                       help='Generar archivo de configuración por defecto')
    parser.add_argument('--output',
                       help='Archivo para guardar alertas')
    parser.add_argument('--stats', action='store_true',
                       help='Mostrar estadísticas y salir')
    
    args = parser.parse_args()
    
    # Banner
    print("\n🛡️  BOFA - Log Guardian v1.0")
    print("Desarrollado por @descambiado")
    print("Sistema avanzado de monitoreo de logs")
    print("="*50)
    
    try:
        guardian = LogGuardian(args.config)
        
        # Configurar salida si se especifica
        if args.output:
            guardian.config['output']['file'] = args.output
        
        if args.generate_config:
            guardian.save_default_config(args.generate_config)
            return
        
        if args.stats:
            guardian.show_statistics()
            return
        
        if args.monitor:
            guardian.monitor_logs()
        else:
            parser.print_help()
    
    except PermissionError:
        print("❌ Error: Permisos insuficientes para leer archivos de log")
        print("💡 Ejecuta con sudo o añade tu usuario al grupo adm/syslog")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
