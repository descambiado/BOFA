
#!/usr/bin/env python3
"""
BOFA Log Timeline Builder - Genera línea de tiempo visual con eventos clave
Autor: @descambiado
Versión: 1.0
"""

import re
import json
import argparse
from datetime import datetime
from collections import defaultdict

class LogTimelineBuilder:
    def __init__(self):
        self.events = []
        self.patterns = {
            "ssh_login": r"Accepted password for (\w+) from ([\d.]+)",
            "failed_login": r"Failed password for (\w+) from ([\d.]+)",
            "sudo_usage": r"(\w+) : TTY=(\w+) ; PWD=([^;]+) ; USER=(\w+) ; COMMAND=(.+)",
            "file_access": r"audit.*path=([^\s]+).*uid=(\d+)",
            "network_conn": r"connection from ([\d.]+):(\d+)"
        }
    
    def parse_log_file(self, filepath):
        print(f"📊 Analizando archivo de log: {filepath}")
        
        try:
            with open(filepath, 'r') as f:
                lines = f.readlines()
        except FileNotFoundError:
            print(f"❌ Archivo no encontrado: {filepath}")
            return
        
        for line_num, line in enumerate(lines, 1):
            self.extract_events(line, line_num)
        
        print(f"✅ Procesadas {len(lines)} líneas, encontrados {len(self.events)} eventos")
    
    def extract_events(self, line, line_num):
        timestamp = self.extract_timestamp(line)
        
        for event_type, pattern in self.patterns.items():
            match = re.search(pattern, line)
            if match:
                event = {
                    "timestamp": timestamp,
                    "type": event_type,
                    "line": line_num,
                    "data": match.groups(),
                    "raw_line": line.strip()
                }
                self.events.append(event)
    
    def extract_timestamp(self, line):
        # Intentar extraer timestamp común de logs
        timestamp_patterns = [
            r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})",
            r"(\w{3} \d{1,2} \d{2}:\d{2}:\d{2})",
            r"(\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})"
        ]
        
        for pattern in timestamp_patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(1)
        
        return "No timestamp"
    
    def build_timeline(self):
        print("\n📅 LÍNEA DE TIEMPO DE EVENTOS")
        print("=" * 60)
        
        # Agrupar eventos por timestamp
        timeline = defaultdict(list)
        for event in self.events:
            timeline[event["timestamp"]].append(event)
        
        # Mostrar timeline ordenado
        for timestamp in sorted(timeline.keys()):
            print(f"\n🕐 {timestamp}")
            for event in timeline[timestamp]:
                icon = self.get_event_icon(event["type"])
                print(f"  {icon} {event['type'].replace('_', ' ').title()}: {event['data']}")
    
    def get_event_icon(self, event_type):
        icons = {
            "ssh_login": "🔐",
            "failed_login": "❌",
            "sudo_usage": "⚡",
            "file_access": "📁",
            "network_conn": "🌐"
        }
        return icons.get(event_type, "📋")
    
    def export_json(self, output_file):
        print(f"\n💾 Exportando timeline a {output_file}")
        
        timeline_data = {
            "total_events": len(self.events),
            "event_types": list(set(e["type"] for e in self.events)),
            "events": self.events,
            "generated_at": datetime.now().isoformat()
        }
        
        with open(output_file, 'w') as f:
            json.dump(timeline_data, f, indent=2, default=str)
        
        print(f"✅ Timeline exportado exitosamente")

def main():
    parser = argparse.ArgumentParser(description="BOFA Log Timeline Builder")
    parser.add_argument("-f", "--file", required=True, help="Archivo de log a analizar")
    parser.add_argument("-o", "--output", help="Archivo JSON de salida")
    parser.add_argument("--format", choices=["console", "json"], default="console",
                       help="Formato de salida")
    
    args = parser.parse_args()
    
    print("📊 BOFA Log Timeline Builder v1.0")
    print("=" * 40)
    
    builder = LogTimelineBuilder()
    builder.parse_log_file(args.file)
    
    if args.format == "console":
        builder.build_timeline()
    
    if args.output:
        builder.export_json(args.output)

if __name__ == "__main__":
    main()
