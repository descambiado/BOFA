
#!/usr/bin/env python3
"""
BOFA Packet Story Builder - Construye narrativas forenses a partir de tráfico .pcap
Autor: @descambiado
Versión: 1.0
"""

import argparse
from datetime import datetime

class PacketStoryBuilder:
    def __init__(self):
        self.story_events = []
        self.timeline = []
        
    def analyze_pcap_simulation(self, pcap_file):
        """Simula análisis de archivo PCAP y genera narrativa"""
        print(f"📦 Analizando archivo PCAP: {pcap_file}")
        
        # Simular eventos comunes en un ataque
        simulated_events = [
            {
                "timestamp": "2025-01-15 09:30:15",
                "event_type": "initial_scan",
                "source_ip": "192.168.1.100",
                "target_ip": "192.168.1.50",
                "description": "Escaneo de puertos inicial detectado",
                "evidence": "Multiple SYN packets to various ports"
            },
            {
                "timestamp": "2025-01-15 09:35:22", 
                "event_type": "exploitation",
                "source_ip": "192.168.1.100",
                "target_ip": "192.168.1.50",
                "description": "Intento de explotación de vulnerabilidad web",
                "evidence": "HTTP POST with SQL injection payload"
            },
            {
                "timestamp": "2025-01-15 09:40:11",
                "event_type": "lateral_movement",
                "source_ip": "192.168.1.50",
                "target_ip": "192.168.1.45",
                "description": "Movimiento lateral hacia otro host",
                "evidence": "SMB authentication attempts"
            },
            {
                "timestamp": "2025-01-15 09:50:33",
                "event_type": "data_exfiltration",
                "source_ip": "192.168.1.45",
                "target_ip": "10.0.0.100",
                "description": "Exfiltración de datos hacia IP externa",
                "evidence": "Large outbound data transfer via HTTPS"
            }
        ]
        
        self.story_events = simulated_events
        print(f"✅ Analizados {len(simulated_events)} eventos significativos")
        
    def build_attack_narrative(self):
        """Construye narrativa cronológica del ataque"""
        print("\n📖 NARRATIVA FORENSE DEL INCIDENTE")
        print("=" * 60)
        
        story_template = {
            "initial_scan": "🔍 **Fase de Reconocimiento**: El atacante inició un escaneo de la red desde {source_ip} hacia {target_ip}. Se detectaron múltiples intentos de conexión a diferentes puertos, sugiriendo un escaneo automatizado para identificar servicios vulnerables.",
            
            "exploitation": "⚔️ **Fase de Explotación**: Se observó tráfico HTTP anómalo desde {source_ip} hacia {target_ip}. El análisis revela intentos de inyección SQL, indicando que el atacante intentó explotar una vulnerabilidad en la aplicación web.",
            
            "lateral_movement": "🔄 **Movimiento Lateral**: Una vez comprometido el host inicial, el atacante procedió a moverse lateralmente en la red. Se detectaron múltiples intentos de autenticación SMB desde {source_ip} hacia {target_ip}.",
            
            "data_exfiltration": "📤 **Exfiltración de Datos**: En la fase final del ataque, se observó una transferencia significativa de datos desde {source_ip} hacia la IP externa {target_ip} utilizando HTTPS para ocultar el contenido."
        }
        
        for event in self.story_events:
            story_text = story_template.get(event["event_type"], "Evento no categorizado")
            formatted_story = story_text.format(
                source_ip=event["source_ip"],
                target_ip=event["target_ip"]
            )
            
            print(f"\n⏰ {event['timestamp']}")
            print(f"{formatted_story}")
            print(f"📋 Evidencia técnica: {event['evidence']}")
            print("-" * 60)
    
    def generate_ioc_list(self):
        """Genera lista de Indicadores de Compromiso"""
        print("\n🚨 INDICADORES DE COMPROMISO (IOCs)")
        print("=" * 50)
        
        iocs = {
            "IP Addresses": set(),
            "Attack Patterns": [],
            "Timestamps": [],
            "Network Artifacts": []
        }
        
        for event in self.story_events:
            iocs["IP Addresses"].add(event["source_ip"])
            iocs["IP Addresses"].add(event["target_ip"]) 
            iocs["Attack Patterns"].append(event["event_type"])
            iocs["Timestamps"].append(event["timestamp"])
            iocs["Network Artifacts"].append(event["evidence"])
        
        print("🌐 **IP Addresses sospechosas:**")
        for ip in sorted(iocs["IP Addresses"]):
            print(f"  - {ip}")
        
        print("\n⚔️ **Patrones de ataque detectados:**")
        for pattern in set(iocs["Attack Patterns"]):
            count = iocs["Attack Patterns"].count(pattern)
            print(f"  - {pattern.replace('_', ' ').title()} ({count} veces)")
        
        print("\n📝 **Artefactos de red:**")
        for artifact in set(iocs["Network Artifacts"]):
            print(f"  - {artifact}")
    
    def generate_recommendations(self):
        """Genera recomendaciones de seguridad basadas en el análisis"""
        print("\n💡 RECOMENDACIONES DE SEGURIDAD")
        print("=" * 50)
        
        recommendations = [
            "🛡️ Implementar segmentación de red para limitar movimiento lateral",
            "🔍 Configurar monitoreo de tráfico anómalo y transferencias de datos grandes",
            "⚡ Activar alertas para múltiples intentos de autenticación fallidos",
            "🔒 Aplicar parches de seguridad en aplicaciones web vulnerables",
            "📊 Implementar análisis de comportamiento de usuarios y entidades (UEBA)",
            "🚫 Configurar DLP (Data Loss Prevention) para detectar exfiltración",
            "📱 Establecer procedimientos de respuesta a incidentes más rápidos"
        ]
        
        for rec in recommendations:
            print(f"  {rec}")
    
    def export_report(self, output_file):
        """Exporta reporte completo a archivo"""
        print(f"\n💾 Generando reporte forense: {output_file}")
        
        report_content = [
            "# REPORTE DE ANÁLISIS FORENSE",
            f"Generado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "Por: BOFA Packet Story Builder v1.0",
            "",
            "## RESUMEN EJECUTIVO",
            f"Se analizó tráfico de red que reveló un ataque coordinado con {len(self.story_events)} fases distintas.",
            "El atacante logró comprometer múltiples sistemas y exfiltrar datos.",
            "",
            "## LÍNEA DE TIEMPO DEL INCIDENTE"
        ]
        
        for event in self.story_events:
            report_content.extend([
                f"### {event['timestamp']} - {event['event_type'].replace('_', ' ').title()}",
                f"**Origen:** {event['source_ip']} → **Destino:** {event['target_ip']}",
                f"**Descripción:** {event['description']}",
                f"**Evidencia:** {event['evidence']}",
                ""
            ])
        
        with open(output_file, 'w') as f:
            f.write('\n'.join(report_content))
        
        print(f"✅ Reporte exportado exitosamente")

def main():
    parser = argparse.ArgumentParser(description="BOFA Packet Story Builder")
    parser.add_argument("-f", "--file", required=True, help="Archivo PCAP a analizar")
    parser.add_argument("-o", "--output", help="Archivo de reporte de salida")
    parser.add_argument("--format", choices=["narrative", "iocs", "recommendations", "all"], 
                       default="all", help="Tipo de análisis a generar")
    
    args = parser.parse_args()
    
    print("📦 BOFA Packet Story Builder v1.0")
    print("🔍 Análisis forense de tráfico de red")
    print("=" * 50)
    
    builder = PacketStoryBuilder()
    builder.analyze_pcap_simulation(args.file)
    
    if args.format in ["narrative", "all"]:
        builder.build_attack_narrative()
    
    if args.format in ["iocs", "all"]:
        builder.generate_ioc_list()
    
    if args.format in ["recommendations", "all"]:
        builder.generate_recommendations()
    
    if args.output:
        builder.export_report(args.output)

if __name__ == "__main__":
    main()
