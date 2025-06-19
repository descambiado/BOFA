
#!/usr/bin/env python3
"""
AD Enumeration Visualizer - BOFA Red Team Module
Genera visualizaciones tipo BloodHound sin Neo4j
"""

import json
import subprocess
import argparse
import os
from datetime import datetime
import networkx as nx
import matplotlib.pyplot as plt

class ADEnumVisualizer:
    def __init__(self):
        self.nodes = {}
        self.edges = []
        self.output_dir = "output/ad_visualization"
        
    def create_output_dir(self):
        os.makedirs(self.output_dir, exist_ok=True)
        
    def enumerate_domain(self, domain):
        """Simula enumeración de dominio AD (educativo)"""
        print(f"[+] Enumerando dominio: {domain}")
        
        # Simular usuarios encontrados
        users = [
            {"name": "Administrator", "enabled": True, "admin": True},
            {"name": "jdoe", "enabled": True, "admin": False},
            {"name": "alice", "enabled": True, "admin": False},
            {"name": "bob", "enabled": False, "admin": False},
            {"name": "service_account", "enabled": True, "admin": False}
        ]
        
        # Simular grupos
        groups = [
            {"name": "Domain Admins", "members": ["Administrator"]},
            {"name": "Enterprise Admins", "members": ["Administrator"]},
            {"name": "Domain Users", "members": ["jdoe", "alice", "bob"]},
            {"name": "Service Accounts", "members": ["service_account"]}
        ]
        
        # Simular computadoras
        computers = [
            {"name": "DC01", "os": "Windows Server 2019", "role": "Domain Controller"},
            {"name": "WS01", "os": "Windows 10", "role": "Workstation"},
            {"name": "SRV01", "os": "Windows Server 2016", "role": "File Server"}
        ]
        
        return users, groups, computers
    
    def build_graph(self, users, groups, computers):
        """Construye grafo de relaciones AD"""
        G = nx.Graph()
        
        # Agregar nodos de usuarios
        for user in users:
            G.add_node(user["name"], 
                      type="user", 
                      enabled=user["enabled"],
                      admin=user["admin"])
        
        # Agregar nodos de grupos
        for group in groups:
            G.add_node(group["name"], type="group")
            # Agregar edges usuario-grupo
            for member in group["members"]:
                G.add_edge(member, group["name"], relation="member_of")
        
        # Agregar nodos de computadoras
        for computer in computers:
            G.add_node(computer["name"], 
                      type="computer",
                      os=computer["os"],
                      role=computer["role"])
        
        return G
    
    def visualize_graph(self, G, domain):
        """Genera visualización del grafo AD"""
        plt.figure(figsize=(15, 10))
        
        # Definir colores por tipo de nodo
        node_colors = []
        for node in G.nodes():
            node_data = G.nodes[node]
            if node_data.get("type") == "user":
                if node_data.get("admin"):
                    node_colors.append("red")  # Admins en rojo
                elif node_data.get("enabled"):
                    node_colors.append("lightblue")  # Usuarios activos
                else:
                    node_colors.append("gray")  # Usuarios inactivos
            elif node_data.get("type") == "group":
                node_colors.append("orange")  # Grupos en naranja
            else:
                node_colors.append("green")  # Computadoras en verde
        
        # Layout del grafo
        pos = nx.spring_layout(G, k=2, iterations=50)
        
        # Dibujar nodos y edges
        nx.draw_networkx_nodes(G, pos, node_color=node_colors, 
                              node_size=1000, alpha=0.8)
        nx.draw_networkx_edges(G, pos, alpha=0.5, width=2)
        nx.draw_networkx_labels(G, pos, font_size=8, font_weight="bold")
        
        plt.title(f"AD Domain Visualization: {domain}", fontsize=16, fontweight="bold")
        plt.axis("off")
        
        # Leyenda
        legend_elements = [
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='red', 
                      markersize=10, label='Admin Users'),
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='lightblue', 
                      markersize=10, label='Regular Users'),
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='orange', 
                      markersize=10, label='Groups'),
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='green', 
                      markersize=10, label='Computers')
        ]
        plt.legend(handles=legend_elements, loc='upper right')
        
        # Guardar visualización
        output_file = f"{self.output_dir}/ad_graph_{domain}.png"
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        print(f"[+] Visualización guardada en: {output_file}")
        
        return output_file
    
    def generate_report(self, users, groups, computers, domain):
        """Genera reporte JSON con hallazgos"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "domain": domain,
            "summary": {
                "total_users": len(users),
                "enabled_users": len([u for u in users if u["enabled"]]),
                "admin_users": len([u for u in users if u["admin"]]),
                "total_groups": len(groups),
                "total_computers": len(computers)
            },
            "findings": [],
            "users": users,
            "groups": groups,
            "computers": computers
        }
        
        # Agregar hallazgos de seguridad
        admin_users = [u["name"] for u in users if u["admin"]]
        if len(admin_users) > 2:
            report["findings"].append({
                "severity": "HIGH",
                "type": "Excessive Admin Accounts",
                "description": f"Se encontraron {len(admin_users)} cuentas administrativas",
                "recommendation": "Revisar necesidad de tantas cuentas admin"
            })
        
        disabled_users = [u["name"] for u in users if not u["enabled"]]
        if disabled_users:
            report["findings"].append({
                "severity": "MEDIUM", 
                "type": "Disabled Accounts",
                "description": f"Cuentas deshabilitadas encontradas: {', '.join(disabled_users)}",
                "recommendation": "Considerar eliminar cuentas no utilizadas"
            })
        
        # Guardar reporte
        report_file = f"{self.output_dir}/ad_report_{domain}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Reporte guardado en: {report_file}")
        return report_file

def main():
    parser = argparse.ArgumentParser(description="AD Enumeration Visualizer")
    parser.add_argument("-d", "--domain", required=True, help="Dominio a enumerar")
    parser.add_argument("-o", "--output", help="Directorio de salida")
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("🔴 BOFA AD Enumeration Visualizer")
    print("⚠️  SOLO PARA FINES EDUCATIVOS")
    print("=" * 60)
    
    visualizer = ADEnumVisualizer()
    
    if args.output:
        visualizer.output_dir = args.output
    
    visualizer.create_output_dir()
    
    try:
        # Enumerar dominio (simulado)
        users, groups, computers = visualizer.enumerate_domain(args.domain)
        
        # Construir grafo
        G = visualizer.build_graph(users, groups, computers)
        
        # Generar visualización
        graph_file = visualizer.visualize_graph(G, args.domain)
        
        # Generar reporte
        report_file = visualizer.generate_report(users, groups, computers, args.domain)
        
        print(f"\n[✓] Enumeración completada para dominio: {args.domain}")
        print(f"[✓] Archivos generados en: {visualizer.output_dir}")
        
    except Exception as e:
        print(f"[!] Error durante la enumeración: {e}")

if __name__ == "__main__":
    main()
