
#!/usr/bin/env python3
"""
BOFA CTF Flag Planner - Permite crear escenarios CTF con banderas y puntuación
Autor: @descambiado
Versión: 1.0
"""

import json
import random
import string
import argparse
from datetime import datetime, timedelta

class CTFFlagPlanner:
    def __init__(self):
        self.flags = []
        self.challenges = []
        self.scoreboard = {}
    
    def generate_flag(self, challenge_name, points=100):
        """Genera una bandera única para un desafío"""
        flag_id = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        flag = f"BOFA{{{flag_id}}}"
        
        flag_data = {
            "id": len(self.flags) + 1,
            "flag": flag,
            "challenge": challenge_name,
            "points": points,
            "created_at": datetime.now().isoformat(),
            "found_by": [],
            "hints": []
        }
        
        self.flags.append(flag_data)
        print(f"🚩 Bandera generada: {flag} (Puntos: {points})")
        return flag_data
    
    def create_challenge(self, name, description, category, difficulty, points):
        """Crea un nuevo desafío CTF"""
        flag_data = self.generate_flag(name, points)
        
        challenge = {
            "id": len(self.challenges) + 1,
            "name": name,
            "description": description,
            "category": category,
            "difficulty": difficulty,
            "points": points,
            "flag_id": flag_data["id"],
            "flag": flag_data["flag"],
            "created_at": datetime.now().isoformat(),
            "solved_by": [],
            "hints": [
                f"Busca en archivos de configuración",
                f"Revisa los logs del sistema",
                f"Analiza el tráfico de red"
            ]
        }
        
        self.challenges.append(challenge)
        print(f"✅ Desafío creado: {name} ({category} - {difficulty})")
        return challenge
    
    def add_predefined_challenges(self):
        """Agrega desafíos predefinidos comunes"""
        predefined = [
            {
                "name": "Web Vulnerability Hunter",
                "description": "Encuentra la vulnerabilidad SQL Injection en la aplicación web",
                "category": "Web",
                "difficulty": "Easy",
                "points": 100
            },
            {
                "name": "Network Reconnaissance", 
                "description": "Enumera servicios en la red interna y encuentra el servicio oculto",
                "category": "Network",
                "difficulty": "Medium",
                "points": 200
            },
            {
                "name": "Privilege Escalation",
                "description": "Escala privilegios en el sistema Linux y obtén acceso root",
                "category": "Linux",
                "difficulty": "Hard",
                "points": 300
            },
            {
                "name": "Forensics Investigation",
                "description": "Analiza la imagen de disco y encuentra evidencia del atacante",
                "category": "Forensics", 
                "difficulty": "Medium",
                "points": 250
            },
            {
                "name": "Malware Analysis",
                "description": "Reverse engineering del malware y extrae su configuración C2",
                "category": "Reverse",
                "difficulty": "Hard",
                "points": 400
            }
        ]
        
        for challenge_data in predefined:
            self.create_challenge(**challenge_data)
    
    def submit_flag(self, team_name, flag_input):
        """Permite a un equipo enviar una bandera"""
        for flag_data in self.flags:
            if flag_data["flag"] == flag_input:
                if team_name not in flag_data["found_by"]:
                    flag_data["found_by"].append({
                        "team": team_name,
                        "timestamp": datetime.now().isoformat()
                    })
                    
                    # Actualizar puntuación
                    if team_name not in self.scoreboard:
                        self.scoreboard[team_name] = 0
                    self.scoreboard[team_name] += flag_data["points"]
                    
                    print(f"🎯 ¡Bandera correcta! Equipo {team_name} +{flag_data['points']} puntos")
                    return True
                else:
                    print(f"⚠️ Bandera ya encontrada por el equipo {team_name}")
                    return False
        
        print(f"❌ Bandera incorrecta: {flag_input}")
        return False
    
    def show_scoreboard(self):
        """Muestra la tabla de puntuaciones"""
        print("\n🏆 TABLA DE PUNTUACIONES")
        print("=" * 40)
        
        sorted_teams = sorted(self.scoreboard.items(), key=lambda x: x[1], reverse=True)
        
        for i, (team, points) in enumerate(sorted_teams, 1):
            medal = "🥇" if i == 1 else "🥈" if i == 2 else "🥉" if i == 3 else f"{i}."
            print(f"{medal} {team}: {points} puntos")
    
    def generate_challenge_page(self, challenge):
        """Genera página HTML para un desafío"""
        html_template = f"""
<!DOCTYPE html>
<html>
<head>
    <title>BOFA CTF - {challenge['name']}</title>
    <style>
        body {{ font-family: 'Courier New', monospace; background: #1a1a1a; color: #00ff00; padding: 20px; }}
        .challenge {{ background: #2a2a2a; padding: 20px; border-radius: 10px; }}
        .flag-input {{ background: #1a1a1a; border: 2px solid #00ff00; color: #00ff00; padding: 10px; width: 300px; }}
        .submit-btn {{ background: #00ff00; color: #1a1a1a; padding: 10px 20px; border: none; cursor: pointer; }}
    </style>
</head>
<body>
    <div class="challenge">
        <h1>🚩 {challenge['name']}</h1>
        <p><strong>Categoría:</strong> {challenge['category']}</p>
        <p><strong>Dificultad:</strong> {challenge['difficulty']}</p>
        <p><strong>Puntos:</strong> {challenge['points']}</p>
        <hr>
        <p>{challenge['description']}</p>
        
        <h3>💡 Pistas:</h3>
        <ul>
        {''.join([f'<li>{hint}</li>' for hint in challenge['hints']])}
        </ul>
        
        <h3>🔑 Enviar Bandera:</h3>
        <input type="text" class="flag-input" placeholder="BOFA{{flag_here}}" id="flagInput">
        <button class="submit-btn" onclick="submitFlag()">Enviar</button>
        
        <script>
            function submitFlag() {{
                const flag = document.getElementById('flagInput').value;
                if (flag === '{challenge['flag']}') {{
                    alert('¡Correcto! +{challenge['points']} puntos');
                }} else {{
                    alert('Bandera incorrecta. Inténtalo de nuevo.');
                }}
            }}
        </script>
    </div>
</body>
</html>
        """
        return html_template
    
    def export_ctf_package(self, output_dir):
        """Exporta todo el CTF como un paquete completo"""
        import os
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Exportar datos JSON
        ctf_data = {
            "challenges": self.challenges,
            "flags": self.flags,
            "scoreboard": self.scoreboard,
            "created_at": datetime.now().isoformat()
        }
        
        with open(f"{output_dir}/ctf_data.json", 'w') as f:
            json.dump(ctf_data, f, indent=2)
        
        # Generar páginas HTML para cada desafío
        for challenge in self.challenges:
            html_content = self.generate_challenge_page(challenge)
            filename = f"challenge_{challenge['id']}_{challenge['name'].replace(' ', '_').lower()}.html"
            
            with open(f"{output_dir}/{filename}", 'w') as f:
                f.write(html_content)
        
        # Generar index principal
        index_html = self.generate_index_page()
        with open(f"{output_dir}/index.html", 'w') as f:
            f.write(index_html)
        
        print(f"📦 CTF package exportado a: {output_dir}")
    
    def generate_index_page(self):
        """Genera página principal del CTF"""
        challenges_list = ""
        for challenge in self.challenges:
            filename = f"challenge_{challenge['id']}_{challenge['name'].replace(' ', '_').lower()}.html"
            challenges_list += f"""
            <div class="challenge-card">
                <h3><a href="{filename}">{challenge['name']}</a></h3>
                <p>{challenge['description']}</p>
                <span class="category">{challenge['category']}</span>
                <span class="difficulty">{challenge['difficulty']}</span>
                <span class="points">{challenge['points']} pts</span>
            </div>
            """
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>BOFA CTF Platform</title>
    <style>
        body {{ font-family: 'Courier New', monospace; background: #1a1a1a; color: #00ff00; padding: 20px; }}
        .challenge-card {{ background: #2a2a2a; padding: 15px; margin: 10px; border-radius: 5px; }}
        .challenge-card a {{ color: #00ff00; text-decoration: none; }}
        .category {{ background: #0066cc; color: white; padding: 3px 8px; border-radius: 3px; font-size: 12px; }}
        .difficulty {{ background: #ff6600; color: white; padding: 3px 8px; border-radius: 3px; font-size: 12px; }}
        .points {{ background: #00cc66; color: white; padding: 3px 8px; border-radius: 3px; font-size: 12px; }}
    </style>
</head>
<body>
    <h1>🚩 BOFA CTF Platform</h1>
    <p>Bienvenido al Capture The Flag de BOFA. Completa los desafíos y captura las banderas.</p>
    
    <h2>📋 Desafíos Disponibles:</h2>
    {challenges_list}
    
    <footer>
        <p>Generado por BOFA CTF Flag Planner v1.0</p>
    </footer>
</body>
</html>
        """
        return html

def main():
    parser = argparse.ArgumentParser(description="BOFA CTF Flag Planner")
    parser.add_argument("--create", action="store_true", help="Crear CTF con desafíos predefinidos")
    parser.add_argument("--export", help="Directorio de exportación")
    parser.add_argument("--flag", help="Bandera a enviar")
    parser.add_argument("--team", help="Nombre del equipo")
    
    args = parser.parse_args()
    
    print("🚩 BOFA CTF Flag Planner v1.0")
    print("=" * 40)
    
    planner = CTFFlagPlanner()
    
    if args.create:
        print("🎯 Creando CTF con desafíos predefinidos...")
        planner.add_predefined_challenges()
        
        if args.export:
            planner.export_ctf_package(args.export)
    
    if args.flag and args.team:
        planner.submit_flag(args.team, args.flag)
        planner.show_scoreboard()

if __name__ == "__main__":
    main()
