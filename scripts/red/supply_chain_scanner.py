
#!/usr/bin/env python3
"""
BOFA Supply Chain Security Scanner v1.0
Mapea y analiza cadenas de suministro de software
Author: @descambiado
"""

import json
import requests
import hashlib
import os
import subprocess
import re
from datetime import datetime, timedelta
import zipfile
import tarfile
from typing import Dict, List, Any, Optional
import urllib.parse

class SupplyChainScanner:
    def __init__(self):
        self.vulnerability_db = self.load_vulnerability_db()
        self.package_managers = {
            "npm": {"file": "package.json", "lock": "package-lock.json"},
            "pip": {"file": "requirements.txt", "lock": "requirements.lock"},
            "maven": {"file": "pom.xml", "lock": "pom.xml.lock"},
            "gradle": {"file": "build.gradle", "lock": "gradle.lockfile"},
            "composer": {"file": "composer.json", "lock": "composer.lock"},
            "cargo": {"file": "Cargo.toml", "lock": "Cargo.lock"}
        }
        
        self.high_risk_patterns = [
            r"eval\s*\(",
            r"exec\s*\(",
            r"system\s*\(",
            r"shell_exec\s*\(",
            r"passthru\s*\(",
            r"\.download\s*\(",
            r"http://",  # Insecure HTTP
            r"ftp://",   # Insecure FTP
        ]
        
        self.suspicious_domains = [
            "bit.ly", "tinyurl.com", "t.co", "goo.gl",
            "ow.ly", "buff.ly", "is.gd", "tiny.cc"
        ]
    
    def load_vulnerability_db(self) -> Dict:
        """Carga base de datos de vulnerabilidades simulada"""
        return {
            "lodash": {
                "4.17.20": ["CVE-2021-23337"],
                "4.17.19": ["CVE-2021-23337", "CVE-2020-8203"]
            },
            "axios": {
                "0.21.0": ["CVE-2020-28168"],
                "0.20.0": ["CVE-2020-28168"]
            },
            "express": {
                "4.17.0": ["CVE-2022-24999"],
                "4.16.0": ["CVE-2022-24999"]
            },
            "django": {
                "3.1.0": ["CVE-2021-35042"],
                "3.0.0": ["CVE-2021-35042", "CVE-2021-33203"]
            },
            "requests": {
                "2.25.0": ["CVE-2021-33503"],
                "2.24.0": ["CVE-2021-33503"]
            }
        }
    
    def scan_dependencies(self, project_path: str) -> Dict:
        """Escanea dependencias del proyecto"""
        results = {
            "project_path": project_path,
            "package_managers": [],
            "dependencies": {},
            "vulnerabilities": [],
            "supply_chain_risks": [],
            "dependency_tree": {},
            "license_issues": [],
            "outdated_packages": []
        }
        
        print(f"[INFO] Escaneando dependencias en: {project_path}")
        
        # Detectar gestores de paquetes
        for pm_name, pm_config in self.package_managers.items():
            manifest_file = os.path.join(project_path, pm_config["file"])
            if os.path.exists(manifest_file):
                results["package_managers"].append(pm_name)
                print(f"[FOUND] Detectado {pm_name}: {pm_config['file']}")
                
                # Analizar dependencias específicas
                deps = self.analyze_package_manager(manifest_file, pm_name)
                results["dependencies"][pm_name] = deps
                
                # Verificar vulnerabilidades
                vulns = self.check_vulnerabilities(deps, pm_name)
                results["vulnerabilities"].extend(vulns)
        
        # Analizar riesgos de cadena de suministro
        results["supply_chain_risks"] = self.analyze_supply_chain_risks(results["dependencies"])
        
        # Generar árbol de dependencias
        results["dependency_tree"] = self.build_dependency_tree(results["dependencies"])
        
        return results
    
    def analyze_package_manager(self, manifest_file: str, pm_type: str) -> List[Dict]:
        """Analiza archivo de dependencias específico"""
        dependencies = []
        
        try:
            if pm_type == "npm":
                dependencies = self.parse_npm_manifest(manifest_file)
            elif pm_type == "pip":
                dependencies = self.parse_pip_requirements(manifest_file)
            elif pm_type == "maven":
                dependencies = self.parse_maven_pom(manifest_file)
            # Agregar más parsers según necesidad
                
        except Exception as e:
            print(f"[ERROR] Error parseando {manifest_file}: {str(e)}")
        
        return dependencies
    
    def parse_npm_manifest(self, package_json_path: str) -> List[Dict]:
        """Parsea package.json de NPM"""
        dependencies = []
        
        try:
            with open(package_json_path, 'r') as f:
                data = json.load(f)
            
            # Dependencies y devDependencies
            for dep_type in ["dependencies", "devDependencies", "peerDependencies"]:
                if dep_type in data:
                    for name, version in data[dep_type].items():
                        dependencies.append({
                            "name": name,
                            "version": version,
                            "type": dep_type,
                            "manager": "npm"
                        })
        
        except Exception as e:
            print(f"[ERROR] Error parseando package.json: {str(e)}")
        
        return dependencies
    
    def parse_pip_requirements(self, requirements_path: str) -> List[Dict]:
        """Parsea requirements.txt de pip"""
        dependencies = []
        
        try:
            with open(requirements_path, 'r') as f:
                lines = f.readlines()
            
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Parsear formato: package==version o package>=version
                    match = re.match(r'^([a-zA-Z0-9_-]+)\s*([=><]+)\s*([0-9.]+)', line)
                    if match:
                        name, operator, version = match.groups()
                        dependencies.append({
                            "name": name,
                            "version": version,
                            "operator": operator,
                            "type": "dependencies",
                            "manager": "pip"
                        })
        
        except Exception as e:
            print(f"[ERROR] Error parseando requirements.txt: {str(e)}")
        
        return dependencies
    
    def parse_maven_pom(self, pom_path: str) -> List[Dict]:
        """Parsea pom.xml de Maven (básico)"""
        dependencies = []
        
        try:
            with open(pom_path, 'r') as f:
                content = f.read()
            
            # Regex básico para extraer dependencias
            dep_pattern = r'<dependency>.*?<groupId>(.*?)</groupId>.*?<artifactId>(.*?)</artifactId>.*?<version>(.*?)</version>.*?</dependency>'
            matches = re.findall(dep_pattern, content, re.DOTALL)
            
            for group_id, artifact_id, version in matches:
                dependencies.append({
                    "name": f"{group_id.strip()}:{artifact_id.strip()}",
                    "version": version.strip(),
                    "type": "dependencies",
                    "manager": "maven"
                })
        
        except Exception as e:
            print(f"[ERROR] Error parseando pom.xml: {str(e)}")
        
        return dependencies
    
    def check_vulnerabilities(self, dependencies: List[Dict], pm_type: str) -> List[Dict]:
        """Verifica vulnerabilidades conocidas"""
        vulnerabilities = []
        
        for dep in dependencies:
            name = dep["name"]
            version = dep.get("version", "")
            
            # Verificar en base de datos local
            if name in self.vulnerability_db:
                pkg_vulns = self.vulnerability_db[name]
                if version in pkg_vulns:
                    for cve in pkg_vulns[version]:
                        vulnerabilities.append({
                            "package": name,
                            "version": version,
                            "cve": cve,
                            "severity": self.get_cve_severity(cve),
                            "manager": pm_type,
                            "fix_available": self.check_fix_available(name, version)
                        })
        
        return vulnerabilities
    
    def get_cve_severity(self, cve: str) -> str:
        """Obtiene severidad de CVE (simulado)"""
        # En producción, consultaría NVD API
        severity_map = {
            "CVE-2021-23337": "high",
            "CVE-2020-8203": "high",
            "CVE-2020-28168": "medium",
            "CVE-2022-24999": "critical",
            "CVE-2021-35042": "medium",
            "CVE-2021-33203": "high",
            "CVE-2021-33503": "medium"
        }
        return severity_map.get(cve, "medium")
    
    def check_fix_available(self, package: str, version: str) -> bool:
        """Verifica si hay fix disponible (simulado)"""
        # En producción, consultaría registros de paquetes
        return True
    
    def analyze_supply_chain_risks(self, dependencies: Dict) -> List[Dict]:
        """Analiza riesgos de cadena de suministro"""
        risks = []
        
        for pm_type, deps in dependencies.items():
            for dep in deps:
                # Verificar paquetes con pocos mantenedores
                if self.is_single_maintainer_risk(dep):
                    risks.append({
                        "type": "single_maintainer",
                        "package": dep["name"],
                        "description": "Paquete mantenido por una sola persona",
                        "severity": "medium",
                        "recommendation": "Considerar alternativas con más mantenedores"
                    })
                
                # Verificar paquetes recientemente transferidos
                if self.is_recently_transferred(dep):
                    risks.append({
                        "type": "ownership_transfer",
                        "package": dep["name"],
                        "description": "Propiedad del paquete transferida recientemente",
                        "severity": "high",
                        "recommendation": "Verificar integridad del nuevo mantenedor"
                    })
                
                # Verificar dominios sospechosos en URLs
                if self.has_suspicious_urls(dep):
                    risks.append({
                        "type": "suspicious_urls",
                        "package": dep["name"],
                        "description": "Contiene URLs a dominios sospechosos",
                        "severity": "high",
                        "recommendation": "Revisar URLs en el código del paquete"
                    })
        
        return risks
    
    def is_single_maintainer_risk(self, dependency: Dict) -> bool:
        """Simula verificación de mantenedor único"""
        # En producción, consultaría APIs de registros
        risky_packages = ["small-package", "one-man-lib", "personal-utils"]
        return dependency["name"] in risky_packages
    
    def is_recently_transferred(self, dependency: Dict) -> bool:
        """Simula verificación de transferencia reciente"""
        recently_transferred = ["transferred-lib", "new-owner-pkg"]
        return dependency["name"] in recently_transferred
    
    def has_suspicious_urls(self, dependency: Dict) -> bool:
        """Simula verificación de URLs sospechosas"""
        suspicious_packages = ["url-shortener-lib", "redirect-utils"]
        return dependency["name"] in suspicious_packages
    
    def build_dependency_tree(self, dependencies: Dict) -> Dict:
        """Construye árbol de dependencias"""
        tree = {}
        
        for pm_type, deps in dependencies.items():
            tree[pm_type] = {
                "direct": len([d for d in deps if d.get("type") == "dependencies"]),
                "dev": len([d for d in deps if d.get("type") == "devDependencies"]),
                "total": len(deps),
                "depth_analysis": self.analyze_dependency_depth(deps)
            }
        
        return tree
    
    def analyze_dependency_depth(self, dependencies: List[Dict]) -> Dict:
        """Analiza profundidad de dependencias"""
        return {
            "max_depth": 5,  # Simulado
            "avg_depth": 3.2,
            "deep_dependencies": ["transitive-dep-1", "nested-lib-2"],
            "circular_dependencies": []
        }
    
    def scan_package_integrity(self, package_name: str, version: str) -> Dict:
        """Escanea integridad de paquete específico"""
        integrity_check = {
            "package": package_name,
            "version": version,
            "hash_verification": True,
            "signature_valid": True,
            "suspicious_files": [],
            "network_connections": [],
            "file_permissions": [],
            "obfuscated_code": False
        }
        
        # Simular verificaciones
        if package_name in ["malicious-lib", "crypto-miner"]:
            integrity_check.update({
                "hash_verification": False,
                "suspicious_files": ["mine.js", "backdoor.py"],
                "network_connections": ["evil.com:8080"],
                "obfuscated_code": True
            })
        
        return integrity_check
    
    def generate_sbom(self, scan_results: Dict) -> Dict:
        """Genera Software Bill of Materials (SBOM)"""
        sbom = {
            "sbom_version": "1.0",
            "timestamp": datetime.now().isoformat(),
            "project": scan_results["project_path"],
            "components": [],
            "vulnerabilities": scan_results["vulnerabilities"],
            "licenses": [],
            "suppliers": set()
        }
        
        # Procesar dependencias para SBOM
        for pm_type, deps in scan_results["dependencies"].items():
            for dep in deps:
                component = {
                    "name": dep["name"],
                    "version": dep.get("version", "unknown"),
                    "type": "library",
                    "supplier": self.get_package_supplier(dep["name"]),
                    "download_location": self.get_package_url(dep["name"], pm_type),
                    "files_analyzed": False,
                    "license_concluded": "NOASSERTION",
                    "license_declared": "NOASSERTION",
                    "copyright_text": "NOASSERTION"
                }
                
                sbom["components"].append(component)
                sbom["suppliers"].add(component["supplier"])
        
        # Convertir set a list para serialización JSON
        sbom["suppliers"] = list(sbom["suppliers"])
        
        return sbom
    
    def get_package_supplier(self, package_name: str) -> str:
        """Obtiene proveedor del paquete"""
        # En producción, consultaría metadatos del registro
        return f"supplier-of-{package_name}"
    
    def get_package_url(self, package_name: str, pm_type: str) -> str:
        """Obtiene URL del paquete"""
        base_urls = {
            "npm": "https://registry.npmjs.org/",
            "pip": "https://pypi.org/project/",
            "maven": "https://repo1.maven.org/maven2/"
        }
        return f"{base_urls.get(pm_type, '')}{package_name}"

def main():
    """Función principal"""
    scanner = SupplyChainScanner()
    
    print("🔗 BOFA Supply Chain Security Scanner v1.0")
    print("=" * 50)
    
    # Simular escaneo de proyecto
    project_path = "./sample_project"
    
    # Crear estructura de ejemplo
    os.makedirs(project_path, exist_ok=True)
    
    # Crear package.json de ejemplo
    sample_package_json = {
        "name": "sample-app",
        "version": "1.0.0",
        "dependencies": {
            "lodash": "4.17.19",
            "axios": "0.21.0",
            "express": "4.17.0"
        },
        "devDependencies": {
            "jest": "26.0.0",
            "eslint": "7.0.0"
        }
    }
    
    with open(os.path.join(project_path, "package.json"), "w") as f:
        json.dump(sample_package_json, f, indent=2)
    
    # Crear requirements.txt de ejemplo
    sample_requirements = """
django==3.1.0
requests==2.25.0
numpy==1.20.0
pandas==1.2.0
"""
    
    with open(os.path.join(project_path, "requirements.txt"), "w") as f:
        f.write(sample_requirements.strip())
    
    print(f"[INFO] Iniciando escaneo de: {project_path}")
    
    # Ejecutar escaneo
    results = scanner.scan_dependencies(project_path)
    
    print("\n📊 RESULTADOS DEL ESCANEO")
    print("=" * 30)
    
    print(f"Gestores de paquetes detectados: {len(results['package_managers'])}")
    for pm in results['package_managers']:
        deps_count = len(results['dependencies'].get(pm, []))
        print(f"  - {pm}: {deps_count} dependencias")
    
    print(f"\n🚨 VULNERABILIDADES ENCONTRADAS: {len(results['vulnerabilities'])}")
    for vuln in results['vulnerabilities']:
        print(f"  - {vuln['package']} v{vuln['version']}: {vuln['cve']} ({vuln['severity']})")
    
    print(f"\n⚠️ RIESGOS DE CADENA DE SUMINISTRO: {len(results['supply_chain_risks'])}")
    for risk in results['supply_chain_risks']:
        print(f"  - {risk['type']}: {risk['package']} - {risk['severity']}")
        print(f"    {risk['description']}")
    
    # Generar SBOM
    print("\n📋 Generando SBOM...")
    sbom = scanner.generate_sbom(results)
    print(f"Componentes en SBOM: {len(sbom['components'])}")
    print(f"Proveedores únicos: {len(sbom['suppliers'])}")
    
    # Verificar integridad de paquetes críticos
    print("\n🔍 Verificando integridad de paquetes...")
    critical_packages = ["lodash", "axios", "django"]
    
    for pkg in critical_packages:
        for pm_type, deps in results['dependencies'].items():
            for dep in deps:
                if dep['name'] == pkg:
                    integrity = scanner.scan_package_integrity(pkg, dep.get('version', ''))
                    status = "✅ OK" if integrity['hash_verification'] else "❌ FAILED"
                    print(f"  {pkg}: {status}")
                    break
    
    # Exportar resultados
    output_file = f"supply_chain_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    export_data = {
        "scan_results": results,
        "sbom": sbom,
        "timestamp": datetime.now().isoformat(),
        "scanner_version": "1.0"
    }
    
    with open(output_file, 'w') as f:
        json.dump(export_data, f, indent=2, default=str)
    
    print(f"\n💡 RECOMENDACIONES")
    print("1. 🔄 Actualizar paquetes con vulnerabilidades conocidas")
    print("2. 🔍 Revisar paquetes con transferencias de propiedad recientes")
    print("3. 📋 Implementar verificación automática de integridad")
    print("4. 🛡️ Configurar alertas para nuevas vulnerabilidades")
    print("5. 📊 Mantener SBOM actualizado en cada release")
    
    print(f"\n✅ Escaneo completado. Resultados en: {output_file}")
    
    # Limpiar archivos de ejemplo
    import shutil
    shutil.rmtree(project_path)

if __name__ == "__main__":
    main()
