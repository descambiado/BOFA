
#!/usr/bin/env python3
"""
Social Engineering Toolkit (Educativo) v1.0
Herramientas educativas para concienciación sobre ingeniería social
Author: @descambiado
"""

import random
import string
import json
import re
from typing import Dict, List, Any
from datetime import datetime, timedelta

class SocialEngineeringToolkit:
    def __init__(self):
        self.phishing_templates = [
            "urgent_security_update",
            "account_verification", 
            "prize_notification",
            "it_support_request",
            "fake_invoice",
            "social_media_alert"
        ]
        
        self.pretext_scenarios = [
            "IT Support Technician",
            "Bank Security Officer", 
            "Survey Researcher",
            "Delivery Company",
            "Government Official",
            "Software Vendor"
        ]
        
    def generate_fake_email(self, template: str, target_info: Dict[str, str]) -> Dict[str, Any]:
        """Genera email de phishing educativo"""
        
        templates = {
            "urgent_security_update": {
                "subject": f"🚨 URGENT: Security Alert for {target_info.get('name', 'User')}",
                "body": f"""
Dear {target_info.get('name', 'Valued Customer')},

We have detected suspicious activity on your account from IP: {self._generate_fake_ip()}.

IMMEDIATE ACTION REQUIRED:
- Login within 24 hours to verify your identity
- Update your security settings
- Review recent transactions

Click here to secure your account: [MALICIOUS_LINK]

Security Team
{target_info.get('company', 'SecureBank')}
                """,
                "urgency": "high",
                "social_triggers": ["fear", "urgency", "authority"]
            },
            
            "account_verification": {
                "subject": "Account Verification Required - Action Needed",
                "body": f"""
Hello {target_info.get('name', 'Customer')},

Your account verification is pending. To maintain access to your account, please verify your information.

Account Details:
- Email: {target_info.get('email', 'user@example.com')}
- Last Login: {(datetime.now() - timedelta(days=random.randint(1,7))).strftime('%Y-%m-%d')}

Verify Now: [VERIFICATION_LINK]

This link expires in 48 hours.

Best regards,
Account Security Team
                """,
                "urgency": "medium",
                "social_triggers": ["authority", "scarcity", "compliance"]
            }
        }
        
        return templates.get(template, templates["urgent_security_update"])
    
    def analyze_target_vulnerability(self, target_profile: Dict[str, Any]) -> Dict[str, Any]:
        """Analiza vulnerabilidades del objetivo (educativo)"""
        
        vulnerability_factors = {
            "age_group": self._assess_age_vulnerability(target_profile.get('age', 30)),
            "tech_savviness": self._assess_tech_savviness(target_profile.get('tech_level', 'medium')),
            "social_media_exposure": self._assess_social_exposure(target_profile.get('social_active', True)),
            "job_role": self._assess_role_vulnerability(target_profile.get('role', 'employee')),
            "stress_indicators": self._assess_stress_factors(target_profile.get('stress_level', 'medium'))
        }
        
        overall_score = sum(vulnerability_factors.values()) / len(vulnerability_factors)
        
        recommendations = self._generate_defense_recommendations(vulnerability_factors)
        
        return {
            "vulnerability_score": round(overall_score, 2),
            "risk_level": self._categorize_risk(overall_score),
            "factors": vulnerability_factors,
            "recommended_attacks": self._suggest_attack_vectors(vulnerability_factors),
            "defense_recommendations": recommendations
        }
    
    def create_pretext_scenario(self, scenario_type: str, target_info: Dict[str, str]) -> Dict[str, Any]:
        """Crea escenario de pretexto"""
        
        scenarios = {
            "IT Support Technician": {
                "identity": "IT Support from TechCorp",
                "reason": "System maintenance and security update",
                "urgency": "We need to update your system remotely today",
                "ask": "Can you please provide your username for the update?",
                "credibility_boosters": [
                    f"Reference ticket: TC-{random.randint(10000, 99999)}",
                    "Manager: Sarah Johnson approved this maintenance",
                    "We're calling all employees in your department"
                ]
            },
            
            "Bank Security Officer": {
                "identity": f"Security Officer from {target_info.get('bank', 'SecureBank')}",
                "reason": "Suspicious transaction detected on your account",
                "urgency": "This needs immediate verification to protect your funds",
                "ask": "Can you verify your account details?",
                "credibility_boosters": [
                    f"Transaction amount: ${random.randint(100, 2000)}",
                    f"Merchant: {random.choice(['Amazon', 'Best Buy', 'Target'])}",
                    "We've temporarily frozen your account for protection"
                ]
            }
        }
        
        return scenarios.get(scenario_type, scenarios["IT Support Technician"])
    
    def generate_awareness_report(self, assessment_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Genera reporte de concienciación"""
        
        total_targets = len(assessment_results)
        high_risk = sum(1 for r in assessment_results if r['risk_level'] == 'HIGH')
        medium_risk = sum(1 for r in assessment_results if r['risk_level'] == 'MEDIUM')
        low_risk = sum(1 for r in assessment_results if r['risk_level'] == 'LOW')
        
        common_vulnerabilities = self._identify_common_vulnerabilities(assessment_results)
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "total_assessed": total_targets,
            "risk_distribution": {
                "high": high_risk,
                "medium": medium_risk, 
                "low": low_risk
            },
            "risk_percentages": {
                "high": round((high_risk / total_targets) * 100, 1) if total_targets > 0 else 0,
                "medium": round((medium_risk / total_targets) * 100, 1) if total_targets > 0 else 0,
                "low": round((low_risk / total_targets) * 100, 1) if total_targets > 0 else 0
            },
            "common_vulnerabilities": common_vulnerabilities,
            "recommended_training": self._recommend_training(common_vulnerabilities),
            "security_recommendations": self._organization_recommendations(assessment_results)
        }
        
        return report
    
    def _generate_fake_ip(self) -> str:
        """Genera IP falsa"""
        return f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    
    def _assess_age_vulnerability(self, age: int) -> float:
        """Evalúa vulnerabilidad por edad"""
        if age < 25 or age > 65:
            return 0.7  # Mayor vulnerabilidad
        elif 25 <= age <= 45:
            return 0.4  # Menor vulnerabilidad
        else:
            return 0.6  # Vulnerabilidad media
    
    def _assess_tech_savviness(self, tech_level: str) -> float:
        """Evalúa conocimientos técnicos"""
        levels = {
            "low": 0.8,
            "medium": 0.5, 
            "high": 0.2
        }
        return levels.get(tech_level, 0.5)
    
    def _assess_social_exposure(self, social_active: bool) -> float:
        """Evalúa exposición en redes sociales"""
        return 0.7 if social_active else 0.3
    
    def _assess_role_vulnerability(self, role: str) -> float:
        """Evalúa vulnerabilidad por rol"""
        high_risk_roles = ["executive", "hr", "finance", "admin"]
        medium_risk_roles = ["manager", "supervisor"]
        
        if role.lower() in high_risk_roles:
            return 0.8
        elif role.lower() in medium_risk_roles:
            return 0.6
        else:
            return 0.4
    
    def _assess_stress_factors(self, stress_level: str) -> float:
        """Evalúa factores de estrés"""
        levels = {
            "low": 0.3,
            "medium": 0.5,
            "high": 0.8
        }
        return levels.get(stress_level, 0.5)
    
    def _categorize_risk(self, score: float) -> str:
        """Categoriza nivel de riesgo"""
        if score >= 0.7:
            return "HIGH"
        elif score >= 0.5:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _suggest_attack_vectors(self, factors: Dict[str, float]) -> List[str]:
        """Sugiere vectores de ataque (educativo)"""
        vectors = []
        
        if factors["tech_savviness"] > 0.6:
            vectors.append("Email phishing with urgent technical language")
        
        if factors["social_media_exposure"] > 0.6:
            vectors.append("Social media information gathering")
        
        if factors["job_role"] > 0.7:
            vectors.append("Targeted spear phishing")
        
        if factors["stress_indicators"] > 0.6:
            vectors.append("Urgency-based social engineering")
        
        return vectors
    
    def _generate_defense_recommendations(self, factors: Dict[str, float]) -> List[str]:
        """Genera recomendaciones defensivas"""
        recommendations = []
        
        if factors["tech_savviness"] > 0.6:
            recommendations.append("📚 Capacitación técnica en seguridad")
        
        if factors["social_media_exposure"] > 0.6:
            recommendations.append("🔒 Configuración de privacidad en redes sociales")
        
        if factors["job_role"] > 0.7:
            recommendations.append("🎯 Entrenamiento especializado para roles críticos")
        
        recommendations.extend([
            "📧 Verificación de emails sospechosos",
            "🔐 Autenticación multifactor",
            "⚠️ Reportar intentos de phishing"
        ])
        
        return recommendations
    
    def _identify_common_vulnerabilities(self, results: List[Dict[str, Any]]) -> List[str]:
        """Identifica vulnerabilidades comunes"""
        vulnerabilities = []
        
        if len(results) == 0:
            return vulnerabilities
        
        # Analizar factores comunes
        avg_tech = sum(r['factors']['tech_savviness'] for r in results) / len(results)
        avg_social = sum(r['factors']['social_media_exposure'] for r in results) / len(results)
        
        if avg_tech > 0.6:
            vulnerabilities.append("Bajo conocimiento técnico generalizado")
        if avg_social > 0.6:
            vulnerabilities.append("Alta exposición en redes sociales")
        
        return vulnerabilities
    
    def _recommend_training(self, vulnerabilities: List[str]) -> List[str]:
        """Recomienda entrenamientos"""
        training = [
            "🎓 Taller de concientización sobre phishing",
            "🔍 Identificación de emails maliciosos",
            "🛡️ Mejores prácticas de seguridad",
            "📱 Seguridad en redes sociales"
        ]
        
        return training
    
    def _organization_recommendations(self, results: List[Dict[str, Any]]) -> List[str]:
        """Recomendaciones organizacionales"""
        return [
            "🚨 Implementar simulacros de phishing regulares",
            "📋 Política de verificación de identidad",
            "🔐 Autenticación multifactor obligatoria",
            "📚 Programa de capacitación continua",
            "🎯 Entrenamiento especializado para roles críticos",
            "📊 Métricas de concienciación en seguridad"
        ]

def main():
    """Función principal educativa"""
    toolkit = SocialEngineeringToolkit()
    
    print("🎭 Social Engineering Toolkit (Educativo) v1.0")
    print("=" * 50)
    print("⚠️ SOLO PARA FINES EDUCATIVOS Y CONCIENCIACIÓN")
    print("=" * 50)
    
    # Ejemplo de perfil objetivo
    target_profile = {
        "name": "Juan Pérez",
        "email": "juan.perez@empresa.com",
        "age": 45,
        "tech_level": "low",
        "social_active": True,
        "role": "executive",
        "stress_level": "high",
        "company": "TechCorp",
        "bank": "SecureBank"
    }
    
    print("\n👤 ANÁLISIS DE VULNERABILIDAD")
    print("-" * 30)
    
    vulnerability_analysis = toolkit.analyze_target_vulnerability(target_profile)
    
    print(f"Objetivo: {target_profile['name']}")
    print(f"Puntuación de vulnerabilidad: {vulnerability_analysis['vulnerability_score']}")
    print(f"Nivel de riesgo: {vulnerability_analysis['risk_level']}")
    
    print("\n📊 Factores de vulnerabilidad:")
    for factor, score in vulnerability_analysis['factors'].items():
        print(f"  {factor}: {score:.2f}")
    
    print("\n🎯 Vectores de ataque recomendados:")
    for vector in vulnerability_analysis['recommended_attacks']:
        print(f"  - {vector}")
    
    print("\n🛡️ Recomendaciones defensivas:")
    for rec in vulnerability_analysis['defense_recommendations']:
        print(f"  {rec}")
    
    print("\n📧 EJEMPLO DE EMAIL DE PHISHING")
    print("-" * 30)
    
    phishing_email = toolkit.generate_fake_email("urgent_security_update", target_profile)
    
    print(f"Asunto: {phishing_email['subject']}")
    print(f"Urgencia: {phishing_email['urgency']}")
    print(f"Disparadores sociales: {', '.join(phishing_email['social_triggers'])}")
    print(f"\nCuerpo del email:\n{phishing_email['body'][:200]}...")
    
    print("\n📞 ESCENARIO DE PRETEXTO")
    print("-" * 30)
    
    pretext = toolkit.create_pretext_scenario("IT Support Technician", target_profile)
    
    print(f"Identidad: {pretext['identity']}")
    print(f"Razón: {pretext['reason']}")
    print(f"Urgencia: {pretext['urgency']}")
    print(f"Solicitud: {pretext['ask']}")
    print("\nRefuerzos de credibilidad:")
    for booster in pretext['credibility_boosters']:
        print(f"  - {booster}")
    
    print("\n📋 REPORTE DE CONCIENCIACIÓN")
    print("-" * 30)
    
    # Simular múltiples objetivos
    sample_results = [vulnerability_analysis]
    for i in range(4):
        sample_profile = target_profile.copy()
        sample_profile['tech_level'] = random.choice(['low', 'medium', 'high'])
        sample_profile['stress_level'] = random.choice(['low', 'medium', 'high'])
        sample_results.append(toolkit.analyze_target_vulnerability(sample_profile))
    
    awareness_report = toolkit.generate_awareness_report(sample_results)
    
    print(f"Total evaluados: {awareness_report['total_assessed']}")
    print("\nDistribución de riesgo:")
    for level, count in awareness_report['risk_distribution'].items():
        percentage = awareness_report['risk_percentages'][level]
        print(f"  {level.upper()}: {count} ({percentage}%)")
    
    print("\nVulnerabilidades comunes:")
    for vuln in awareness_report['common_vulnerabilities']:
        print(f"  - {vuln}")
    
    print("\nEntrenamiento recomendado:")
    for training in awareness_report['recommended_training']:
        print(f"  {training}")
    
    # Exportar resultados
    output_file = f"social_engineering_assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump({
            'target_analysis': vulnerability_analysis,
            'phishing_example': phishing_email,
            'pretext_example': pretext,
            'awareness_report': awareness_report
        }, f, indent=2)
    
    print(f"\n✅ Análisis exportado a: {output_file}")
    print("\n🎓 RECUERDA: Esta herramienta es solo para educación y concienciación")
    print("🚫 NO usar para actividades maliciosas o no autorizadas")

if __name__ == "__main__":
    main()
