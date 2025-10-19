#!/usr/bin/env python3
"""
Identity Trust Analyzer - BOFA v2.5.1
Analyzes identity trust levels and access patterns
Author: @descambiado
"""

import argparse
import json
from datetime import datetime, timedelta
from typing import Dict, Any, List
import random


class IdentityTrustAnalyzer:
    """Analyzes identity trust and access patterns"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.identities = []
        self.trust_factors = [
            "mfa_enabled", "password_age", "last_login", "login_attempts",
            "privilege_level", "access_patterns", "device_posture"
        ]
    
    def analyze_identities(self, auth_log: str) -> Dict[str, Any]:
        """Analyze identities from authentication logs"""
        try:
            with open(auth_log, 'r') as f:
                logs = json.load(f)
            
            for log_entry in logs:
                identity = self._analyze_identity(log_entry)
                if identity:
                    self.identities.append(identity)
            
            return {
                "identities_analyzed": len(self.identities),
                "high_risk_count": sum(1 for i in self.identities if i["risk_level"] == "HIGH"),
                "medium_risk_count": sum(1 for i in self.identities if i["risk_level"] == "MEDIUM")
            }
        
        except FileNotFoundError:
            # Generate sample data for demonstration
            return self._generate_sample_analysis()
        except json.JSONDecodeError:
            return {"error": "Invalid JSON format"}
    
    def _analyze_identity(self, log_entry: Dict) -> Dict[str, Any]:
        """Analyze single identity"""
        username = log_entry.get("username", "unknown")
        
        trust_score = 100
        risk_factors = []
        
        # MFA check
        if not log_entry.get("mfa_enabled", False):
            trust_score -= 30
            risk_factors.append("MFA not enabled")
        
        # Password age
        password_age_days = log_entry.get("password_age_days", 0)
        if password_age_days > 90:
            trust_score -= 20
            risk_factors.append(f"Password age: {password_age_days} days")
        
        # Failed login attempts
        failed_attempts = log_entry.get("failed_login_attempts", 0)
        if failed_attempts > 3:
            trust_score -= 15
            risk_factors.append(f"{failed_attempts} failed login attempts")
        
        # Privilege level
        is_admin = log_entry.get("is_admin", False)
        if is_admin:
            trust_score -= 10  # Higher scrutiny for admins
        
        # Determine risk level
        if trust_score >= 70:
            risk_level = "LOW"
        elif trust_score >= 40:
            risk_level = "MEDIUM"
        else:
            risk_level = "HIGH"
        
        return {
            "username": username,
            "trust_score": max(0, trust_score),
            "risk_level": risk_level,
            "risk_factors": risk_factors,
            "is_admin": is_admin,
            "mfa_enabled": log_entry.get("mfa_enabled", False)
        }
    
    def _generate_sample_analysis(self) -> Dict[str, Any]:
        """Generate sample analysis for demonstration"""
        sample_users = [
            {"username": "admin", "mfa": True, "password_age": 45, "failed": 0, "admin": True},
            {"username": "john.doe", "mfa": False, "password_age": 120, "failed": 2, "admin": False},
            {"username": "jane.smith", "mfa": True, "password_age": 30, "failed": 0, "admin": False},
            {"username": "root", "mfa": False, "password_age": 365, "failed": 5, "admin": True},
            {"username": "service_account", "mfa": False, "password_age": 180, "failed": 1, "admin": True}
        ]
        
        for user in sample_users:
            identity = self._analyze_identity({
                "username": user["username"],
                "mfa_enabled": user["mfa"],
                "password_age_days": user["password_age"],
                "failed_login_attempts": user["failed"],
                "is_admin": user["admin"]
            })
            self.identities.append(identity)
        
        return {
            "identities_analyzed": len(self.identities),
            "high_risk_count": sum(1 for i in self.identities if i["risk_level"] == "HIGH"),
            "medium_risk_count": sum(1 for i in self.identities if i["risk_level"] == "MEDIUM")
        }
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate trust analysis report"""
        return {
            "scan_info": {
                "tool": "Identity Trust Analyzer",
                "version": "1.0",
                "timestamp": datetime.now().isoformat(),
                "category": "zero_trust"
            },
            "summary": {
                "total_identities": len(self.identities),
                "high_risk": sum(1 for i in self.identities if i["risk_level"] == "HIGH"),
                "medium_risk": sum(1 for i in self.identities if i["risk_level"] == "MEDIUM"),
                "low_risk": sum(1 for i in self.identities if i["risk_level"] == "LOW"),
                "avg_trust_score": sum(i["trust_score"] for i in self.identities) / len(self.identities) if self.identities else 0
            },
            "identities": sorted(self.identities, key=lambda x: x["trust_score"]),
            "recommendations": self._generate_recommendations()
        }
    
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        # High risk identities
        high_risk = [i for i in self.identities if i["risk_level"] == "HIGH"]
        if high_risk:
            recommendations.append(f"Immediately review {len(high_risk)} high-risk identities")
        
        # MFA enforcement
        no_mfa = [i for i in self.identities if not i["mfa_enabled"]]
        if no_mfa:
            recommendations.append(f"Enable MFA for {len(no_mfa)} accounts without it")
        
        # Admin accounts
        high_risk_admins = [i for i in self.identities if i["is_admin"] and i["risk_level"] == "HIGH"]
        if high_risk_admins:
            recommendations.append(f"CRITICAL: {len(high_risk_admins)} admin accounts are high-risk")
        
        return recommendations


def main():
    parser = argparse.ArgumentParser(description="Identity trust analysis")
    parser.add_argument("-f", "--file", help="Auth log file (JSON)")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("-v", "--verbose", action="store_true")
    
    args = parser.parse_args()
    
    analyzer = IdentityTrustAnalyzer(verbose=args.verbose)
    stats = analyzer.analyze_identities(args.file or "sample.json")
    
    print(f"[+] Analyzed {stats.get('identities_analyzed', 0)} identities")
    print(f"[!] High risk: {stats.get('high_risk_count', 0)}")
    print(f"[!] Medium risk: {stats.get('medium_risk_count', 0)}")
    
    report = analyzer.generate_report()
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report saved to {args.output}")
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
