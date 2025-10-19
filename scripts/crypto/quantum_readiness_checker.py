#!/usr/bin/env python3
"""
Quantum Readiness Checker - BOFA v2.5.1
Verifies cryptographic readiness for post-quantum era
Author: @descambiado
"""

import argparse
import json
import re
from datetime import datetime
from typing import Dict, Any, List
from pathlib import Path


class QuantumReadinessChecker:
    """Checks quantum-readiness of cryptographic implementations"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.findings = []
        self.vulnerable_algorithms = {
            "RSA": {"type": "asymmetric", "quantum_vulnerable": True, "replacement": "CRYSTALS-Kyber"},
            "DSA": {"type": "signature", "quantum_vulnerable": True, "replacement": "CRYSTALS-Dilithium"},
            "ECDSA": {"type": "signature", "quantum_vulnerable": True, "replacement": "CRYSTALS-Dilithium"},
            "ECDH": {"type": "key_exchange", "quantum_vulnerable": True, "replacement": "CRYSTALS-Kyber"},
            "DH": {"type": "key_exchange", "quantum_vulnerable": True, "replacement": "CRYSTALS-Kyber"},
            "AES": {"type": "symmetric", "quantum_vulnerable": False, "note": "Increase key size to 256-bit"},
            "SHA256": {"type": "hash", "quantum_vulnerable": False, "note": "Consider SHA3-256"},
            "SHA3": {"type": "hash", "quantum_vulnerable": False, "note": "Quantum-resistant"},
        }
    
    def scan_codebase(self, directory: str) -> Dict[str, Any]:
        """Scan codebase for cryptographic usage"""
        path = Path(directory)
        
        if not path.exists():
            return {"error": "Directory not found"}
        
        files_scanned = 0
        vulnerable_files = 0
        
        for file_path in path.rglob("*.py"):
            result = self._scan_file(file_path)
            if result:
                files_scanned += 1
                if result["vulnerabilities"]:
                    vulnerable_files += 1
                    self.findings.append(result)
        
        return {
            "files_scanned": files_scanned,
            "vulnerable_files": vulnerable_files
        }
    
    def _scan_file(self, file_path: Path) -> Dict[str, Any]:
        """Scan individual file for crypto usage"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            vulnerabilities = []
            
            # Pattern matching for cryptographic libraries
            patterns = {
                "RSA": [r"RSA\.generate", r"rsa\.new", r"RSA_PKCS1"],
                "DSA": [r"DSA\.generate", r"dsa\.new"],
                "ECDSA": [r"ECDSA", r"ec\.generate_private_key"],
                "ECDH": [r"ECDH", r"ec\.ECDH"],
                "DH": [r"DH\.generate", r"dh\.generate_parameters"],
                "AES": [r"AES\.new\(", r"Cipher\.AES"],
                "SHA256": [r"hashlib\.sha256", r"SHA256\.new"],
            }
            
            for algo, pattern_list in patterns.items():
                for pattern in pattern_list:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        algo_info = self.vulnerable_algorithms.get(algo.upper(), {})
                        
                        if algo_info.get("quantum_vulnerable"):
                            vulnerabilities.append({
                                "algorithm": algo.upper(),
                                "line": line_num,
                                "type": algo_info.get("type"),
                                "quantum_vulnerable": True,
                                "replacement": algo_info.get("replacement"),
                                "severity": "HIGH"
                            })
                        elif algo_info.get("note"):
                            vulnerabilities.append({
                                "algorithm": algo.upper(),
                                "line": line_num,
                                "type": algo_info.get("type"),
                                "quantum_vulnerable": False,
                                "note": algo_info.get("note"),
                                "severity": "INFO"
                            })
            
            if vulnerabilities:
                return {
                    "file": str(file_path),
                    "vulnerabilities": vulnerabilities,
                    "quantum_risk_score": self._calculate_quantum_risk(vulnerabilities)
                }
            
            return None
        
        except Exception as e:
            if self.verbose:
                print(f"Error scanning {file_path}: {e}")
            return None
    
    def _calculate_quantum_risk(self, vulnerabilities: List[Dict]) -> int:
        """Calculate quantum risk score"""
        vulnerable_count = sum(1 for v in vulnerabilities if v.get("quantum_vulnerable"))
        return min(100, vulnerable_count * 20)
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate quantum readiness report"""
        total_vulns = sum(len(f["vulnerabilities"]) for f in self.findings)
        quantum_vulnerable = sum(
            sum(1 for v in f["vulnerabilities"] if v.get("quantum_vulnerable"))
            for f in self.findings
        )
        
        return {
            "scan_info": {
                "tool": "Quantum Readiness Checker",
                "version": "1.0",
                "timestamp": datetime.now().isoformat(),
                "category": "crypto"
            },
            "summary": {
                "files_with_crypto": len(self.findings),
                "total_crypto_usage": total_vulns,
                "quantum_vulnerable_algos": quantum_vulnerable,
                "readiness_score": self._calculate_readiness_score()
            },
            "findings": self.findings,
            "migration_plan": self._generate_migration_plan(),
            "recommendations": self._generate_recommendations()
        }
    
    def _calculate_readiness_score(self) -> int:
        """Calculate overall quantum readiness score (0-100)"""
        if not self.findings:
            return 100
        
        total_usages = sum(len(f["vulnerabilities"]) for f in self.findings)
        vulnerable = sum(
            sum(1 for v in f["vulnerabilities"] if v.get("quantum_vulnerable"))
            for f in self.findings
        )
        
        if total_usages == 0:
            return 100
        
        readiness = 100 - int((vulnerable / total_usages) * 100)
        return max(0, readiness)
    
    def _generate_migration_plan(self) -> Dict[str, Any]:
        """Generate PQC migration plan"""
        algorithms_to_replace = {}
        
        for finding in self.findings:
            for vuln in finding["vulnerabilities"]:
                if vuln.get("quantum_vulnerable"):
                    algo = vuln["algorithm"]
                    if algo not in algorithms_to_replace:
                        algorithms_to_replace[algo] = {
                            "replacement": vuln.get("replacement"),
                            "occurrences": 0,
                            "priority": "HIGH" if algo in ["RSA", "ECDSA"] else "MEDIUM"
                        }
                    algorithms_to_replace[algo]["occurrences"] += 1
        
        return {
            "algorithms_to_replace": algorithms_to_replace,
            "timeline": {
                "phase1": "Inventory and assessment (Month 1-2)",
                "phase2": "Hybrid crypto implementation (Month 3-6)",
                "phase3": "Full PQC migration (Month 7-12)"
            },
            "recommended_pqc_algorithms": {
                "key_encapsulation": "CRYSTALS-Kyber (NIST standard)",
                "digital_signatures": "CRYSTALS-Dilithium (NIST standard)",
                "alternative_signatures": "SPHINCS+ (stateless hash-based)"
            }
        }
    
    def _generate_recommendations(self) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = [
            "Start planning PQC migration immediately - quantum computers pose near-term threat",
            "Implement hybrid classical/post-quantum schemes during transition",
            "Prioritize replacing RSA and ECDSA/ECDH implementations",
            "Increase AES key sizes to 256-bit minimum",
            "Consider crypto-agility in new implementations"
        ]
        
        if self._calculate_readiness_score() < 50:
            recommendations.insert(0, "URGENT: System is highly vulnerable to quantum attacks")
        
        return recommendations


def main():
    parser = argparse.ArgumentParser(description="Quantum readiness checker")
    parser.add_argument("-d", "--directory", required=True, help="Codebase directory")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("-v", "--verbose", action="store_true")
    
    args = parser.parse_args()
    
    checker = QuantumReadinessChecker(verbose=args.verbose)
    stats = checker.scan_codebase(args.directory)
    
    print(f"[+] Scanned {stats.get('files_scanned', 0)} files")
    print(f"[!] Found {stats.get('vulnerable_files', 0)} files with quantum-vulnerable crypto")
    
    report = checker.generate_report()
    print(f"[+] Quantum Readiness Score: {report['summary']['readiness_score']}/100")
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report saved to {args.output}")
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
