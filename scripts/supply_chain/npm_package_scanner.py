#!/usr/bin/env python3
"""
NPM Package Scanner - BOFA v2.5.1
Scans NPM packages for vulnerabilities and security issues
Author: @descambiado
"""

import argparse
import json
import os
import re
import hashlib
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path
import subprocess


class NPMPackageScanner:
    """Scans NPM packages for security vulnerabilities"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.results = []
        self.known_vulnerabilities = self._load_known_vulns()
        self.typosquatting_database = self._load_typosquatting_db()
    
    def _load_known_vulns(self) -> Dict[str, List[Dict]]:
        """Load database of known vulnerable packages"""
        return {
            "event-stream": [{"version": "3.3.6", "cve": "CVE-2018-3721", "severity": "CRITICAL"}],
            "flatmap-stream": [{"version": "0.1.1", "cve": "CVE-2018-16487", "severity": "CRITICAL"}],
            "eslint-scope": [{"version": "3.7.2", "cve": "CVE-2018-16469", "severity": "HIGH"}],
            "getcookies": [{"version": "*", "cve": "MALWARE-2019", "severity": "CRITICAL"}],
            "ua-parser-js": [{"version": "0.7.29-0.7.31", "cve": "CVE-2021-27292", "severity": "CRITICAL"}],
        }
    
    def _load_typosquatting_db(self) -> Dict[str, str]:
        """Load common typosquatting patterns"""
        popular_packages = [
            "react", "vue", "angular", "express", "lodash", "axios", "webpack",
            "typescript", "eslint", "prettier", "moment", "chalk", "commander"
        ]
        # Generate common typos
        typos = {}
        for pkg in popular_packages:
            # Common typo patterns
            typos[pkg + "js"] = pkg
            typos[pkg + "-js"] = pkg
            typos[pkg.replace("e", "3")] = pkg
            typos[pkg.replace("o", "0")] = pkg
        return typos
    
    def scan_package_json(self, package_json_path: str) -> Dict[str, Any]:
        """Scan package.json file"""
        path = Path(package_json_path)
        
        if not path.exists():
            return {"error": "package.json not found"}
        
        try:
            with open(path, 'r') as f:
                package_data = json.load(f)
            
            dependencies = {
                **package_data.get("dependencies", {}),
                **package_data.get("devDependencies", {})
            }
            
            total_packages = len(dependencies)
            vulnerable_count = 0
            typosquatting_count = 0
            outdated_count = 0
            
            for package_name, version in dependencies.items():
                finding = self._analyze_package(package_name, version)
                if finding:
                    self.results.append(finding)
                    if finding.get("vulnerability"):
                        vulnerable_count += 1
                    if finding.get("typosquatting"):
                        typosquatting_count += 1
                    if finding.get("outdated"):
                        outdated_count += 1
            
            # Run npm audit if available
            npm_audit_results = self._run_npm_audit(path.parent)
            
            return {
                "total_packages": total_packages,
                "vulnerable_packages": vulnerable_count,
                "typosquatting_suspects": typosquatting_count,
                "outdated_packages": outdated_count,
                "npm_audit": npm_audit_results
            }
        
        except json.JSONDecodeError:
            return {"error": "Invalid package.json format"}
        except Exception as e:
            return {"error": str(e)}
    
    def _analyze_package(self, package_name: str, version: str) -> Optional[Dict[str, Any]]:
        """Analyze individual package"""
        issues = []
        
        # Check known vulnerabilities
        if package_name in self.known_vulnerabilities:
            for vuln in self.known_vulnerabilities[package_name]:
                if self._version_matches(version, vuln["version"]):
                    issues.append({
                        "type": "vulnerability",
                        "severity": vuln["severity"],
                        "cve": vuln["cve"],
                        "description": f"Known vulnerability in {package_name}@{version}"
                    })
        
        # Check typosquatting
        if package_name in self.typosquatting_database:
            issues.append({
                "type": "typosquatting",
                "severity": "HIGH",
                "description": f"Possible typosquatting of '{self.typosquatting_database[package_name]}'",
                "intended_package": self.typosquatting_database[package_name]
            })
        
        # Check for suspicious patterns
        suspicious = self._check_suspicious_patterns(package_name)
        if suspicious:
            issues.extend(suspicious)
        
        if issues:
            return {
                "package": package_name,
                "version": version,
                "issues": issues,
                "risk_score": self._calculate_package_risk(issues)
            }
        
        return None
    
    def _version_matches(self, version: str, pattern: str) -> bool:
        """Check if version matches vulnerability pattern"""
        if pattern == "*":
            return True
        # Simple version matching (can be enhanced with semver)
        return version.strip("^~") in pattern
    
    def _check_suspicious_patterns(self, package_name: str) -> List[Dict]:
        """Check for suspicious package name patterns"""
        issues = []
        
        # Check for excessive hyphens (common in malicious packages)
        if package_name.count('-') > 5:
            issues.append({
                "type": "suspicious",
                "severity": "MEDIUM",
                "description": "Package name contains excessive hyphens"
            })
        
        # Check for leetspeak
        if re.search(r'[0-9]{2,}', package_name) or '1337' in package_name:
            issues.append({
                "type": "suspicious",
                "severity": "MEDIUM",
                "description": "Package name contains unusual number patterns"
            })
        
        # Check for single character packages
        if len(package_name) <= 2:
            issues.append({
                "type": "suspicious",
                "severity": "LOW",
                "description": "Very short package name"
            })
        
        return issues
    
    def _calculate_package_risk(self, issues: List[Dict]) -> int:
        """Calculate risk score for package"""
        severity_scores = {"CRITICAL": 100, "HIGH": 75, "MEDIUM": 50, "LOW": 25}
        total = sum(severity_scores.get(issue.get("severity", "LOW"), 0) for issue in issues)
        return min(100, total)
    
    def _run_npm_audit(self, project_dir: Path) -> Dict[str, Any]:
        """Run npm audit if available"""
        try:
            result = subprocess.run(
                ["npm", "audit", "--json"],
                cwd=project_dir,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode in [0, 1]:  # 0 = no vulns, 1 = vulns found
                audit_data = json.loads(result.stdout)
                return {
                    "available": True,
                    "vulnerabilities": audit_data.get("metadata", {}).get("vulnerabilities", {}),
                    "dependencies": audit_data.get("metadata", {}).get("dependencies", 0)
                }
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            pass
        
        return {"available": False, "reason": "npm audit not available"}
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate structured report"""
        critical = sum(1 for r in self.results for i in r["issues"] if i.get("severity") == "CRITICAL")
        high = sum(1 for r in self.results for i in r["issues"] if i.get("severity") == "HIGH")
        medium = sum(1 for r in self.results for i in r["issues"] if i.get("severity") == "MEDIUM")
        
        return {
            "scan_info": {
                "tool": "NPM Package Scanner",
                "version": "1.0",
                "timestamp": datetime.now().isoformat(),
                "category": "supply_chain"
            },
            "summary": {
                "packages_analyzed": len(self.results),
                "vulnerabilities_by_severity": {
                    "critical": critical,
                    "high": high,
                    "medium": medium
                }
            },
            "findings": self.results,
            "recommendations": self._generate_recommendations()
        }
    
    def _generate_recommendations(self) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        for result in self.results:
            for issue in result["issues"]:
                if issue.get("severity") in ["CRITICAL", "HIGH"]:
                    if issue.get("type") == "vulnerability":
                        recommendations.append(
                            f"Update {result['package']} to patch {issue.get('cve', 'vulnerability')}"
                        )
                    elif issue.get("type") == "typosquatting":
                        recommendations.append(
                            f"Replace {result['package']} with correct package: {issue.get('intended_package')}"
                        )
        
        return recommendations[:10]


def main():
    parser = argparse.ArgumentParser(description="NPM package security scanner")
    parser.add_argument("-f", "--file", default="package.json", help="Path to package.json")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    scanner = NPMPackageScanner(verbose=args.verbose)
    scan_stats = scanner.scan_package_json(args.file)
    
    print(f"[+] Analyzed {scan_stats.get('total_packages', 0)} packages")
    print(f"[+] Found {scan_stats.get('vulnerable_packages', 0)} vulnerable packages")
    print(f"[+] Detected {scan_stats.get('typosquatting_suspects', 0)} typosquatting suspects")
    
    report = scanner.generate_report()
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report saved to {args.output}")
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
