#!/usr/bin/env python3
"""
Kubernetes Security Posture - BOFA v2.5.1
Comprehensive K8s security assessment based on CIS benchmarks
Author: @descambiado
"""

import argparse
import json
import subprocess
from datetime import datetime
from typing import Dict, Any, List, Optional


class K8sSecurityPosture:
    """Kubernetes security posture assessment"""
    
    def __init__(self, namespace: str = "default", verbose: bool = False):
        self.namespace = namespace
        self.verbose = verbose
        self.findings = []
        self.checks = self._load_security_checks()
    
    def _load_security_checks(self) -> List[Dict]:
        """Load CIS Kubernetes Benchmark checks"""
        return [
            {
                "id": "5.2.1",
                "category": "Pod Security",
                "check": "privileged_containers",
                "description": "Minimize use of privileged containers",
                "severity": "CRITICAL"
            },
            {
                "id": "5.2.2",
                "category": "Pod Security",
                "check": "host_network",
                "description": "Minimize hostNetwork usage",
                "severity": "HIGH"
            },
            {
                "id": "5.2.3",
                "category": "Pod Security",
                "check": "host_pid_ipc",
                "description": "Minimize hostPID and hostIPC usage",
                "severity": "HIGH"
            },
            {
                "id": "5.2.4",
                "category": "Pod Security",
                "check": "host_path",
                "description": "Minimize hostPath volumes",
                "severity": "MEDIUM"
            },
            {
                "id": "5.2.6",
                "category": "Pod Security",
                "check": "root_containers",
                "description": "Do not run containers as root",
                "severity": "HIGH"
            },
            {
                "id": "5.7.1",
                "category": "Network Policies",
                "check": "network_policies",
                "description": "Create NetworkPolicies",
                "severity": "MEDIUM"
            },
            {
                "id": "5.1.1",
                "category": "RBAC",
                "check": "cluster_admin_binding",
                "description": "Ensure cluster-admin role is used sparingly",
                "severity": "HIGH"
            },
            {
                "id": "5.1.5",
                "category": "RBAC",
                "check": "default_sa_automount",
                "description": "Ensure default service accounts are not actively used",
                "severity": "MEDIUM"
            }
        ]
    
    def assess(self) -> Dict[str, Any]:
        """Run comprehensive security assessment"""
        
        if not self._check_kubectl():
            return {"error": "kubectl not available"}
        
        print(f"[+] Starting Kubernetes security assessment...")
        
        for check in self.checks:
            result = getattr(self, f"_check_{check['check']}")()
            if result:
                self.findings.append({
                    "check_id": check["id"],
                    "category": check["category"],
                    "description": check["description"],
                    "severity": check["severity"],
                    **result
                })
        
        return {
            "total_checks": len(self.checks),
            "findings_count": len(self.findings),
            "namespace": self.namespace
        }
    
    def _check_kubectl(self) -> bool:
        """Check if kubectl is available"""
        try:
            subprocess.run(["kubectl", "version", "--client"], 
                         capture_output=True, timeout=5)
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def _run_kubectl(self, args: List[str]) -> Optional[Dict]:
        """Run kubectl command and return JSON output"""
        try:
            cmd = ["kubectl"] + args + ["-o", "json"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0 and result.stdout:
                return json.loads(result.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            pass
        
        return None
    
    def _check_privileged_containers(self) -> Optional[Dict]:
        """Check for privileged containers"""
        pods = self._run_kubectl(["get", "pods", "-n", self.namespace])
        if not pods:
            return None
        
        violations = []
        for pod in pods.get("items", []):
            pod_name = pod["metadata"]["name"]
            for container in pod["spec"].get("containers", []):
                security_context = container.get("securityContext", {})
                if security_context.get("privileged"):
                    violations.append({
                        "pod": pod_name,
                        "container": container["name"]
                    })
        
        if violations:
            return {
                "status": "FAIL",
                "violations": violations,
                "remediation": "Remove privileged: true from container securityContext"
            }
        
        return {"status": "PASS"}
    
    def _check_host_network(self) -> Optional[Dict]:
        """Check for hostNetwork usage"""
        pods = self._run_kubectl(["get", "pods", "-n", self.namespace])
        if not pods:
            return None
        
        violations = []
        for pod in pods.get("items", []):
            if pod["spec"].get("hostNetwork"):
                violations.append({"pod": pod["metadata"]["name"]})
        
        if violations:
            return {
                "status": "FAIL",
                "violations": violations,
                "remediation": "Remove hostNetwork: true from pod spec"
            }
        
        return {"status": "PASS"}
    
    def _check_host_pid_ipc(self) -> Optional[Dict]:
        """Check for hostPID/hostIPC usage"""
        pods = self._run_kubectl(["get", "pods", "-n", self.namespace])
        if not pods:
            return None
        
        violations = []
        for pod in pods.get("items", []):
            spec = pod["spec"]
            if spec.get("hostPID") or spec.get("hostIPC"):
                violations.append({
                    "pod": pod["metadata"]["name"],
                    "hostPID": spec.get("hostPID", False),
                    "hostIPC": spec.get("hostIPC", False)
                })
        
        if violations:
            return {
                "status": "FAIL",
                "violations": violations,
                "remediation": "Remove hostPID and hostIPC from pod spec"
            }
        
        return {"status": "PASS"}
    
    def _check_host_path(self) -> Optional[Dict]:
        """Check for hostPath volumes"""
        pods = self._run_kubectl(["get", "pods", "-n", self.namespace])
        if not pods:
            return None
        
        violations = []
        for pod in pods.get("items", []):
            for volume in pod["spec"].get("volumes", []):
                if "hostPath" in volume:
                    violations.append({
                        "pod": pod["metadata"]["name"],
                        "volume": volume["name"],
                        "path": volume["hostPath"]["path"]
                    })
        
        if violations:
            return {
                "status": "FAIL",
                "violations": violations,
                "remediation": "Use PersistentVolumes instead of hostPath"
            }
        
        return {"status": "PASS"}
    
    def _check_root_containers(self) -> Optional[Dict]:
        """Check for containers running as root"""
        pods = self._run_kubectl(["get", "pods", "-n", self.namespace])
        if not pods:
            return None
        
        violations = []
        for pod in pods.get("items", []):
            pod_name = pod["metadata"]["name"]
            for container in pod["spec"].get("containers", []):
                security_context = container.get("securityContext", {})
                run_as_user = security_context.get("runAsUser")
                run_as_non_root = security_context.get("runAsNonRoot")
                
                if run_as_user == 0 or (run_as_user is None and not run_as_non_root):
                    violations.append({
                        "pod": pod_name,
                        "container": container["name"]
                    })
        
        if violations:
            return {
                "status": "FAIL",
                "violations": violations,
                "remediation": "Set runAsNonRoot: true or runAsUser to non-zero UID"
            }
        
        return {"status": "PASS"}
    
    def _check_network_policies(self) -> Optional[Dict]:
        """Check for NetworkPolicy presence"""
        policies = self._run_kubectl(["get", "networkpolicies", "-n", self.namespace])
        
        if not policies or not policies.get("items"):
            return {
                "status": "FAIL",
                "remediation": "Create NetworkPolicies to restrict pod communication"
            }
        
        return {
            "status": "PASS",
            "policies_count": len(policies.get("items", []))
        }
    
    def _check_cluster_admin_binding(self) -> Optional[Dict]:
        """Check for excessive cluster-admin usage"""
        bindings = self._run_kubectl(["get", "clusterrolebindings"])
        if not bindings:
            return None
        
        violations = []
        for binding in bindings.get("items", []):
            if binding["roleRef"]["name"] == "cluster-admin":
                subjects = binding.get("subjects", [])
                if len(subjects) > 2:  # More than 2 is suspicious
                    violations.append({
                        "binding": binding["metadata"]["name"],
                        "subjects_count": len(subjects)
                    })
        
        if violations:
            return {
                "status": "WARNING",
                "violations": violations,
                "remediation": "Minimize cluster-admin role usage"
            }
        
        return {"status": "PASS"}
    
    def _check_default_sa_automount(self) -> Optional[Dict]:
        """Check default service account token automount"""
        sa_list = self._run_kubectl(["get", "serviceaccounts", "-n", self.namespace])
        if not sa_list:
            return None
        
        violations = []
        for sa in sa_list.get("items", []):
            if sa["metadata"]["name"] == "default":
                automount = sa.get("automountServiceAccountToken")
                if automount is None or automount:
                    violations.append({"namespace": self.namespace})
        
        if violations:
            return {
                "status": "FAIL",
                "violations": violations,
                "remediation": "Set automountServiceAccountToken: false for default SA"
            }
        
        return {"status": "PASS"}
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate structured security report"""
        critical = sum(1 for f in self.findings if f["severity"] == "CRITICAL" and f.get("status") == "FAIL")
        high = sum(1 for f in self.findings if f["severity"] == "HIGH" and f.get("status") == "FAIL")
        medium = sum(1 for f in self.findings if f["severity"] == "MEDIUM" and f.get("status") == "FAIL")
        
        passed = sum(1 for f in self.findings if f.get("status") == "PASS")
        failed = sum(1 for f in self.findings if f.get("status") == "FAIL")
        
        return {
            "scan_info": {
                "tool": "K8s Security Posture",
                "version": "1.0",
                "timestamp": datetime.now().isoformat(),
                "namespace": self.namespace,
                "category": "cloud"
            },
            "summary": {
                "total_checks": len(self.checks),
                "passed": passed,
                "failed": failed,
                "failures_by_severity": {
                    "critical": critical,
                    "high": high,
                    "medium": medium
                }
            },
            "findings": self.findings,
            "recommendations": self._generate_recommendations()
        }
    
    def _generate_recommendations(self) -> List[str]:
        """Generate prioritized recommendations"""
        recommendations = []
        
        for finding in sorted(self.findings, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(x["severity"], 3)):
            if finding.get("status") == "FAIL":
                recommendations.append(
                    f"[{finding['severity']}] {finding['description']}: {finding.get('remediation', 'Review manually')}"
                )
        
        return recommendations[:10]


def main():
    parser = argparse.ArgumentParser(description="Kubernetes security posture assessment")
    parser.add_argument("-n", "--namespace", default="default", help="Kubernetes namespace")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    assessor = K8sSecurityPosture(namespace=args.namespace, verbose=args.verbose)
    stats = assessor.assess()
    
    print(f"[+] Completed {stats.get('total_checks', 0)} security checks")
    print(f"[+] Found {stats.get('findings_count', 0)} findings")
    
    report = assessor.generate_report()
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report saved to {args.output}")
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
