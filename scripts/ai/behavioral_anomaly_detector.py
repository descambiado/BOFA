#!/usr/bin/env python3
"""
Behavioral Anomaly Detector - BOFA v2.5.1
Detects behavioral anomalies using ML techniques
Author: @descambiado
"""

import argparse
import json
from datetime import datetime
from typing import Dict, Any, List
import random
import math


class BehavioralAnomalyDetector:
    """ML-based behavioral anomaly detection"""
    
    def __init__(self, sensitivity: float = 0.7, verbose: bool = False):
        self.sensitivity = sensitivity
        self.verbose = verbose
        self.anomalies = []
        self.baseline_profile = {}
    
    def analyze_logs(self, log_file: str) -> Dict[str, Any]:
        """Analyze logs for behavioral anomalies"""
        try:
            with open(log_file, 'r') as f:
                logs = [json.loads(line) for line in f if line.strip()]
            
            # Build baseline profile
            self.baseline_profile = self._build_baseline(logs)
            
            # Detect anomalies
            for log_entry in logs:
                anomaly = self._detect_anomaly(log_entry)
                if anomaly:
                    self.anomalies.append(anomaly)
            
            return {
                "logs_analyzed": len(logs),
                "anomalies_detected": len(self.anomalies)
            }
        
        except FileNotFoundError:
            return self._generate_sample_analysis()
        except json.JSONDecodeError:
            return {"error": "Invalid log format"}
    
    def _build_baseline(self, logs: List[Dict]) -> Dict[str, Any]:
        """Build baseline behavioral profile"""
        baseline = {
            "avg_login_time": self._calculate_avg_time(logs, "login_time"),
            "typical_ips": self._extract_frequent_ips(logs),
            "avg_session_duration": self._calculate_avg_duration(logs),
            "typical_actions": self._extract_action_patterns(logs)
        }
        return baseline
    
    def _calculate_avg_time(self, logs: List[Dict], field: str) -> int:
        """Calculate average time (hour of day)"""
        times = [int(log.get(field, "12:00").split(":")[0]) for log in logs if log.get(field)]
        return sum(times) // len(times) if times else 12
    
    def _extract_frequent_ips(self, logs: List[Dict]) -> List[str]:
        """Extract frequent IP addresses"""
        ips = [log.get("ip") for log in logs if log.get("ip")]
        ip_counts = {}
        for ip in ips:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        # Return IPs that appear in >10% of logs
        threshold = len(logs) * 0.1
        return [ip for ip, count in ip_counts.items() if count >= threshold]
    
    def _calculate_avg_duration(self, logs: List[Dict]) -> float:
        """Calculate average session duration"""
        durations = [log.get("session_duration", 30) for log in logs if log.get("session_duration")]
        return sum(durations) / len(durations) if durations else 30.0
    
    def _extract_action_patterns(self, logs: List[Dict]) -> Dict[str, int]:
        """Extract common action patterns"""
        actions = {}
        for log in logs:
            action = log.get("action", "unknown")
            actions[action] = actions.get(action, 0) + 1
        return actions
    
    def _detect_anomaly(self, log_entry: Dict) -> Dict[str, Any]:
        """Detect anomalies in single log entry"""
        anomaly_score = 0
        anomaly_reasons = []
        
        # Unusual time
        login_time = log_entry.get("login_time", "12:00")
        hour = int(login_time.split(":")[0])
        baseline_hour = self.baseline_profile.get("avg_login_time", 12)
        
        time_diff = abs(hour - baseline_hour)
        if time_diff > 6:
            anomaly_score += 30
            anomaly_reasons.append(f"Unusual login time: {login_time} (baseline: {baseline_hour}:00)")
        
        # Unusual IP
        ip = log_entry.get("ip", "")
        if ip and ip not in self.baseline_profile.get("typical_ips", []):
            anomaly_score += 25
            anomaly_reasons.append(f"New/unusual IP address: {ip}")
        
        # Unusual session duration
        duration = log_entry.get("session_duration", 30)
        baseline_duration = self.baseline_profile.get("avg_session_duration", 30)
        
        if duration > baseline_duration * 3:
            anomaly_score += 20
            anomaly_reasons.append(f"Unusually long session: {duration} min (baseline: {baseline_duration:.1f})")
        
        # Unusual action
        action = log_entry.get("action", "")
        typical_actions = self.baseline_profile.get("typical_actions", {})
        if action not in typical_actions or typical_actions.get(action, 0) < 2:
            anomaly_score += 15
            anomaly_reasons.append(f"Unusual action: {action}")
        
        # Failed attempts
        failed_attempts = log_entry.get("failed_attempts", 0)
        if failed_attempts > 3:
            anomaly_score += 40
            anomaly_reasons.append(f"Multiple failed attempts: {failed_attempts}")
        
        # Threshold check
        threshold = (1 - self.sensitivity) * 100
        if anomaly_score > threshold:
            return {
                "timestamp": log_entry.get("timestamp", datetime.now().isoformat()),
                "username": log_entry.get("username", "unknown"),
                "anomaly_score": anomaly_score,
                "severity": self._get_severity(anomaly_score),
                "reasons": anomaly_reasons,
                "details": log_entry
            }
        
        return None
    
    def _get_severity(self, score: int) -> str:
        """Determine severity based on anomaly score"""
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _generate_sample_analysis(self) -> Dict[str, Any]:
        """Generate sample analysis"""
        sample_logs = [
            {"username": "user1", "login_time": "14:30", "ip": "192.168.1.100", "action": "login", "session_duration": 45, "failed_attempts": 0},
            {"username": "user2", "login_time": "03:15", "ip": "10.0.0.50", "action": "admin_access", "session_duration": 180, "failed_attempts": 5},
            {"username": "user3", "login_time": "10:00", "ip": "192.168.1.101", "action": "login", "session_duration": 30, "failed_attempts": 0},
        ]
        
        self.baseline_profile = self._build_baseline(sample_logs)
        
        for log in sample_logs:
            anomaly = self._detect_anomaly(log)
            if anomaly:
                self.anomalies.append(anomaly)
        
        return {
            "logs_analyzed": len(sample_logs),
            "anomalies_detected": len(self.anomalies)
        }
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate anomaly detection report"""
        critical = sum(1 for a in self.anomalies if a["severity"] == "CRITICAL")
        high = sum(1 for a in self.anomalies if a["severity"] == "HIGH")
        
        return {
            "scan_info": {
                "tool": "Behavioral Anomaly Detector",
                "version": "1.0",
                "timestamp": datetime.now().isoformat(),
                "sensitivity": self.sensitivity,
                "category": "ai"
            },
            "summary": {
                "total_anomalies": len(self.anomalies),
                "anomalies_by_severity": {
                    "critical": critical,
                    "high": high,
                    "medium": sum(1 for a in self.anomalies if a["severity"] == "MEDIUM"),
                    "low": sum(1 for a in self.anomalies if a["severity"] == "LOW")
                }
            },
            "baseline_profile": self.baseline_profile,
            "anomalies": sorted(self.anomalies, key=lambda x: x["anomaly_score"], reverse=True),
            "recommendations": self._generate_recommendations()
        }
    
    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations"""
        recommendations = []
        
        critical_anomalies = [a for a in self.anomalies if a["severity"] == "CRITICAL"]
        if critical_anomalies:
            recommendations.append(f"Investigate {len(critical_anomalies)} critical anomalies immediately")
        
        unusual_ips = sum(1 for a in self.anomalies if any("IP address" in r for r in a["reasons"]))
        if unusual_ips:
            recommendations.append(f"Review {unusual_ips} logins from unusual IP addresses")
        
        return recommendations


def main():
    parser = argparse.ArgumentParser(description="Behavioral anomaly detection")
    parser.add_argument("-f", "--file", help="Log file (JSONL format)")
    parser.add_argument("-s", "--sensitivity", type=float, default=0.7, help="Sensitivity (0.0-1.0)")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("-v", "--verbose", action="store_true")
    
    args = parser.parse_args()
    
    detector = BehavioralAnomalyDetector(sensitivity=args.sensitivity, verbose=args.verbose)
    stats = detector.analyze_logs(args.file or "sample.log")
    
    print(f"[+] Analyzed {stats.get('logs_analyzed', 0)} log entries")
    print(f"[!] Detected {stats.get('anomalies_detected', 0)} anomalies")
    
    report = detector.generate_report()
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report saved to {args.output}")
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
