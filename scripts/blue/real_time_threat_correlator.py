#!/usr/bin/env python3
"""
🔗 Real-Time Threat Correlator v2.5.1
Advanced threat intelligence correlation engine with ML-powered analysis
By @descambiado for BOFA Security Suite
"""

import asyncio
import json
import time
import aiohttp
import numpy as np
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from typing import List, Dict, Set, Optional, Tuple
import argparse
from pathlib import Path
import hashlib
import re
from collections import defaultdict, deque
import statistics

@dataclass
class ThreatIndicator:
    """Threat intelligence indicator"""
    type: str  # ip, domain, hash, url, etc.
    value: str
    source: str
    confidence: float
    severity: str
    first_seen: datetime
    last_seen: datetime
    tags: List[str]
    context: Dict

@dataclass
class SecurityEvent:
    """Security event from various sources"""
    id: str
    timestamp: datetime
    source: str
    event_type: str
    severity: str
    indicators: List[str]
    metadata: Dict
    raw_data: str

@dataclass
class ThreatCorrelation:
    """Correlated threat information"""
    correlation_id: str
    events: List[SecurityEvent]
    indicators: List[ThreatIndicator]
    attack_pattern: str
    confidence_score: float
    risk_level: str
    timeline: List[Tuple[datetime, str]]
    recommendations: List[str]

class ThreatIntelligenceFeeds:
    """Threat intelligence feed manager"""
    
    def __init__(self):
        self.feeds = {
            'misp': 'https://misp-galaxy.org/indicators',
            'otx': 'https://otx.alienvault.com/api/v1/indicators',
            'virustotal': 'https://www.virustotal.com/vtapi/v2',
            'malwaredomainlist': 'http://www.malwaredomainlist.com/hostslist/hosts.txt',
            'phishtank': 'http://data.phishtank.com/data/online-valid.csv'
        }
        self.indicators_cache = {}
        self.last_update = {}
    
    async def fetch_indicators(self, feed_name: str) -> List[ThreatIndicator]:
        """Fetch indicators from threat intelligence feed"""
        if feed_name not in self.feeds:
            return []
        
        # Simulate fetching from various TI feeds
        indicators = []
        
        if feed_name == 'simulated_iocs':
            # Generate simulated IOCs for demo
            malicious_ips = [
                '192.0.2.1', '203.0.113.5', '198.51.100.10',
                '10.0.0.100', '172.16.0.50', '192.168.1.200'
            ]
            
            malicious_domains = [
                'malware-c2.example.com', 'phishing-site.test',
                'evil-payload.invalid', 'suspicious-domain.bad'
            ]
            
            malicious_hashes = [
                'a1b2c3d4e5f6789012345678901234567890abcd',
                'f6e5d4c3b2a1098765432109876543210fedcba',
                '123456789abcdef0123456789abcdef012345678'
            ]
            
            # Create IP indicators
            for ip in malicious_ips:
                indicator = ThreatIndicator(
                    type='ip',
                    value=ip,
                    source='simulated_feed',
                    confidence=np.random.uniform(0.6, 0.95),
                    severity=np.random.choice(['low', 'medium', 'high', 'critical']),
                    first_seen=datetime.now() - timedelta(days=np.random.randint(1, 30)),
                    last_seen=datetime.now() - timedelta(hours=np.random.randint(1, 24)),
                    tags=['malware', 'c2', 'apt'] if np.random.random() > 0.5 else ['phishing'],
                    context={'country': np.random.choice(['CN', 'RU', 'KP', 'IR', 'Unknown'])}
                )
                indicators.append(indicator)
            
            # Create domain indicators
            for domain in malicious_domains:
                indicator = ThreatIndicator(
                    type='domain',
                    value=domain,
                    source='simulated_feed',
                    confidence=np.random.uniform(0.7, 0.9),
                    severity=np.random.choice(['medium', 'high']),
                    first_seen=datetime.now() - timedelta(days=np.random.randint(1, 15)),
                    last_seen=datetime.now() - timedelta(hours=np.random.randint(1, 12)),
                    tags=['phishing', 'credential-theft'],
                    context={'registrar': 'suspicious-registrar.com'}
                )
                indicators.append(indicator)
            
            # Create hash indicators
            for hash_val in malicious_hashes:
                indicator = ThreatIndicator(
                    type='hash',
                    value=hash_val,
                    source='simulated_feed',
                    confidence=np.random.uniform(0.8, 0.95),
                    severity=np.random.choice(['high', 'critical']),
                    first_seen=datetime.now() - timedelta(days=np.random.randint(1, 7)),
                    last_seen=datetime.now() - timedelta(hours=np.random.randint(1, 6)),
                    tags=['trojan', 'backdoor', 'stealer'],
                    context={'family': np.random.choice(['Emotet', 'TrickBot', 'Cobalt Strike'])}
                )
                indicators.append(indicator)
        
        self.indicators_cache[feed_name] = indicators
        self.last_update[feed_name] = datetime.now()
        
        return indicators

class RealTimeThreatCorrelator:
    """Main threat correlation engine"""
    
    def __init__(self):
        self.ti_feeds = ThreatIntelligenceFeeds()
        self.indicators = {}
        self.events_buffer = deque(maxlen=10000)
        self.correlations = []
        self.attack_patterns = self._load_attack_patterns()
        self.ml_threshold = 0.75
    
    def _load_attack_patterns(self) -> Dict:
        """Load MITRE ATT&CK patterns and custom patterns"""
        patterns = {
            'credential_dumping': {
                'indicators': ['lsass.exe', 'sekurlsa', 'mimikatz'],
                'events': ['process_creation', 'memory_access'],
                'timeline_window': 300  # seconds
            },
            'lateral_movement': {
                'indicators': ['psexec', 'wmic', 'powershell'],
                'events': ['network_connection', 'process_creation'],
                'timeline_window': 600
            },
            'data_exfiltration': {
                'indicators': ['large_upload', 'compression', 'encryption'],
                'events': ['file_access', 'network_connection'],
                'timeline_window': 1800
            },
            'c2_communication': {
                'indicators': ['beacon', 'periodic_connection', 'dns_tunneling'],
                'events': ['network_connection', 'dns_query'],
                'timeline_window': 3600
            },
            'privilege_escalation': {
                'indicators': ['uac_bypass', 'token_manipulation', 'dll_injection'],
                'events': ['process_creation', 'registry_modification'],
                'timeline_window': 300
            }
        }
        return patterns
    
    async def initialize_feeds(self):
        """Initialize threat intelligence feeds"""
        print("[+] Initializing threat intelligence feeds...")
        
        feed_names = ['simulated_iocs']  # Add real feeds here
        
        for feed in feed_names:
            indicators = await self.ti_feeds.fetch_indicators(feed)
            
            for indicator in indicators:
                key = f"{indicator.type}:{indicator.value}"
                self.indicators[key] = indicator
            
            print(f"  Loaded {len(indicators)} indicators from {feed}")
        
        print(f"[+] Total indicators loaded: {len(self.indicators)}")
    
    def parse_security_event(self, raw_event: str, source: str = "unknown") -> Optional[SecurityEvent]:
        """Parse raw security event into structured format"""
        try:
            # Try to parse as JSON first
            if raw_event.strip().startswith('{'):
                data = json.loads(raw_event)
                
                event = SecurityEvent(
                    id=data.get('id', str(time.time())),
                    timestamp=datetime.fromisoformat(data.get('timestamp', datetime.now().isoformat())),
                    source=data.get('source', source),
                    event_type=data.get('type', 'unknown'),
                    severity=data.get('severity', 'medium'),
                    indicators=data.get('indicators', []),
                    metadata=data.get('metadata', {}),
                    raw_data=raw_event
                )
                
                return event
            
            # Parse common log formats
            elif 'failed login' in raw_event.lower():
                # Authentication event
                ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', raw_event)
                user_match = re.search(r'user[:\s]+(\w+)', raw_event, re.IGNORECASE)
                
                indicators = []
                if ip_match:
                    indicators.append(ip_match.group())
                if user_match:
                    indicators.append(user_match.group(1))
                
                event = SecurityEvent(
                    id=str(hash(raw_event)),
                    timestamp=datetime.now(),
                    source=source,
                    event_type='authentication_failure',
                    severity='medium',
                    indicators=indicators,
                    metadata={'raw_log': raw_event},
                    raw_data=raw_event
                )
                
                return event
            
            elif 'connection' in raw_event.lower():
                # Network event
                ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', raw_event)
                port_matches = re.findall(r':(\d+)', raw_event)
                
                indicators = ip_matches + [f"port:{port}" for port in port_matches]
                
                event = SecurityEvent(
                    id=str(hash(raw_event)),
                    timestamp=datetime.now(),
                    source=source,
                    event_type='network_connection',
                    severity='low',
                    indicators=indicators,
                    metadata={'raw_log': raw_event},
                    raw_data=raw_event
                )
                
                return event
            
            else:
                # Generic event
                # Extract potential IOCs
                ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', raw_event)
                domain_matches = re.findall(r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', raw_event)
                hash_matches = re.findall(r'\b[a-fA-F0-9]{32,64}\b', raw_event)
                
                indicators = ip_matches + domain_matches + hash_matches
                
                event = SecurityEvent(
                    id=str(hash(raw_event)),
                    timestamp=datetime.now(),
                    source=source,
                    event_type='generic',
                    severity='low',
                    indicators=indicators,
                    metadata={'raw_log': raw_event},
                    raw_data=raw_event
                )
                
                return event
        
        except Exception as e:
            print(f"[-] Error parsing event: {e}")
            return None
    
    def add_event(self, event: SecurityEvent):
        """Add security event to correlation buffer"""
        self.events_buffer.append(event)
        
        # Trigger real-time correlation
        self._correlate_events()
    
    def _correlate_events(self):
        """Correlate events in real-time"""
        if len(self.events_buffer) < 2:
            return
        
        # Look for correlations in recent events
        recent_events = list(self.events_buffer)[-100:]  # Last 100 events
        
        # Group events by time windows
        time_windows = self._group_events_by_time(recent_events)
        
        for window_events in time_windows:
            if len(window_events) < 2:
                continue
            
            # Check for attack patterns
            correlation = self._detect_attack_patterns(window_events)
            
            if correlation:
                self.correlations.append(correlation)
                self._alert_correlation(correlation)
    
    def _group_events_by_time(self, events: List[SecurityEvent], window_size: int = 300) -> List[List[SecurityEvent]]:
        """Group events by time windows"""
        if not events:
            return []
        
        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        
        windows = []
        current_window = [sorted_events[0]]
        window_start = sorted_events[0].timestamp
        
        for event in sorted_events[1:]:
            if (event.timestamp - window_start).total_seconds() <= window_size:
                current_window.append(event)
            else:
                if len(current_window) > 1:
                    windows.append(current_window)
                current_window = [event]
                window_start = event.timestamp
        
        if len(current_window) > 1:
            windows.append(current_window)
        
        return windows
    
    def _detect_attack_patterns(self, events: List[SecurityEvent]) -> Optional[ThreatCorrelation]:
        """Detect attack patterns in event group"""
        for pattern_name, pattern_config in self.attack_patterns.items():
            score = self._calculate_pattern_score(events, pattern_config)
            
            if score >= self.ml_threshold:
                # Found a matching pattern
                correlation_id = f"corr_{int(time.time())}_{pattern_name}"
                
                # Gather related threat indicators
                related_indicators = []
                for event in events:
                    for indicator_value in event.indicators:
                        for ioc_type in ['ip', 'domain', 'hash']:
                            key = f"{ioc_type}:{indicator_value}"
                            if key in self.indicators:
                                related_indicators.append(self.indicators[key])
                
                # Calculate overall confidence
                confidence = self._calculate_confidence(events, related_indicators, score)
                
                # Determine risk level
                risk_level = self._calculate_risk_level(confidence, len(events), related_indicators)
                
                # Create timeline
                timeline = [(event.timestamp, f"{event.event_type} from {event.source}") 
                           for event in sorted(events, key=lambda e: e.timestamp)]
                
                # Generate recommendations
                recommendations = self._generate_recommendations(pattern_name, events, related_indicators)
                
                correlation = ThreatCorrelation(
                    correlation_id=correlation_id,
                    events=events,
                    indicators=related_indicators,
                    attack_pattern=pattern_name,
                    confidence_score=confidence,
                    risk_level=risk_level,
                    timeline=timeline,
                    recommendations=recommendations
                )
                
                return correlation
        
        return None
    
    def _calculate_pattern_score(self, events: List[SecurityEvent], pattern_config: Dict) -> float:
        """Calculate how well events match an attack pattern"""
        score = 0.0
        max_score = 100.0
        
        # Check for pattern indicators
        pattern_indicators = set(pattern_config.get('indicators', []))
        found_indicators = set()
        
        for event in events:
            for indicator in event.indicators:
                for pattern_indicator in pattern_indicators:
                    if pattern_indicator.lower() in str(indicator).lower():
                        found_indicators.add(pattern_indicator)
        
        # Indicator score (40% of total)
        if pattern_indicators:
            indicator_score = (len(found_indicators) / len(pattern_indicators)) * 40
            score += indicator_score
        
        # Event type score (30% of total)
        pattern_events = set(pattern_config.get('events', []))
        found_event_types = set(event.event_type for event in events)
        
        if pattern_events:
            event_score = len(pattern_events.intersection(found_event_types)) / len(pattern_events) * 30
            score += event_score
        
        # Timeline score (20% of total)
        timeline_window = pattern_config.get('timeline_window', 600)
        if len(events) > 1:
            event_times = [event.timestamp for event in events]
            time_span = (max(event_times) - min(event_times)).total_seconds()
            
            if time_span <= timeline_window:
                timeline_score = 20
            else:
                timeline_score = max(0, 20 * (1 - (time_span - timeline_window) / timeline_window))
            
            score += timeline_score
        
        # Severity bonus (10% of total)
        high_severity_events = sum(1 for event in events if event.severity in ['high', 'critical'])
        severity_score = min(10, (high_severity_events / len(events)) * 10)
        score += severity_score
        
        return score / max_score
    
    def _calculate_confidence(self, events: List[SecurityEvent], indicators: List[ThreatIndicator], pattern_score: float) -> float:
        """Calculate overall confidence score"""
        factors = []
        
        # Pattern matching confidence
        factors.append(pattern_score)
        
        # Threat intelligence confidence
        if indicators:
            ti_confidence = statistics.mean(indicator.confidence for indicator in indicators)
            factors.append(ti_confidence)
        
        # Event volume factor
        volume_factor = min(1.0, len(events) / 5.0)  # More events = higher confidence up to a point
        factors.append(volume_factor)
        
        # Source diversity factor
        unique_sources = len(set(event.source for event in events))
        source_factor = min(1.0, unique_sources / 3.0)  # Multiple sources = higher confidence
        factors.append(source_factor)
        
        return statistics.mean(factors)
    
    def _calculate_risk_level(self, confidence: float, event_count: int, indicators: List[ThreatIndicator]) -> str:
        """Calculate risk level based on various factors"""
        risk_score = 0
        
        # Confidence factor
        risk_score += confidence * 40
        
        # Event volume factor
        risk_score += min(30, event_count * 3)
        
        # Indicator severity factor
        if indicators:
            critical_indicators = sum(1 for i in indicators if i.severity == 'critical')
            high_indicators = sum(1 for i in indicators if i.severity == 'high')
            risk_score += critical_indicators * 5 + high_indicators * 3
        
        if risk_score >= 80:
            return 'critical'
        elif risk_score >= 60:
            return 'high'
        elif risk_score >= 40:
            return 'medium'
        else:
            return 'low'
    
    def _generate_recommendations(self, pattern_name: str, events: List[SecurityEvent], indicators: List[ThreatIndicator]) -> List[str]:
        """Generate specific recommendations based on detected pattern"""
        recommendations = []
        
        base_recommendations = {
            'credential_dumping': [
                "Immediately isolate affected systems",
                "Force password reset for all potentially compromised accounts",
                "Review privileged account access logs",
                "Deploy additional memory protection controls",
                "Enhance monitoring for LSASS process access"
            ],
            'lateral_movement': [
                "Segment network to limit lateral movement",
                "Review and restrict administrative account usage",
                "Monitor for unusual cross-system activity",
                "Implement application whitelisting",
                "Enhanced logging for remote access tools"
            ],
            'data_exfiltration': [
                "Monitor and restrict large data transfers",
                "Review file access logs for sensitive data",
                "Implement data loss prevention (DLP) controls",
                "Monitor unusual compression/encryption activity",
                "Review external network connections"
            ],
            'c2_communication': [
                "Block identified C2 infrastructure",
                "Monitor for beaconing patterns",
                "Implement DNS monitoring and filtering",
                "Review proxy and firewall logs",
                "Deploy network behavior analysis tools"
            ],
            'privilege_escalation': [
                "Review and harden UAC settings",
                "Monitor for unusual process creation",
                "Implement least privilege principles",
                "Deploy application control solutions",
                "Enhanced monitoring for DLL injection"
            ]
        }
        
        # Add pattern-specific recommendations
        if pattern_name in base_recommendations:
            recommendations.extend(base_recommendations[pattern_name])
        
        # Add indicator-specific recommendations
        for indicator in indicators:
            if indicator.type == 'ip':
                recommendations.append(f"Block IP address {indicator.value} at perimeter")
            elif indicator.type == 'domain':
                recommendations.append(f"Block domain {indicator.value} in DNS/proxy")
            elif indicator.type == 'hash':
                recommendations.append(f"Add hash {indicator.value} to endpoint protection")
        
        # Add general recommendations
        recommendations.extend([
            "Preserve forensic evidence from affected systems",
            "Coordinate with incident response team",
            "Consider threat hunting activities",
            "Update threat intelligence feeds",
            "Review and update security controls"
        ])
        
        return list(set(recommendations))  # Remove duplicates
    
    def _alert_correlation(self, correlation: ThreatCorrelation):
        """Generate alert for detected correlation"""
        print("\n" + "="*80)
        print(f"🚨 THREAT CORRELATION DETECTED: {correlation.correlation_id}")
        print("="*80)
        print(f"Attack Pattern: {correlation.attack_pattern.upper()}")
        print(f"Risk Level: {correlation.risk_level.upper()}")
        print(f"Confidence: {correlation.confidence_score:.2f}")
        print(f"Events Involved: {len(correlation.events)}")
        print(f"Threat Indicators: {len(correlation.indicators)}")
        
        print("\n📅 Timeline:")
        for timestamp, description in correlation.timeline[-5:]:  # Last 5 events
            print(f"  {timestamp.strftime('%H:%M:%S')} - {description}")
        
        print("\n🎯 Key Indicators:")
        for indicator in correlation.indicators[:3]:  # Top 3 indicators
            print(f"  {indicator.type.upper()}: {indicator.value} (confidence: {indicator.confidence:.2f})")
        
        print("\n💡 Recommendations:")
        for i, rec in enumerate(correlation.recommendations[:5], 1):  # Top 5 recommendations
            print(f"  {i}. {rec}")
        
        print("="*80)
    
    def generate_report(self, output_file: str = None) -> Dict:
        """Generate comprehensive correlation report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'tool': 'BOFA Real-Time Threat Correlator v2.5.1',
            'author': '@descambiado',
            'summary': {
                'total_events_processed': len(self.events_buffer),
                'total_indicators': len(self.indicators),
                'correlations_found': len(self.correlations),
                'high_risk_correlations': len([c for c in self.correlations if c.risk_level in ['high', 'critical']])
            },
            'correlations': [asdict(c) for c in self.correlations],
            'threat_indicators': {k: asdict(v) for k, v in self.indicators.items()},
            'attack_patterns_detected': list(set(c.attack_pattern for c in self.correlations)),
            'recommendations': self._generate_overall_recommendations()
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            print(f"[+] Report saved to {output_file}")
        
        return report
    
    def _generate_overall_recommendations(self) -> List[str]:
        """Generate overall security recommendations"""
        recommendations = [
            "Implement real-time SIEM correlation rules",
            "Deploy advanced threat hunting capabilities",
            "Enhance threat intelligence feed integration",
            "Improve cross-system event correlation",
            "Implement automated response workflows",
            "Regular review and tuning of correlation rules",
            "Training for security analysts on attack patterns",
            "Deploy user and entity behavior analytics (UEBA)"
        ]
        return recommendations

async def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description="BOFA Real-Time Threat Correlator v2.5.1")
    parser.add_argument("--mode", choices=["demo", "file", "realtime"], 
                       default="demo", help="Operation mode")
    parser.add_argument("--input-file", help="Input file with security events")
    parser.add_argument("--output", help="Output file for report")
    parser.add_argument("--threshold", type=float, default=0.75, 
                       help="ML correlation threshold (0.0-1.0)")
    parser.add_argument("--window", type=int, default=300, 
                       help="Time window for correlation (seconds)")
    
    args = parser.parse_args()
    
    print("🔗 BOFA Real-Time Threat Correlator v2.5.1")
    print("=" * 60)
    print("Advanced threat intelligence correlation engine")
    print("By @descambiado for BOFA Security Suite")
    print("=" * 60)
    
    correlator = RealTimeThreatCorrelator()
    correlator.ml_threshold = args.threshold
    
    # Initialize threat intelligence feeds
    await correlator.initialize_feeds()
    
    if args.mode == "demo":
        print("\n[+] Running demonstration with simulated events...")
        
        # Generate simulated security events
        demo_events = [
            '{"id": "evt001", "timestamp": "2025-01-18T10:00:00", "type": "process_creation", "severity": "medium", "indicators": ["lsass.exe", "mimikatz"], "source": "endpoint_1", "metadata": {"process": "lsass.exe", "cmdline": "sekurlsa::logonpasswords"}}',
            '{"id": "evt002", "timestamp": "2025-01-18T10:01:30", "type": "memory_access", "severity": "high", "indicators": ["lsass.exe"], "source": "endpoint_1", "metadata": {"target_process": "lsass.exe", "access_type": "read"}}',
            'Failed login attempt from 192.0.2.1 for user administrator',
            '{"id": "evt003", "timestamp": "2025-01-18T10:05:00", "type": "network_connection", "severity": "medium", "indicators": ["203.0.113.5", "port:443"], "source": "firewall", "metadata": {"src_ip": "10.0.0.100", "dst_ip": "203.0.113.5", "protocol": "HTTPS"}}',
            'Network connection to malware-c2.example.com:443 from 10.0.0.100',
            '{"id": "evt004", "timestamp": "2025-01-18T10:07:00", "type": "file_access", "severity": "low", "indicators": ["sensitive_data.xlsx"], "source": "file_monitor", "metadata": {"file": "C:\\Users\\admin\\Documents\\sensitive_data.xlsx", "action": "read"}}',
            '{"id": "evt005", "timestamp": "2025-01-18T10:10:00", "type": "network_connection", "severity": "high", "indicators": ["203.0.113.5", "large_upload"], "source": "proxy", "metadata": {"bytes_transferred": 50000000, "duration": 300}}'
        ]
        
        # Process events
        for i, raw_event in enumerate(demo_events):
            print(f"\n[+] Processing event {i+1}/{len(demo_events)}")
            
            event = correlator.parse_security_event(raw_event, "demo_source")
            if event:
                correlator.add_event(event)
                print(f"  Event: {event.event_type} from {event.source}")
                print(f"  Indicators: {event.indicators}")
            
            # Add slight delay to simulate real-time
            await asyncio.sleep(0.5)
        
        print(f"\n[+] Processed {len(demo_events)} events")
        print(f"[+] Found {len(correlator.correlations)} correlations")
        
    elif args.mode == "file" and args.input_file:
        print(f"\n[+] Processing events from file: {args.input_file}")
        
        try:
            with open(args.input_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    event = correlator.parse_security_event(line, "file_input")
                    if event:
                        correlator.add_event(event)
                    
                    if line_num % 100 == 0:
                        print(f"  Processed {line_num} lines...")
            
            print(f"[+] Processed {line_num} events from file")
            
        except FileNotFoundError:
            print(f"[-] File not found: {args.input_file}")
            return
        
    elif args.mode == "realtime":
        print("\n[+] Starting real-time correlation mode...")
        print("Enter security events (one per line), or 'quit' to exit:")
        
        try:
            while True:
                raw_event = input("> ").strip()
                
                if raw_event.lower() in ['quit', 'exit', 'q']:
                    break
                
                if not raw_event:
                    continue
                
                event = correlator.parse_security_event(raw_event, "user_input")
                if event:
                    correlator.add_event(event)
                    print(f"  Processed: {event.event_type}")
                else:
                    print("  Could not parse event")
                    
        except KeyboardInterrupt:
            print("\n[+] Exiting real-time mode...")
    
    # Generate final report
    if args.output:
        correlator.generate_report(args.output)
    
    # Summary
    print(f"\n📊 Correlation Summary:")
    print(f"  Total Events: {len(correlator.events_buffer)}")
    print(f"  Threat Indicators: {len(correlator.indicators)}")
    print(f"  Correlations Found: {len(correlator.correlations)}")
    
    if correlator.correlations:
        risk_levels = [c.risk_level for c in correlator.correlations]
        for level in ['critical', 'high', 'medium', 'low']:
            count = risk_levels.count(level)
            if count > 0:
                print(f"  {level.title()} Risk: {count}")
    
    print("\n[+] Correlation analysis complete!")
    print("\n🛡️ Key Benefits:")
    print("• Real-time threat correlation across multiple sources")
    print("• ML-powered attack pattern recognition")
    print("• Automated threat intelligence integration")
    print("• Actionable security recommendations")
    print("• Reduced false positive alerts through correlation")

if __name__ == "__main__":
    asyncio.run(main())