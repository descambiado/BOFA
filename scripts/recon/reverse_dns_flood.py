
#!/usr/bin/env python3
"""
Reverse DNS Flood - Passive Defense Testing Tool
Developed by @descambiado for BOFA Suite

Revolutionary tool for testing firewall and WAF response patterns
using controlled reverse DNS queries without causing harm.
"""

import os
import sys
import time
import random
import socket
import threading
import argparse
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import statistics

class ReverseDNSFlood:
    def __init__(self):
        self.version = "1.0.0"
        self.author = "@descambiado"
        self.results = {
            'queries_sent': 0,
            'responses_received': 0,
            'timeouts': 0,
            'errors': 0,
            'response_times': [],
            'detected_patterns': [],
            'security_indicators': []
        }
        self.running = False
        
    def print_banner(self):
        print("\n" + "="*70)
        print("🧠 REVERSE DNS FLOOD - Passive Defense Testing")
        print("="*70)
        print(f"Version: {self.version} | Author: {self.author}")
        print("Controlled reverse DNS testing for security assessment")
        print("="*70)
        
    def log_activity(self, activity):
        """Log activities with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {activity}")
        
    def generate_ip_ranges(self, target_network, count=1000):
        """Generate random IP addresses from specified ranges"""
        self.log_activity(f"🎯 Generating {count} IP addresses from {target_network}")
        
        try:
            network = ipaddress.ip_network(target_network, strict=False)
            
            # For large networks, sample randomly
            if network.num_addresses > count:
                ips = []
                for _ in range(count):
                    # Generate random IP within network
                    network_int = int(network.network_address)
                    random_offset = random.randint(0, network.num_addresses - 1)
                    random_ip = ipaddress.ip_address(network_int + random_offset)
                    ips.append(str(random_ip))
                return ips
            else:
                # Return all IPs in small networks
                return [str(ip) for ip in network.hosts()]
                
        except Exception as e:
            self.log_activity(f"❌ Error generating IPs: {e}")
            return []
            
    def generate_safe_ips(self, count=1000):
        """Generate safe IP ranges for testing"""
        self.log_activity(f"🛡️  Generating {count} safe test IPs")
        
        # Use safe, non-routable IP ranges
        safe_ranges = [
            "10.0.0.0/8",       # Private range
            "172.16.0.0/12",    # Private range
            "192.168.0.0/16",   # Private range
            "127.0.0.0/8",      # Loopback
            "169.254.0.0/16",   # Link-local
        ]
        
        all_ips = []
        ips_per_range = count // len(safe_ranges)
        
        for range_str in safe_ranges:
            range_ips = self.generate_ip_ranges(range_str, ips_per_range)
            all_ips.extend(range_ips)
            
        return all_ips[:count]
        
    def perform_reverse_dns_query(self, ip_address, timeout=2):
        """Perform a single reverse DNS query"""
        start_time = time.time()
        
        try:
            # Attempt reverse DNS lookup
            hostname = socket.gethostbyaddr(ip_address)
            end_time = time.time()
            
            response_time = (end_time - start_time) * 1000  # Convert to milliseconds
            
            return {
                'ip': ip_address,
                'hostname': hostname[0] if hostname else None,
                'response_time': response_time,
                'status': 'success',
                'timestamp': datetime.now().isoformat()
            }
            
        except socket.timeout:
            return {
                'ip': ip_address,
                'hostname': None,
                'response_time': timeout * 1000,
                'status': 'timeout',
                'timestamp': datetime.now().isoformat()
            }
            
        except socket.herror:
            # Host not found
            end_time = time.time()
            response_time = (end_time - start_time) * 1000
            
            return {
                'ip': ip_address,
                'hostname': None,
                'response_time': response_time,
                'status': 'no_host',
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            end_time = time.time()
            response_time = (end_time - start_time) * 1000
            
            return {
                'ip': ip_address,
                'hostname': None,
                'response_time': response_time,
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
            
    def analyze_response_patterns(self, responses):
        """Analyze response patterns for security indicators"""
        self.log_activity("🔍 Analyzing response patterns for security indicators")
        
        analysis = {
            'total_queries': len(responses),
            'successful_responses': 0,
            'timeouts': 0,
            'errors': 0,
            'response_times': [],
            'detected_security_measures': [],
            'statistical_analysis': {}
        }
        
        for response in responses:
            if response['status'] == 'success':
                analysis['successful_responses'] += 1
                analysis['response_times'].append(response['response_time'])
            elif response['status'] == 'timeout':
                analysis['timeouts'] += 1
            else:
                analysis['errors'] += 1
                
        # Statistical analysis of response times
        if analysis['response_times']:
            times = analysis['response_times']
            analysis['statistical_analysis'] = {
                'mean_response_time': statistics.mean(times),
                'median_response_time': statistics.median(times),
                'min_response_time': min(times),
                'max_response_time': max(times),
                'std_deviation': statistics.stdev(times) if len(times) > 1 else 0
            }
            
            # Detect potential security measures
            mean_time = analysis['statistical_analysis']['mean_response_time']
            std_dev = analysis['statistical_analysis']['std_deviation']
            
            # High timeout rate might indicate rate limiting
            timeout_rate = analysis['timeouts'] / analysis['total_queries']
            if timeout_rate > 0.3:  # More than 30% timeouts
                analysis['detected_security_measures'].append({
                    'measure': 'Possible Rate Limiting',
                    'confidence': 'high' if timeout_rate > 0.5 else 'medium',
                    'description': f'High timeout rate: {timeout_rate:.2%}'
                })
                
            # Consistent response times might indicate load balancing/proxy
            if std_dev < 10 and mean_time > 100:  # Low variance, high response time
                analysis['detected_security_measures'].append({
                    'measure': 'Possible Load Balancer/Proxy',
                    'confidence': 'medium',
                    'description': f'Consistent response times (std dev: {std_dev:.2f}ms)'
                })
                
            # Very fast responses might indicate caching
            if mean_time < 50:
                analysis['detected_security_measures'].append({
                    'measure': 'Possible DNS Caching',
                    'confidence': 'medium',
                    'description': f'Fast average response time: {mean_time:.2f}ms'
                })
                
        return analysis
        
    def detect_firewall_behavior(self, responses):
        """Detect potential firewall or WAF behavior"""
        self.log_activity("🛡️  Analyzing for firewall/WAF behavior patterns")
        
        firewall_indicators = []
        
        # Group responses by time windows
        time_windows = {}
        for response in responses:
            timestamp = datetime.fromisoformat(response['timestamp'])
            window_key = timestamp.strftime("%H:%M")  # Group by minute
            
            if window_key not in time_windows:
                time_windows[window_key] = []
            time_windows[window_key].append(response)
            
        # Analyze patterns in time windows
        for window, window_responses in time_windows.items():
            window_timeouts = sum(1 for r in window_responses if r['status'] == 'timeout')
            window_errors = sum(1 for r in window_responses if r['status'] == 'error')
            
            total_window_queries = len(window_responses)
            if total_window_queries > 10:  # Only analyze significant windows
                
                # Sudden increase in timeouts/errors might indicate blocking
                timeout_rate = window_timeouts / total_window_queries
                error_rate = window_errors / total_window_queries
                
                if timeout_rate > 0.8 or error_rate > 0.8:
                    firewall_indicators.append({
                        'type': 'Potential Blocking Detected',
                        'time_window': window,
                        'timeout_rate': f"{timeout_rate:.2%}",
                        'error_rate': f"{error_rate:.2%}",
                        'confidence': 'high'
                    })
                    
        return firewall_indicators
        
    def run_controlled_flood(self, ip_list, threads=10, delay=0.1, duration=None):
        """Run controlled reverse DNS flood test"""
        self.log_activity(f"🚀 Starting controlled flood test")
        self.log_activity(f"   Targets: {len(ip_list)} IPs")
        self.log_activity(f"   Threads: {threads}")
        self.log_activity(f"   Delay: {delay}s between requests")
        if duration:
            self.log_activity(f"   Duration: {duration} seconds")
            
        self.running = True
        responses = []
        start_time = time.time()
        
        def worker(ip):
            if not self.running:
                return None
                
            result = self.perform_reverse_dns_query(ip)
            
            # Update counters
            if result['status'] == 'success':
                self.results['responses_received'] += 1
            elif result['status'] == 'timeout':
                self.results['timeouts'] += 1
            else:
                self.results['errors'] += 1
                
            self.results['queries_sent'] += 1
            
            # Progress update
            if self.results['queries_sent'] % 50 == 0:
                elapsed = time.time() - start_time
                rate = self.results['queries_sent'] / elapsed
                self.log_activity(f"Progress: {self.results['queries_sent']} queries, {rate:.1f} q/s")
                
            time.sleep(delay)  # Rate limiting
            return result
            
        try:
            with ThreadPoolExecutor(max_workers=threads) as executor:
                # Submit all queries
                future_to_ip = {executor.submit(worker, ip): ip for ip in ip_list}
                
                for future in as_completed(future_to_ip):
                    if duration and (time.time() - start_time) > duration:
                        self.running = False
                        break
                        
                    result = future.result()
                    if result:
                        responses.append(result)
                        
        except KeyboardInterrupt:
            self.log_activity("⚠️  Test interrupted by user")
            self.running = False
            
        return responses
        
    def generate_report(self, responses, analysis, firewall_indicators):
        """Generate comprehensive test report"""
        elapsed_time = time.time() - self.start_time if hasattr(self, 'start_time') else 0
        
        report = {
            'test_summary': {
                'timestamp': datetime.now().isoformat(),
                'duration': f"{elapsed_time:.2f} seconds",
                'total_queries': len(responses),
                'queries_per_second': len(responses) / elapsed_time if elapsed_time > 0 else 0,
                'success_rate': f"{analysis['successful_responses'] / len(responses) * 100:.1f}%" if responses else "0%"
            },
            'response_analysis': analysis,
            'security_indicators': firewall_indicators,
            'recommendations': self.generate_recommendations(analysis, firewall_indicators)
        }
        
        return report
        
    def generate_recommendations(self, analysis, firewall_indicators):
        """Generate testing recommendations based on results"""
        recommendations = []
        
        if analysis['timeouts'] > analysis['total_queries'] * 0.3:
            recommendations.append({
                'category': 'Rate Limiting',
                'recommendation': 'High timeout rate detected. Consider reducing request rate or implementing longer delays.',
                'priority': 'high'
            })
            
        if firewall_indicators:
            recommendations.append({
                'category': 'Security Measures',
                'recommendation': 'Potential blocking detected. Test may be triggering security measures.',
                'priority': 'high'
            })
            
        if analysis['statistical_analysis'].get('std_deviation', 0) > 500:
            recommendations.append({
                'category': 'Network Variability',
                'recommendation': 'High response time variability suggests network congestion or load balancing.',
                'priority': 'medium'
            })
            
        if not recommendations:
            recommendations.append({
                'category': 'Test Results',
                'recommendation': 'Test completed successfully with normal response patterns.',
                'priority': 'info'
            })
            
        return recommendations
        
    def save_report(self, report, filename):
        """Save report to file"""
        import json
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)
            
        self.log_activity(f"📊 Report saved to: {filename}")

def main():
    parser = argparse.ArgumentParser(description="Reverse DNS Flood - Passive Defense Testing")
    parser.add_argument('-t', '--targets', help='Target IP range (CIDR notation)')
    parser.add_argument('-c', '--count', type=int, default=100,
                       help='Number of IPs to test (default: 100)')
    parser.add_argument('--threads', type=int, default=10,
                       help='Number of concurrent threads (default: 10)')
    parser.add_argument('--delay', type=float, default=0.1,
                       help='Delay between requests in seconds (default: 0.1)')
    parser.add_argument('--duration', type=int,
                       help='Maximum test duration in seconds')
    parser.add_argument('--safe-mode', action='store_true',
                       help='Use only safe, non-routable IP ranges')
    parser.add_argument('-o', '--output', help='Output report filename')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    flood_tester = ReverseDNSFlood()
    flood_tester.print_banner()
    
    # Validate arguments
    if not args.safe_mode and not args.targets:
        print("❌ Either --targets or --safe-mode must be specified")
        return 1
        
    print(f"\n🎯 Test Configuration:")
    print(f"   Target Count: {args.count}")
    print(f"   Threads: {args.threads}")
    print(f"   Delay: {args.delay}s")
    print(f"   Safe Mode: {'Yes' if args.safe_mode else 'No'}")
    if args.targets:
        print(f"   Target Range: {args.targets}")
        
    print(f"\n⚠️  IMPORTANT WARNINGS:")
    print(f"   • This tool generates DNS queries for testing purposes")
    print(f"   • Use only against your own infrastructure or with authorization")
    print(f"   • Monitor your network for unintended effects")
    print(f"   • Some systems may interpret high query rates as attacks")
    
    confirm = input(f"\n🚀 Start reverse DNS flood test? (y/N): ")
    if confirm.lower() != 'y':
        print("Test cancelled.")
        return 0
        
    try:
        flood_tester.start_time = time.time()
        
        # Generate IP list
        if args.safe_mode:
            ip_list = flood_tester.generate_safe_ips(args.count)
        else:
            ip_list = flood_tester.generate_ip_ranges(args.targets, args.count)
            
        if not ip_list:
            print("❌ No IPs generated for testing")
            return 1
            
        # Run the test
        responses = flood_tester.run_controlled_flood(
            ip_list, args.threads, args.delay, args.duration
        )
        
        if not responses:
            print("❌ No responses received")
            return 1
            
        # Analyze results
        analysis = flood_tester.analyze_response_patterns(responses)
        firewall_indicators = flood_tester.detect_firewall_behavior(responses)
        
        # Generate report
        report = flood_tester.generate_report(responses, analysis, firewall_indicators)
        
        # Display summary
        print(f"\n🎯 TEST RESULTS SUMMARY:")
        print(f"   Total Queries: {report['test_summary']['total_queries']}")
        print(f"   Success Rate: {report['test_summary']['success_rate']}")
        print(f"   Queries/Second: {report['test_summary']['queries_per_second']:.1f}")
        print(f"   Duration: {report['test_summary']['duration']}")
        
        if analysis['statistical_analysis']:
            stats = analysis['statistical_analysis']
            print(f"\n📊 Response Time Statistics:")
            print(f"   Mean: {stats['mean_response_time']:.2f}ms")
            print(f"   Median: {stats['median_response_time']:.2f}ms")
            print(f"   Min/Max: {stats['min_response_time']:.2f}/{stats['max_response_time']:.2f}ms")
            
        if analysis['detected_security_measures']:
            print(f"\n🛡️  Security Measures Detected:")
            for measure in analysis['detected_security_measures']:
                print(f"   • {measure['measure']} ({measure['confidence']} confidence)")
                print(f"     {measure['description']}")
                
        if firewall_indicators:
            print(f"\n🔥 Firewall/WAF Indicators:")
            for indicator in firewall_indicators:
                print(f"   • {indicator['type']} at {indicator['time_window']}")
                
        # Save report
        if args.output:
            flood_tester.save_report(report, args.output)
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"reverse_dns_flood_report_{timestamp}.json"
            flood_tester.save_report(report, filename)
            
        print(f"\n✅ Reverse DNS flood test completed successfully!")
        
    except KeyboardInterrupt:
        print(f"\n⚠️  Test interrupted by user")
        return 1
    except Exception as e:
        print(f"\n❌ Test error: {e}")
        return 1
        
    return 0

if __name__ == "__main__":
    sys.exit(main())
