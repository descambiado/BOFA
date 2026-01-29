
#!/usr/bin/env python3
"""
Defense Break Replicator - Malware Behavior Simulator
Developed by @descambiado for BOFA Suite

Revolutionary tool that emulates multiple malware behaviors
to train and test security defense systems without causing real damage.
"""

import os
import sys
import time
import random
import socket
import psutil
import tempfile
import threading
import subprocess
import argparse
from datetime import datetime, timedelta
from pathlib import Path

class DefenseBreakReplicator:
    def __init__(self):
        self.version = "1.0.0"
        self.author = "@descambiado"
        self.simulation_active = False
        self.created_files = []
        self.started_processes = []
        self.network_connections = []
        
    def print_banner(self):
        print("\n" + "="*70)
        print("🧪 DEFENSE BREAK REPLICATOR - Malware Behavior Simulator")
        print("="*70)
        print(f"Version: {self.version} | Author: {self.author}")
        print("Safe malware behavior emulation for defense training")
        print("="*70)
        
    def log_activity(self, activity, level="INFO"):
        """Log simulation activities"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{level}] {activity}")
        
        # Also write to syslog if available
        try:
            import syslog
            syslog.openlog("DefenseBreakReplicator")
            syslog_level = syslog.LOG_INFO if level == "INFO" else syslog.LOG_WARNING
            syslog.syslog(syslog_level, f"SIMULATION: {activity}")
        except:
            pass
            
    def simulate_file_system_behavior(self, duration=60):
        """Simulate malware file system activities"""
        self.log_activity("🗂️  Starting file system behavior simulation")
        
        end_time = time.time() + duration
        suspicious_paths = [
            "/tmp",
            "/var/tmp", 
            os.path.expanduser("~/.cache"),
            os.path.expanduser("~/.local/share")
        ]
        
        malware_filenames = [
            "svchost_backup.exe",
            "system32_update.dll",
            "winlogon_helper.bat",
            "chrome_extension_update.js",
            "firefox_addon_cache.tmp",
            "java_runtime_cache.jar",
            "adobe_flash_update.exe",
            "microsoft_defender_bypass.ps1"
        ]
        
        while time.time() < end_time and self.simulation_active:
            try:
                # Create suspicious files
                base_path = random.choice(suspicious_paths)
                filename = random.choice(malware_filenames)
                filepath = os.path.join(base_path, filename)
                
                # Create file with suspicious content
                with open(filepath, 'w') as f:
                    suspicious_content = self.generate_suspicious_content()
                    f.write(suspicious_content)
                
                self.created_files.append(filepath)
                self.log_activity(f"Created suspicious file: {filepath}")
                
                # Modify file attributes randomly
                if random.choice([True, False]):
                    os.chmod(filepath, 0o777)  # Highly permissive
                    self.log_activity(f"Set suspicious permissions on: {filepath}")
                
                # Simulate file encryption behavior
                if random.choice([True, False]):
                    encrypted_name = filepath + ".encrypted"
                    os.rename(filepath, encrypted_name)
                    self.created_files.append(encrypted_name)
                    self.log_activity(f"Simulated file encryption: {encrypted_name}")
                
                time.sleep(random.uniform(2, 10))
                
            except Exception as e:
                self.log_activity(f"File system simulation error: {e}", "WARNING")
                
    def simulate_network_behavior(self, duration=60):
        """Simulate malware network activities"""
        self.log_activity("🌐 Starting network behavior simulation")
        
        end_time = time.time() + duration
        suspicious_domains = [
            "malware-command-control.fake",
            "botnet-communication.fake", 
            "data-exfiltration.fake",
            "crypto-mining-pool.fake",
            "phishing-kit-download.fake"
        ]
        
        suspicious_ips = [
            "10.0.0.1",  # Private IP for safe testing
            "127.0.0.1", # Localhost
            "192.168.1.1"
        ]
        
        while time.time() < end_time and self.simulation_active:
            try:
                # Simulate DNS lookups to suspicious domains
                domain = random.choice(suspicious_domains)
                self.log_activity(f"Simulated DNS lookup: {domain}")
                
                # Simulate connection attempts (safe, local only)
                target_ip = random.choice(suspicious_ips)
                target_port = random.choice([8080, 9999, 4444, 1337, 31337])
                
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    sock.connect((target_ip, target_port))
                    self.network_connections.append(sock)
                    self.log_activity(f"Simulated connection to: {target_ip}:{target_port}")
                except:
                    self.log_activity(f"Connection attempt to: {target_ip}:{target_port}")
                
                # Simulate data exfiltration patterns
                if random.choice([True, False]):
                    fake_data_size = random.randint(1024, 10240)  # 1KB-10KB
                    self.log_activity(f"Simulated data exfiltration: {fake_data_size} bytes")
                
                time.sleep(random.uniform(3, 15))
                
            except Exception as e:
                self.log_activity(f"Network simulation error: {e}", "WARNING")
                
    def simulate_process_behavior(self, duration=60):
        """Simulate malware process activities"""
        self.log_activity("⚙️  Starting process behavior simulation")
        
        end_time = time.time() + duration
        
        while time.time() < end_time and self.simulation_active:
            try:
                # Simulate process injection behavior
                current_pid = os.getpid()
                self.log_activity(f"Simulated process injection attempt from PID: {current_pid}")
                
                # Simulate registry modifications (Linux equivalent: config files)
                config_paths = [
                    os.path.expanduser("~/.bashrc"),
                    os.path.expanduser("~/.profile"),
                    "/tmp/fake_registry_key.conf"
                ]
                
                config_path = random.choice(config_paths)
                if config_path.startswith("/tmp/"):
                    # Only create fake registry entries in /tmp for safety
                    with open(config_path, 'a') as f:
                        fake_entry = f"# MALWARE_SIMULATION_ENTRY_{random.randint(1000, 9999)}\n"
                        f.write(fake_entry)
                    self.created_files.append(config_path)
                    self.log_activity(f"Simulated registry modification: {config_path}")
                
                # Simulate privilege escalation attempts
                self.log_activity("Simulated privilege escalation attempt")
                
                # Simulate anti-debugging techniques
                if random.choice([True, False]):
                    self.log_activity("Simulated anti-debugging technique activation")
                
                # Simulate persistence mechanisms
                if random.choice([True, False]):
                    cron_job = "/tmp/fake_malware_cron.txt"
                    with open(cron_job, 'w') as f:
                        f.write("# Fake malware persistence entry\n")
                        f.write("@reboot /tmp/fake_malware.sh\n")
                    self.created_files.append(cron_job)
                    self.log_activity(f"Simulated persistence mechanism: cron job")
                
                time.sleep(random.uniform(5, 20))
                
            except Exception as e:
                self.log_activity(f"Process simulation error: {e}", "WARNING")
                
    def simulate_system_reconnaissance(self, duration=30):
        """Simulate malware system reconnaissance"""
        self.log_activity("🔍 Starting system reconnaissance simulation")
        
        end_time = time.time() + duration
        
        while time.time() < end_time and self.simulation_active:
            try:
                # Simulate system information gathering
                system_info = {
                    'hostname': socket.gethostname(),
                    'platform': sys.platform,
                    'cpu_count': psutil.cpu_count(),
                    'memory': psutil.virtual_memory().total,
                    'disk_usage': psutil.disk_usage('/').total
                }
                
                self.log_activity(f"Simulated system info gathering: {system_info['hostname']}")
                
                # Simulate network interface enumeration
                try:
                    interfaces = psutil.net_if_addrs()
                    self.log_activity(f"Simulated network interface enumeration: {len(interfaces)} interfaces")
                except:
                    pass
                
                # Simulate running process enumeration
                try:
                    processes = len(list(psutil.process_iter()))
                    self.log_activity(f"Simulated process enumeration: {processes} processes")
                except:
                    pass
                
                # Simulate user enumeration
                try:
                    current_user = os.getlogin()
                    self.log_activity(f"Simulated user enumeration: {current_user}")
                except:
                    pass
                
                time.sleep(random.uniform(2, 8))
                
            except Exception as e:
                self.log_activity(f"Reconnaissance simulation error: {e}", "WARNING")
                
    def simulate_crypto_mining(self, duration=30):
        """Simulate cryptocurrency mining behavior"""
        self.log_activity("⛏️  Starting crypto mining behavior simulation")
        
        end_time = time.time() + duration
        
        while time.time() < end_time and self.simulation_active:
            try:
                # Simulate high CPU usage patterns
                cpu_percent = random.uniform(80, 95)
                self.log_activity(f"Simulated high CPU usage: {cpu_percent:.1f}%")
                
                # Simulate mining pool connections
                fake_pools = [
                    "pool.fake-bitcoin.com:4444",
                    "stratum.fake-ethereum.org:8008", 
                    "mining.fake-monero.net:3333"
                ]
                
                pool = random.choice(fake_pools)
                self.log_activity(f"Simulated mining pool connection: {pool}")
                
                # Simulate worker creation
                worker_id = f"worker_{random.randint(1000, 9999)}"
                self.log_activity(f"Simulated mining worker: {worker_id}")
                
                time.sleep(random.uniform(5, 15))
                
            except Exception as e:
                self.log_activity(f"Crypto mining simulation error: {e}", "WARNING")
                
    def generate_suspicious_content(self):
        """Generate suspicious file content for testing"""
        templates = [
            "#!/bin/bash\n# Fake malware script\necho 'This is a simulation'\n",
            "// Fake malware payload\nfunction exploit() {\n    // Simulation only\n}\n",
            "REM Fake batch malware\necho This is a simulation\n",
            "# PowerShell simulation\nWrite-Host 'Simulation Mode'\n",
            "import os\n# Python simulation\nprint('Defense training simulation')\n"
        ]
        
        return random.choice(templates)
        
    def generate_honeytokens(self):
        """Generate honeytokens for detection testing"""
        self.log_activity("🍯 Generating honeytokens for detection testing")
        
        honeytokens = [
            {
                'type': 'fake_credential',
                'content': 'admin:SuperSecretPassword123!',
                'location': '/tmp/fake_credentials.txt'
            },
            {
                'type': 'fake_api_key', 
                'content': 'API_KEY=sk-fake1234567890abcdef',
                'location': '/tmp/fake_config.env'
            },
            {
                'type': 'fake_database_connection',
                'content': 'mysql://root:password@localhost/sensitive_db',
                'location': '/tmp/fake_db_config.txt'
            }
        ]
        
        for token in honeytokens:
            try:
                with open(token['location'], 'w') as f:
                    f.write(token['content'] + '\n')
                self.created_files.append(token['location'])
                self.log_activity(f"Created honeytoken: {token['type']} at {token['location']}")
            except Exception as e:
                self.log_activity(f"Honeytoken creation error: {e}", "WARNING")
                
    def cleanup_simulation(self):
        """Clean up all simulation artifacts"""
        self.log_activity("🧹 Cleaning up simulation artifacts")
        
        # Remove created files
        for filepath in self.created_files:
            try:
                if os.path.exists(filepath):
                    os.remove(filepath)
                    self.log_activity(f"Removed: {filepath}")
            except Exception as e:
                self.log_activity(f"Cleanup error for {filepath}: {e}", "WARNING")
        
        # Close network connections
        for conn in self.network_connections:
            try:
                conn.close()
            except:
                pass
                
        self.created_files.clear()
        self.network_connections.clear()
        
        self.log_activity("✅ Simulation cleanup completed")
        
    def run_full_simulation(self, duration=300):
        """Run complete malware behavior simulation"""
        self.log_activity(f"🚀 Starting full malware behavior simulation ({duration}s)")
        self.simulation_active = True
        
        # Start different simulation threads
        threads = []
        
        # File system behavior
        fs_thread = threading.Thread(target=self.simulate_file_system_behavior, args=(duration,))
        threads.append(fs_thread)
        
        # Network behavior
        net_thread = threading.Thread(target=self.simulate_network_behavior, args=(duration,))
        threads.append(net_thread)
        
        # Process behavior
        proc_thread = threading.Thread(target=self.simulate_process_behavior, args=(duration,))
        threads.append(proc_thread)
        
        # System reconnaissance
        recon_thread = threading.Thread(target=self.simulate_system_reconnaissance, args=(duration//2,))
        threads.append(recon_thread)
        
        # Crypto mining simulation
        mining_thread = threading.Thread(target=self.simulate_crypto_mining, args=(duration//4,))
        threads.append(mining_thread)
        
        # Generate honeytokens
        self.generate_honeytokens()
        
        # Start all threads
        for thread in threads:
            thread.start()
            
        try:
            # Wait for completion or interruption
            time.sleep(duration)
        except KeyboardInterrupt:
            self.log_activity("⚠️  Simulation interrupted by user")
        finally:
            self.simulation_active = False
            
            # Wait for threads to finish
            for thread in threads:
                thread.join(timeout=5)
                
            # Cleanup
            self.cleanup_simulation()
            
        self.log_activity("🎯 Malware behavior simulation completed")

def main():
    parser = argparse.ArgumentParser(description="Defense Break Replicator - Malware Behavior Simulator")
    parser.add_argument('-d', '--duration', type=int, default=300,
                       help='Simulation duration in seconds (default: 300)')
    parser.add_argument('-t', '--type', choices=['filesystem', 'network', 'process', 'recon', 'mining', 'all'],
                       default='all', help='Simulation type')
    parser.add_argument('--honeytokens', action='store_true',
                       help='Generate honeytokens only')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('--yes', action='store_true',
                       help='Non-interactive: skip confirmation prompt')
    
    args = parser.parse_args()
    
    simulator = DefenseBreakReplicator()
    simulator.print_banner()
    
    print(f"\n🎯 Configuration:")
    print(f"   Duration: {args.duration} seconds")
    print(f"   Simulation Type: {args.type}")
    print(f"   Verbose: {args.verbose}")
    
    print(f"\n⚠️  IMPORTANT WARNINGS:")
    print(f"   • This tool creates files and network activity for testing")
    print(f"   • All activities are simulated and non-malicious")
    print(f"   • Use only in authorized testing environments")
    print(f"   • Monitor your SIEM/EDR systems during execution")
    
    if not args.yes:
        try:
            confirm = input(f"\n🚀 Start simulation? (y/N): ")
        except EOFError:
            confirm = "n"
        if confirm.lower() != 'y':
            print("Simulation cancelled.")
            return 0
        
    try:    
        if args.honeytokens:
            simulator.generate_honeytokens()
        elif args.type == 'all':
            simulator.run_full_simulation(args.duration)
        else:
            # Run specific simulation type
            simulator.simulation_active = True
            if args.type == 'filesystem':
                simulator.simulate_file_system_behavior(args.duration)
            elif args.type == 'network':
                simulator.simulate_network_behavior(args.duration)
            elif args.type == 'process':
                simulator.simulate_process_behavior(args.duration)
            elif args.type == 'recon':
                simulator.simulate_system_reconnaissance(args.duration)
            elif args.type == 'mining':
                simulator.simulate_crypto_mining(args.duration)
            
            simulator.cleanup_simulation()
            
    except KeyboardInterrupt:
        simulator.simulation_active = False
        simulator.cleanup_simulation()
        print("\n⚠️  Simulation interrupted and cleaned up")
        
    return 0

if __name__ == "__main__":
    sys.exit(main())
