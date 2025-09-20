#!/usr/bin/env python3
"""
🧬 Behavioral Biometrics Analyzer v2.5.1
Revolutionary biometric authentication testing through behavioral patterns
By @descambiado for BOFA Security Suite
"""

import asyncio
import time
import json
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional
import argparse
from pathlib import Path
import statistics

@dataclass
class KeystrokePattern:
    """Keystroke dynamics pattern"""
    key: str
    dwell_time: float  # Time key is pressed
    flight_time: float  # Time between keystrokes
    pressure: float
    timestamp: float

@dataclass
class MousePattern:
    """Mouse movement pattern"""
    x: int
    y: int
    velocity: float
    acceleration: float
    pressure: float
    timestamp: float

class BehavioralBiometricsAnalyzer:
    """Advanced behavioral biometrics analyzer"""
    
    def __init__(self):
        self.keystroke_patterns = []
        self.mouse_patterns = []
        self.user_profiles = {}
        
    def simulate_keystroke_data(self, text: str, user_id: str) -> List[KeystrokePattern]:
        """Simulate realistic keystroke dynamics"""
        patterns = []
        base_time = time.time()
        
        # User-specific characteristics
        user_speed = np.random.normal(100, 20)  # WPM
        user_consistency = np.random.uniform(0.7, 0.95)
        
        for i, char in enumerate(text):
            # Dwell time (how long key is pressed)
            if char.isalpha():
                base_dwell = 0.08 + np.random.normal(0, 0.02)
            elif char == ' ':
                base_dwell = 0.12 + np.random.normal(0, 0.03)
            else:
                base_dwell = 0.15 + np.random.normal(0, 0.04)
            
            # Apply user consistency
            dwell_time = base_dwell * np.random.uniform(user_consistency, 1.0/user_consistency)
            
            # Flight time (time between keystrokes)
            base_flight = 60 / (user_speed * 5)  # Convert WPM to inter-keystroke interval
            
            # Digraph-specific timing (common letter pairs)
            if i > 0:
                digraph = text[i-1:i+1].lower()
                if digraph in ['th', 'he', 'in', 'er', 'an']:
                    base_flight *= 0.8  # Faster for common pairs
                elif digraph in ['qw', 'xz', 'qz']:
                    base_flight *= 1.5  # Slower for uncommon pairs
            
            flight_time = base_flight * np.random.uniform(user_consistency, 1.0/user_consistency)
            
            # Pressure simulation
            pressure = np.random.uniform(0.3, 1.0)
            
            pattern = KeystrokePattern(
                key=char,
                dwell_time=dwell_time,
                flight_time=flight_time,
                pressure=pressure,
                timestamp=base_time + i * (dwell_time + flight_time)
            )
            patterns.append(pattern)
            
        return patterns
    
    def simulate_mouse_data(self, duration: float, user_id: str) -> List[MousePattern]:
        """Simulate realistic mouse movement patterns"""
        patterns = []
        base_time = time.time()
        
        # User-specific mouse characteristics
        user_smoothness = np.random.uniform(0.6, 0.9)
        preferred_speed = np.random.uniform(200, 800)  # pixels/second
        
        # Simulate mouse path
        x, y = 400, 300  # Starting position
        for i in range(int(duration * 50)):  # 50 Hz sampling
            # Generate smooth mouse movement using Perlin noise simulation
            t = i / 50.0
            
            # Target movement
            target_x = 400 + 200 * np.sin(t * 0.5) + 50 * np.sin(t * 3)
            target_y = 300 + 150 * np.cos(t * 0.3) + 30 * np.cos(t * 4)
            
            # Apply user smoothness
            dx = (target_x - x) * user_smoothness * 0.1
            dy = (target_y - y) * user_smoothness * 0.1
            
            # Add tremor/jitter
            dx += np.random.normal(0, 1.0)
            dy += np.random.normal(0, 1.0)
            
            x += dx
            y += dy
            
            # Calculate velocity and acceleration
            if i > 0:
                prev_pattern = patterns[-1]
                dt = 0.02
                velocity = np.sqrt(dx**2 + dy**2) / dt
                
                if i > 1:
                    prev_velocity = prev_pattern.velocity
                    acceleration = (velocity - prev_velocity) / dt
                else:
                    acceleration = 0
            else:
                velocity = 0
                acceleration = 0
            
            # Pressure varies with speed
            pressure = min(1.0, velocity / preferred_speed)
            
            pattern = MousePattern(
                x=int(x),
                y=int(y),
                velocity=velocity,
                acceleration=acceleration,
                pressure=pressure,
                timestamp=base_time + t
            )
            patterns.append(pattern)
            
        return patterns
    
    def extract_keystroke_features(self, patterns: List[KeystrokePattern]) -> Dict:
        """Extract behavioral features from keystroke patterns"""
        if not patterns:
            return {}
        
        dwell_times = [p.dwell_time for p in patterns]
        flight_times = [p.flight_time for p in patterns if p.flight_time > 0]
        pressures = [p.pressure for p in patterns]
        
        features = {
            'dwell_mean': statistics.mean(dwell_times),
            'dwell_std': statistics.stdev(dwell_times) if len(dwell_times) > 1 else 0,
            'dwell_median': statistics.median(dwell_times),
            'flight_mean': statistics.mean(flight_times) if flight_times else 0,
            'flight_std': statistics.stdev(flight_times) if len(flight_times) > 1 else 0,
            'flight_median': statistics.median(flight_times) if flight_times else 0,
            'pressure_mean': statistics.mean(pressures),
            'pressure_std': statistics.stdev(pressures) if len(pressures) > 1 else 0,
            'typing_rhythm': self._calculate_rhythm_score(patterns),
            'total_typing_time': patterns[-1].timestamp - patterns[0].timestamp if patterns else 0
        }
        
        return features
    
    def extract_mouse_features(self, patterns: List[MousePattern]) -> Dict:
        """Extract behavioral features from mouse patterns"""
        if not patterns:
            return {}
        
        velocities = [p.velocity for p in patterns]
        accelerations = [p.acceleration for p in patterns]
        pressures = [p.pressure for p in patterns]
        
        # Path analysis
        path_length = sum(np.sqrt((patterns[i+1].x - patterns[i].x)**2 + 
                                 (patterns[i+1].y - patterns[i].y)**2) 
                         for i in range(len(patterns)-1))
        
        # Tremor analysis
        tremor_score = self._calculate_tremor_score(patterns)
        
        features = {
            'velocity_mean': statistics.mean(velocities),
            'velocity_std': statistics.stdev(velocities) if len(velocities) > 1 else 0,
            'velocity_max': max(velocities),
            'acceleration_mean': statistics.mean(accelerations),
            'acceleration_std': statistics.stdev(accelerations) if len(accelerations) > 1 else 0,
            'pressure_mean': statistics.mean(pressures),
            'path_length': path_length,
            'tremor_score': tremor_score,
            'movement_efficiency': self._calculate_efficiency(patterns),
            'pause_patterns': self._analyze_pause_patterns(patterns)
        }
        
        return features
    
    def _calculate_rhythm_score(self, patterns: List[KeystrokePattern]) -> float:
        """Calculate typing rhythm consistency"""
        if len(patterns) < 3:
            return 0
        
        intervals = [patterns[i+1].timestamp - patterns[i].timestamp 
                    for i in range(len(patterns)-1)]
        
        if not intervals:
            return 0
        
        # Rhythm is inverse of coefficient of variation
        mean_interval = statistics.mean(intervals)
        std_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
        
        if mean_interval == 0:
            return 0
        
        cv = std_interval / mean_interval
        return max(0, 1 - cv)
    
    def _calculate_tremor_score(self, patterns: List[MousePattern]) -> float:
        """Calculate mouse tremor/jitter score"""
        if len(patterns) < 10:
            return 0
        
        # High-frequency movement analysis
        velocities = [p.velocity for p in patterns]
        
        # Calculate power spectral density to detect tremor
        # Simplistic approach: look for high-frequency components
        velocity_changes = [abs(velocities[i+1] - velocities[i]) 
                           for i in range(len(velocities)-1)]
        
        if not velocity_changes:
            return 0
        
        high_freq_power = sum(v for v in velocity_changes if v > statistics.mean(velocity_changes))
        total_power = sum(velocity_changes)
        
        return high_freq_power / total_power if total_power > 0 else 0
    
    def _calculate_efficiency(self, patterns: List[MousePattern]) -> float:
        """Calculate movement efficiency (straight line vs actual path)"""
        if len(patterns) < 2:
            return 1.0
        
        # Actual path length
        actual_length = sum(np.sqrt((patterns[i+1].x - patterns[i].x)**2 + 
                                   (patterns[i+1].y - patterns[i].y)**2) 
                           for i in range(len(patterns)-1))
        
        # Straight line distance
        straight_distance = np.sqrt((patterns[-1].x - patterns[0].x)**2 + 
                                   (patterns[-1].y - patterns[0].y)**2)
        
        if actual_length == 0:
            return 1.0
        
        return straight_distance / actual_length
    
    def _analyze_pause_patterns(self, patterns: List[MousePattern]) -> float:
        """Analyze pause patterns in mouse movement"""
        if len(patterns) < 10:
            return 0
        
        velocities = [p.velocity for p in patterns]
        low_velocity_threshold = statistics.mean(velocities) * 0.1
        
        pauses = [v < low_velocity_threshold for v in velocities]
        pause_count = sum(pauses)
        
        return pause_count / len(patterns)
    
    def create_user_profile(self, user_id: str, keystroke_samples: List[List[KeystrokePattern]], 
                           mouse_samples: List[List[MousePattern]]) -> Dict:
        """Create behavioral profile for a user"""
        keystroke_features_list = [self.extract_keystroke_features(sample) 
                                  for sample in keystroke_samples]
        mouse_features_list = [self.extract_mouse_features(sample) 
                              for sample in mouse_samples]
        
        # Aggregate features
        profile = {'user_id': user_id, 'keystroke_profile': {}, 'mouse_profile': {}}
        
        if keystroke_features_list:
            for key in keystroke_features_list[0].keys():
                values = [f[key] for f in keystroke_features_list if key in f]
                if values:
                    profile['keystroke_profile'][key] = {
                        'mean': statistics.mean(values),
                        'std': statistics.stdev(values) if len(values) > 1 else 0,
                        'min': min(values),
                        'max': max(values)
                    }
        
        if mouse_features_list:
            for key in mouse_features_list[0].keys():
                values = [f[key] for f in mouse_features_list if key in f]
                if values:
                    profile['mouse_profile'][key] = {
                        'mean': statistics.mean(values),
                        'std': statistics.stdev(values) if len(values) > 1 else 0,
                        'min': min(values),
                        'max': max(values)
                    }
        
        self.user_profiles[user_id] = profile
        return profile
    
    def authenticate_user(self, user_id: str, keystroke_sample: List[KeystrokePattern], 
                         mouse_sample: List[MousePattern]) -> Dict:
        """Authenticate user based on behavioral patterns"""
        if user_id not in self.user_profiles:
            return {'success': False, 'reason': 'User profile not found'}
        
        profile = self.user_profiles[user_id]
        current_keystroke_features = self.extract_keystroke_features(keystroke_sample)
        current_mouse_features = self.extract_mouse_features(mouse_sample)
        
        # Calculate similarity scores
        keystroke_score = self._calculate_similarity_score(
            current_keystroke_features, profile['keystroke_profile']
        )
        mouse_score = self._calculate_similarity_score(
            current_mouse_features, profile['mouse_profile']
        )
        
        # Combined score
        overall_score = (keystroke_score + mouse_score) / 2
        threshold = 0.7  # Configurable threshold
        
        result = {
            'success': overall_score >= threshold,
            'confidence': overall_score,
            'keystroke_score': keystroke_score,
            'mouse_score': mouse_score,
            'threshold': threshold,
            'details': {
                'keystroke_features': current_keystroke_features,
                'mouse_features': current_mouse_features
            }
        }
        
        return result
    
    def _calculate_similarity_score(self, current_features: Dict, profile: Dict) -> float:
        """Calculate similarity between current features and stored profile"""
        if not current_features or not profile:
            return 0.0
        
        scores = []
        
        for feature_name, current_value in current_features.items():
            if feature_name in profile:
                stored_stats = profile[feature_name]
                
                # Calculate z-score
                mean = stored_stats['mean']
                std = stored_stats['std']
                
                if std == 0:
                    # If no variation in training, check exact match
                    score = 1.0 if abs(current_value - mean) < 0.01 else 0.0
                else:
                    # Calculate similarity based on how many standard deviations away
                    z_score = abs(current_value - mean) / std
                    # Convert to similarity (closer to 0 z-score = higher similarity)
                    score = max(0, 1 - (z_score / 3))  # 3-sigma rule
                
                scores.append(score)
        
        return statistics.mean(scores) if scores else 0.0
    
    def generate_report(self, output_file: str = None):
        """Generate comprehensive behavioral analysis report"""
        report = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'tool': 'BOFA Behavioral Biometrics Analyzer v2.5.1',
            'author': '@descambiado',
            'analysis_summary': {
                'total_users': len(self.user_profiles),
                'keystroke_patterns_collected': len(self.keystroke_patterns),
                'mouse_patterns_collected': len(self.mouse_patterns)
            },
            'user_profiles': self.user_profiles,
            'security_recommendations': self._generate_security_recommendations()
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            print(f"[+] Report saved to {output_file}")
        
        return report
    
    def _generate_security_recommendations(self) -> List[str]:
        """Generate security recommendations"""
        recommendations = [
            "Implement behavioral biometrics as additional authentication factor",
            "Set adaptive thresholds based on user behavior patterns",
            "Monitor for unusual typing patterns indicating potential compromise",
            "Use continuous authentication rather than one-time verification",
            "Combine behavioral biometrics with traditional 2FA methods",
            "Regular retraining of user profiles to adapt to natural changes",
            "Implement anomaly detection for administrative actions",
            "Consider time-of-day and location factors in authentication decisions"
        ]
        return recommendations
    
    def visualize_patterns(self, user_id: str, save_path: str = None):
        """Visualize user behavioral patterns"""
        if user_id not in self.user_profiles:
            print(f"[-] User profile for {user_id} not found")
            return
        
        profile = self.user_profiles[user_id]
        
        # Create visualization
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 10))
        fig.suptitle(f'Behavioral Biometrics Profile: {user_id}', fontsize=16)
        
        # Keystroke timing patterns
        if profile['keystroke_profile']:
            keys = list(profile['keystroke_profile'].keys())
            means = [profile['keystroke_profile'][k]['mean'] for k in keys]
            stds = [profile['keystroke_profile'][k]['std'] for k in keys]
            
            ax1.errorbar(range(len(keys)), means, yerr=stds, fmt='o-')
            ax1.set_title('Keystroke Timing Patterns')
            ax1.set_xlabel('Feature')
            ax1.set_ylabel('Time (seconds)')
            ax1.set_xticks(range(len(keys)))
            ax1.set_xticklabels(keys, rotation=45)
        
        # Mouse movement patterns
        if profile['mouse_profile']:
            keys = list(profile['mouse_profile'].keys())
            means = [profile['mouse_profile'][k]['mean'] for k in keys]
            
            ax2.bar(range(len(keys)), means)
            ax2.set_title('Mouse Movement Patterns')
            ax2.set_xlabel('Feature')
            ax2.set_ylabel('Value')
            ax2.set_xticks(range(len(keys)))
            ax2.set_xticklabels(keys, rotation=45)
        
        # Feature distribution heatmap
        if profile['keystroke_profile'] and profile['mouse_profile']:
            all_features = {**profile['keystroke_profile'], **profile['mouse_profile']}
            feature_matrix = [[f['mean'], f['std'], f['min'], f['max']] 
                             for f in all_features.values()]
            
            sns.heatmap(feature_matrix, 
                       xticklabels=['Mean', 'Std', 'Min', 'Max'],
                       yticklabels=list(all_features.keys()),
                       annot=True, fmt='.3f', ax=ax3)
            ax3.set_title('Feature Statistics Heatmap')
        
        # Authentication timeline (simulated)
        times = np.arange(0, 24, 0.5)
        auth_success_rate = 0.95 + 0.05 * np.sin(times * np.pi / 6)  # Circadian rhythm
        
        ax4.plot(times, auth_success_rate, 'g-', linewidth=2)
        ax4.set_title('Expected Authentication Success Rate by Time')
        ax4.set_xlabel('Hour of Day')
        ax4.set_ylabel('Success Rate')
        ax4.set_ylim(0.8, 1.0)
        ax4.grid(True, alpha=0.3)
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"[+] Visualization saved to {save_path}")
        
        plt.show()

async def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description="BOFA Behavioral Biometrics Analyzer v2.5.1")
    parser.add_argument("--mode", choices=["profile", "authenticate", "demo"], 
                       default="demo", help="Operation mode")
    parser.add_argument("--user-id", default="user001", help="User identifier")
    parser.add_argument("--text", default="The quick brown fox jumps over the lazy dog", 
                       help="Text for keystroke analysis")
    parser.add_argument("--duration", type=float, default=10.0, 
                       help="Duration for mouse tracking (seconds)")
    parser.add_argument("--samples", type=int, default=5, 
                       help="Number of samples for profile creation")
    parser.add_argument("--output", help="Output file for report")
    parser.add_argument("--visualize", action="store_true", 
                       help="Generate visualizations")
    
    args = parser.parse_args()
    
    print("🧬 BOFA Behavioral Biometrics Analyzer v2.5.1")
    print("=" * 60)
    print("Revolutionary biometric authentication testing")
    print("By @descambiado for BOFA Security Suite")
    print("=" * 60)
    
    analyzer = BehavioralBiometricsAnalyzer()
    
    if args.mode == "demo":
        print("\n[+] Running comprehensive demo...")
        
        # Create multiple user profiles
        users = ["alice", "bob", "charlie", "diana"]
        
        for user in users:
            print(f"\n[+] Creating profile for user: {user}")
            
            # Generate training samples
            keystroke_samples = []
            mouse_samples = []
            
            for i in range(args.samples):
                # Keystroke samples
                keystroke_pattern = analyzer.simulate_keystroke_data(args.text, user)
                keystroke_samples.append(keystroke_pattern)
                
                # Mouse samples  
                mouse_pattern = analyzer.simulate_mouse_data(args.duration, user)
                mouse_samples.append(mouse_pattern)
                
                print(f"  Generated sample {i+1}/{args.samples}")
            
            # Create profile
            profile = analyzer.create_user_profile(user, keystroke_samples, mouse_samples)
            print(f"  Profile created with {len(profile['keystroke_profile'])} keystroke features")
            print(f"  and {len(profile['mouse_profile'])} mouse features")
        
        # Test authentication
        print(f"\n[+] Testing authentication for all users...")
        
        for user in users:
            # Generate test sample
            test_keystroke = analyzer.simulate_keystroke_data(args.text, user)
            test_mouse = analyzer.simulate_mouse_data(args.duration, user)
            
            # Authenticate
            result = analyzer.authenticate_user(user, test_keystroke, test_mouse)
            
            status = "✅ PASS" if result['success'] else "❌ FAIL"
            print(f"  {user}: {status} (Confidence: {result['confidence']:.2f})")
            print(f"    Keystroke Score: {result['keystroke_score']:.2f}")
            print(f"    Mouse Score: {result['mouse_score']:.2f}")
        
        # Test impersonation
        print(f"\n[+] Testing impersonation attacks...")
        
        for imposter in users[:2]:
            for target in users[2:]:
                # Imposter tries to authenticate as target
                test_keystroke = analyzer.simulate_keystroke_data(args.text, imposter)
                test_mouse = analyzer.simulate_mouse_data(args.duration, imposter)
                
                result = analyzer.authenticate_user(target, test_keystroke, test_mouse)
                
                status = "🚨 BREACH" if result['success'] else "✅ BLOCKED"
                print(f"  {imposter} → {target}: {status} (Confidence: {result['confidence']:.2f})")
    
    elif args.mode == "profile":
        print(f"\n[+] Creating profile for user: {args.user_id}")
        
        keystroke_samples = []
        mouse_samples = []
        
        for i in range(args.samples):
            keystroke_pattern = analyzer.simulate_keystroke_data(args.text, args.user_id)
            mouse_pattern = analyzer.simulate_mouse_data(args.duration, args.user_id)
            
            keystroke_samples.append(keystroke_pattern)
            mouse_samples.append(mouse_pattern)
            
            print(f"Generated sample {i+1}/{args.samples}")
        
        profile = analyzer.create_user_profile(args.user_id, keystroke_samples, mouse_samples)
        print(f"[+] Profile created successfully")
    
    elif args.mode == "authenticate":
        print(f"\n[+] Authenticating user: {args.user_id}")
        
        # Generate test sample
        test_keystroke = analyzer.simulate_keystroke_data(args.text, args.user_id)
        test_mouse = analyzer.simulate_mouse_data(args.duration, args.user_id)
        
        result = analyzer.authenticate_user(args.user_id, test_keystroke, test_mouse)
        
        if result['success']:
            print("✅ Authentication successful")
        else:
            print("❌ Authentication failed")
            print(f"Reason: {result.get('reason', 'Low confidence score')}")
        
        print(f"Confidence: {result['confidence']:.2f}")
    
    # Generate report
    if args.output:
        analyzer.generate_report(args.output)
    
    # Generate visualizations
    if args.visualize and analyzer.user_profiles:
        for user_id in analyzer.user_profiles.keys():
            viz_path = f"behavioral_analysis_{user_id}.png"
            analyzer.visualize_patterns(user_id, viz_path)
    
    print("\n[+] Analysis complete!")
    print("\n🛡️ Security Implications:")
    print("• Behavioral biometrics provide continuous authentication")
    print("• Can detect account takeover even with valid credentials")
    print("• Adaptive thresholds needed for different contexts")
    print("• Combine with traditional 2FA for best security")
    print("• Monitor for sudden behavioral changes")

if __name__ == "__main__":
    asyncio.run(main())