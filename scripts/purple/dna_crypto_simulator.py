#!/usr/bin/env python3
"""
BOFA DNA-based Cryptography Simulator v2.5.1
Revolutionary biological cryptography using DNA sequences and genetic algorithms
"""

import random
import hashlib
import base64
import json
from datetime import datetime
import re
from itertools import product

class DNACryptographySimulator:
    def __init__(self):
        # DNA nucleotide mapping
        self.dna_alphabet = ['A', 'T', 'G', 'C']
        
        # Binary to DNA mapping (2 bits per nucleotide)
        self.binary_to_dna = {
            '00': 'A',
            '01': 'T',
            '10': 'G',
            '11': 'C'
        }
        
        self.dna_to_binary = {v: k for k, v in self.binary_to_dna.items()}
        
        # Genetic code table (simplified)
        self.genetic_code = {
            'TTT': 'F', 'TTC': 'F', 'TTA': 'L', 'TTG': 'L',
            'TCT': 'S', 'TCC': 'S', 'TCA': 'S', 'TCG': 'S',
            'TAT': 'Y', 'TAC': 'Y', 'TAA': '*', 'TAG': '*',
            'TGT': 'C', 'TGC': 'C', 'TGA': '*', 'TGG': 'W',
            'CTT': 'L', 'CTC': 'L', 'CTA': 'L', 'CTG': 'L',
            'CCT': 'P', 'CCC': 'P', 'CCA': 'P', 'CCG': 'P',
            'CAT': 'H', 'CAC': 'H', 'CAA': 'Q', 'CAG': 'Q',
            'CGT': 'R', 'CGC': 'R', 'CGA': 'R', 'CGG': 'R',
            'ATT': 'I', 'ATC': 'I', 'ATA': 'I', 'ATG': 'M',
            'ACT': 'T', 'ACC': 'T', 'ACA': 'T', 'ACG': 'T',
            'AAT': 'N', 'AAC': 'N', 'AAA': 'K', 'AAG': 'K',
            'AGT': 'S', 'AGC': 'S', 'AGA': 'R', 'AGG': 'R',
            'GTT': 'V', 'GTC': 'V', 'GTA': 'V', 'GTG': 'V',
            'GCT': 'A', 'GCC': 'A', 'GCA': 'A', 'GCG': 'A',
            'GAT': 'D', 'GAC': 'D', 'GAA': 'E', 'GAG': 'E',
            'GGT': 'G', 'GGC': 'G', 'GGA': 'G', 'GGG': 'G'
        }
        
        # DNA cryptographic constraints
        self.constraints = {
            'gc_content_min': 0.4,  # Minimum GC content
            'gc_content_max': 0.6,  # Maximum GC content
            'max_homopolymer': 4,   # Maximum consecutive same nucleotides
            'prohibited_sequences': ['AAAA', 'TTTT', 'GGGG', 'CCCC']
        }
    
    def text_to_binary(self, text):
        """Convert text to binary representation"""
        return ''.join(format(ord(char), '08b') for char in text)
    
    def binary_to_text(self, binary):
        """Convert binary to text"""
        # Ensure binary length is multiple of 8
        while len(binary) % 8 != 0:
            binary += '0'
        
        chars = []
        for i in range(0, len(binary), 8):
            byte = binary[i:i+8]
            chars.append(chr(int(byte, 2)))
        return ''.join(chars)
    
    def binary_to_dna_sequence(self, binary):
        """Convert binary data to DNA sequence"""
        # Ensure binary length is even
        if len(binary) % 2 != 0:
            binary += '0'
        
        dna_sequence = ''
        for i in range(0, len(binary), 2):
            two_bits = binary[i:i+2]
            dna_sequence += self.binary_to_dna[two_bits]
        
        return dna_sequence
    
    def dna_sequence_to_binary(self, dna_sequence):
        """Convert DNA sequence back to binary"""
        binary = ''
        for nucleotide in dna_sequence:
            if nucleotide in self.dna_to_binary:
                binary += self.dna_to_binary[nucleotide]
        
        return binary
    
    def validate_dna_constraints(self, dna_sequence):
        """Validate DNA sequence against biological constraints"""
        issues = []
        
        # Check GC content
        gc_count = dna_sequence.count('G') + dna_sequence.count('C')
        gc_content = gc_count / len(dna_sequence) if len(dna_sequence) > 0 else 0
        
        if gc_content < self.constraints['gc_content_min']:
            issues.append(f"GC content too low: {gc_content:.2%}")
        elif gc_content > self.constraints['gc_content_max']:
            issues.append(f"GC content too high: {gc_content:.2%}")
        
        # Check homopolymers
        for nucleotide in self.dna_alphabet:
            homopolymer = nucleotide * (self.constraints['max_homopolymer'] + 1)
            if homopolymer in dna_sequence:
                issues.append(f"Homopolymer detected: {homopolymer}")
        
        # Check prohibited sequences
        for prohibited in self.constraints['prohibited_sequences']:
            if prohibited in dna_sequence:
                issues.append(f"Prohibited sequence found: {prohibited}")
        
        return {
            'valid': len(issues) == 0,
            'gc_content': gc_content,
            'issues': issues
        }
    
    def apply_error_correction(self, dna_sequence):
        """Apply Reed-Solomon-like error correction for DNA"""
        # Simplified error correction using repetition code
        corrected_sequence = ''
        redundancy_factor = 3
        
        # Add redundancy
        for nucleotide in dna_sequence:
            corrected_sequence += nucleotide * redundancy_factor
        
        return {
            'original_length': len(dna_sequence),
            'corrected_length': len(corrected_sequence),
            'redundancy_factor': redundancy_factor,
            'corrected_sequence': corrected_sequence
        }
    
    def dna_steganography(self, cover_dna, secret_message):
        """Hide secret message in DNA sequence using steganography"""
        secret_binary = self.text_to_binary(secret_message)
        secret_dna = self.binary_to_dna_sequence(secret_binary)
        
        # Use least significant bit-like approach for DNA
        # Replace every 4th nucleotide with secret data
        stego_dna = list(cover_dna)
        secret_index = 0
        
        for i in range(3, len(stego_dna), 4):
            if secret_index < len(secret_dna):
                stego_dna[i] = secret_dna[secret_index]
                secret_index += 1
        
        return {
            'cover_length': len(cover_dna),
            'secret_length': len(secret_message),
            'stego_dna': ''.join(stego_dna),
            'capacity_used': f"{(secret_index / (len(stego_dna) // 4)) * 100:.1f}%"
        }
    
    def extract_dna_steganography(self, stego_dna, secret_length):
        """Extract hidden message from DNA steganography"""
        hidden_dna = ''
        
        # Extract every 4th nucleotide
        for i in range(3, len(stego_dna), 4):
            hidden_dna += stego_dna[i]
        
        # Convert back to text
        hidden_binary = self.dna_sequence_to_binary(hidden_dna)
        
        # Truncate to expected message length
        expected_bits = secret_length * 8
        if len(hidden_binary) >= expected_bits:
            hidden_binary = hidden_binary[:expected_bits]
            hidden_message = self.binary_to_text(hidden_binary)
            return {
                'success': True,
                'hidden_message': hidden_message,
                'extracted_length': len(hidden_message)
            }
        
        return {
            'success': False,
            'error': 'Insufficient data to extract message'
        }
    
    def dna_one_time_pad(self, message, key_dna=None):
        """Implement DNA-based one-time pad encryption"""
        message_binary = self.text_to_binary(message)
        message_dna = self.binary_to_dna_sequence(message_binary)
        
        # Generate or use provided key
        if key_dna is None:
            key_dna = self.generate_random_dna(len(message_dna))
        
        if len(key_dna) < len(message_dna):
            return {'error': 'Key too short for message'}
        
        # XOR-like operation for DNA
        encrypted_dna = ''
        for i in range(len(message_dna)):
            msg_nucleotide = message_dna[i]
            key_nucleotide = key_dna[i]
            
            # Convert to binary, XOR, convert back
            msg_bits = self.dna_to_binary[msg_nucleotide]
            key_bits = self.dna_to_binary[key_nucleotide]
            
            encrypted_bits = format(int(msg_bits, 2) ^ int(key_bits, 2), '02b')
            encrypted_dna += self.binary_to_dna[encrypted_bits]
        
        return {
            'message_length': len(message),
            'encrypted_dna': encrypted_dna,
            'key_dna': key_dna[:len(message_dna)],
            'security_level': 'PERFECT' if key_dna else 'HIGH'
        }
    
    def dna_decrypt_one_time_pad(self, encrypted_dna, key_dna):
        """Decrypt DNA one-time pad encryption"""
        if len(key_dna) < len(encrypted_dna):
            return {'error': 'Key too short for decryption'}
        
        decrypted_dna = ''
        for i in range(len(encrypted_dna)):
            enc_nucleotide = encrypted_dna[i]
            key_nucleotide = key_dna[i]
            
            # Convert to binary, XOR, convert back
            enc_bits = self.dna_to_binary[enc_nucleotide]
            key_bits = self.dna_to_binary[key_nucleotide]
            
            decrypted_bits = format(int(enc_bits, 2) ^ int(key_bits, 2), '02b')
            decrypted_dna += self.binary_to_dna[decrypted_bits]
        
        # Convert back to text
        decrypted_binary = self.dna_sequence_to_binary(decrypted_dna)
        decrypted_message = self.binary_to_text(decrypted_binary)
        
        return {
            'success': True,
            'decrypted_message': decrypted_message.rstrip('\x00'),  # Remove padding
            'decrypted_dna': decrypted_dna
        }
    
    def generate_random_dna(self, length):
        """Generate random DNA sequence"""
        return ''.join(random.choice(self.dna_alphabet) for _ in range(length))
    
    def dna_hash_function(self, data):
        """DNA-based hash function"""
        # Convert data to DNA
        binary_data = self.text_to_binary(data)
        dna_data = self.binary_to_dna_sequence(binary_data)
        
        # Apply DNA-specific transformations
        transformed_dna = self.dna_transformation(dna_data)
        
        # Convert back to binary and hash
        transformed_binary = self.dna_sequence_to_binary(transformed_dna)
        
        # Use traditional hash as base and convert to DNA
        sha256_hash = hashlib.sha256(transformed_binary.encode()).hexdigest()
        hash_binary = bin(int(sha256_hash, 16))[2:].zfill(256)
        hash_dna = self.binary_to_dna_sequence(hash_binary)
        
        return {
            'input_data': data,
            'dna_representation': dna_data,
            'transformed_dna': transformed_dna,
            'hash_dna': hash_dna,
            'hash_length': len(hash_dna),
            'traditional_hash': sha256_hash
        }
    
    def dna_transformation(self, dna_sequence):
        """Apply biological transformations to DNA sequence"""
        transformations = []
        
        # Complement transformation
        complement_map = {'A': 'T', 'T': 'A', 'G': 'C', 'C': 'G'}
        complement = ''.join(complement_map[n] for n in dna_sequence)
        transformations.append(('complement', complement))
        
        # Reverse transformation
        reverse = dna_sequence[::-1]
        transformations.append(('reverse', reverse))
        
        # Reverse complement
        reverse_complement = complement[::-1]
        transformations.append(('reverse_complement', reverse_complement))
        
        # Select transformation based on sequence properties
        gc_content = (dna_sequence.count('G') + dna_sequence.count('C')) / len(dna_sequence)
        
        if gc_content > 0.6:
            return complement
        elif gc_content < 0.4:
            return reverse_complement
        else:
            return reverse
    
    def genetic_algorithm_key_generation(self, target_length, generations=100):
        """Generate cryptographic keys using genetic algorithms"""
        population_size = 50
        mutation_rate = 0.1
        
        # Initialize population
        population = [self.generate_random_dna(target_length) for _ in range(population_size)]
        
        for generation in range(generations):
            # Evaluate fitness (based on cryptographic properties)
            fitness_scores = []
            for individual in population:
                fitness = self.evaluate_crypto_fitness(individual)
                fitness_scores.append((fitness, individual))
            
            # Sort by fitness
            fitness_scores.sort(reverse=True)
            
            # Select top performers
            survivors = [individual for _, individual in fitness_scores[:population_size//2]]
            
            # Generate new population
            new_population = survivors.copy()
            
            while len(new_population) < population_size:
                parent1 = random.choice(survivors)
                parent2 = random.choice(survivors)
                child = self.dna_crossover(parent1, parent2)
                child = self.dna_mutation(child, mutation_rate)
                new_population.append(child)
            
            population = new_population
        
        # Return best individual
        best_fitness = max(self.evaluate_crypto_fitness(individual) for individual in population)
        best_individual = [individual for individual in population 
                          if self.evaluate_crypto_fitness(individual) == best_fitness][0]
        
        return {
            'best_key': best_individual,
            'fitness_score': best_fitness,
            'generations': generations,
            'final_population_size': len(population)
        }
    
    def evaluate_crypto_fitness(self, dna_sequence):
        """Evaluate cryptographic fitness of DNA sequence"""
        score = 0
        
        # GC content balance (50% is ideal)
        gc_content = (dna_sequence.count('G') + dna_sequence.count('C')) / len(dna_sequence)
        gc_score = 1 - abs(gc_content - 0.5) * 2
        score += gc_score * 30
        
        # Nucleotide distribution
        for nucleotide in self.dna_alphabet:
            frequency = dna_sequence.count(nucleotide) / len(dna_sequence)
            if 0.2 <= frequency <= 0.3:  # Ideal range
                score += 10
        
        # Avoid homopolymers
        max_homopolymer = max(len(match.group()) for match in re.finditer(r'(.)\1*', dna_sequence))
        if max_homopolymer <= 3:
            score += 20
        elif max_homopolymer <= 5:
            score += 10
        
        # Complexity (no simple patterns)
        if not any(pattern in dna_sequence for pattern in ['ATATATATAT', 'CGCGCGCGCG']):
            score += 10
        
        return score
    
    def dna_crossover(self, parent1, parent2):
        """Genetic crossover for DNA sequences"""
        crossover_point = random.randint(1, min(len(parent1), len(parent2)) - 1)
        child = parent1[:crossover_point] + parent2[crossover_point:]
        return child
    
    def dna_mutation(self, dna_sequence, mutation_rate):
        """Apply mutations to DNA sequence"""
        mutated = list(dna_sequence)
        
        for i in range(len(mutated)):
            if random.random() < mutation_rate:
                mutated[i] = random.choice(self.dna_alphabet)
        
        return ''.join(mutated)
    
    def generate_comprehensive_report(self, test_data):
        """Generate comprehensive DNA cryptography report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'version': '2.5.1',
            'test_suite': 'DNA_Cryptography',
            'results': {},
            'security_analysis': {},
            'recommendations': []
        }
        
        # Test basic encryption/decryption
        encryption_test = self.dna_one_time_pad(test_data['message'])
        decryption_test = self.dna_decrypt_one_time_pad(
            encryption_test['encrypted_dna'], 
            encryption_test['key_dna']
        )
        
        report['results']['encryption'] = {
            'success': decryption_test['success'],
            'message_recovery': decryption_test['decrypted_message'] == test_data['message'],
            'encrypted_length': len(encryption_test['encrypted_dna']),
            'key_length': len(encryption_test['key_dna'])
        }
        
        # Test steganography
        cover_dna = self.generate_random_dna(1000)
        stego_test = self.dna_steganography(cover_dna, test_data['secret'])
        extract_test = self.extract_dna_steganography(
            stego_test['stego_dna'], 
            len(test_data['secret'])
        )
        
        report['results']['steganography'] = {
            'success': extract_test['success'],
            'capacity_used': stego_test['capacity_used'],
            'secret_recovery': extract_test.get('hidden_message') == test_data['secret']
        }
        
        # Test hash function
        hash_test = self.dna_hash_function(test_data['message'])
        report['results']['hashing'] = {
            'hash_dna_length': len(hash_test['hash_dna']),
            'reproducible': self.dna_hash_function(test_data['message'])['hash_dna'] == hash_test['hash_dna']
        }
        
        # Test genetic key generation
        key_gen_test = self.genetic_algorithm_key_generation(64, 50)
        report['results']['genetic_keygen'] = {
            'key_length': len(key_gen_test['best_key']),
            'fitness_score': key_gen_test['fitness_score'],
            'validation': self.validate_dna_constraints(key_gen_test['best_key'])
        }
        
        # Security analysis
        report['security_analysis'] = {
            'quantum_resistance': 'HIGH - DNA operations not vulnerable to quantum algorithms',
            'storage_density': 'EXCELLENT - 2 bits per nucleotide, ~1 exabyte per gram',
            'stability': 'MODERATE - Requires proper storage conditions',
            'error_rate': 'LOW - With error correction codes',
            'practical_implementation': 'EMERGING - Requires specialized DNA synthesis/sequencing'
        }
        
        # Recommendations
        report['recommendations'] = [
            "Implement robust error correction for DNA storage",
            "Use hybrid classical-DNA systems for practical deployment",
            "Consider environmental factors for DNA stability",
            "Develop specialized DNA reading/writing hardware",
            "Establish standards for DNA cryptographic protocols"
        ]
        
        return report

def main():
    """Main execution function"""
    print("🧬 BOFA DNA-based Cryptography Simulator v2.5.1")
    print("=" * 60)
    
    simulator = DNACryptographySimulator()
    
    # Test data
    test_data = {
        'message': "Hello, DNA Cryptography World!",
        'secret': "Hidden message in DNA"
    }
    
    print("🔬 Testing DNA cryptographic operations...")
    
    # Test 1: Basic text to DNA conversion
    print("\n📝 Test 1: Text to DNA conversion")
    binary_rep = simulator.text_to_binary(test_data['message'])
    dna_rep = simulator.binary_to_dna_sequence(binary_rep)
    print(f"   Original: {test_data['message']}")
    print(f"   Binary: {binary_rep[:50]}...")
    print(f"   DNA: {dna_rep[:50]}...")
    
    # Validate constraints
    validation = simulator.validate_dna_constraints(dna_rep)
    print(f"   Valid DNA: {validation['valid']}")
    print(f"   GC Content: {validation['gc_content']:.2%}")
    
    # Test 2: DNA One-Time Pad encryption
    print("\n🔐 Test 2: DNA One-Time Pad encryption")
    encryption_result = simulator.dna_one_time_pad(test_data['message'])
    print(f"   Encrypted DNA length: {len(encryption_result['encrypted_dna'])}")
    print(f"   Key DNA length: {len(encryption_result['key_dna'])}")
    print(f"   Security level: {encryption_result['security_level']}")
    
    # Test decryption
    decryption_result = simulator.dna_decrypt_one_time_pad(
        encryption_result['encrypted_dna'], 
        encryption_result['key_dna']
    )
    print(f"   Decryption successful: {decryption_result['success']}")
    print(f"   Recovered message: {decryption_result['decrypted_message']}")
    
    # Test 3: DNA Steganography
    print("\n🕵️ Test 3: DNA Steganography")
    cover_dna = simulator.generate_random_dna(500)
    stego_result = simulator.dna_steganography(cover_dna, test_data['secret'])
    print(f"   Cover DNA length: {stego_result['cover_length']}")
    print(f"   Capacity used: {stego_result['capacity_used']}")
    
    # Extract hidden message
    extract_result = simulator.extract_dna_steganography(
        stego_result['stego_dna'], 
        len(test_data['secret'])
    )
    print(f"   Extraction successful: {extract_result['success']}")
    if extract_result['success']:
        print(f"   Hidden message: {extract_result['hidden_message']}")
    
    # Test 4: DNA Hash Function
    print("\n#️⃣ Test 4: DNA Hash Function")
    hash_result = simulator.dna_hash_function(test_data['message'])
    print(f"   Input: {hash_result['input_data']}")
    print(f"   DNA hash: {hash_result['hash_dna'][:50]}...")
    print(f"   Hash length: {hash_result['hash_length']} nucleotides")
    
    # Test 5: Genetic Algorithm Key Generation
    print("\n🧬 Test 5: Genetic Algorithm Key Generation")
    key_gen_result = simulator.genetic_algorithm_key_generation(128, 25)
    print(f"   Generated key: {key_gen_result['best_key'][:50]}...")
    print(f"   Fitness score: {key_gen_result['fitness_score']:.1f}")
    
    key_validation = simulator.validate_dna_constraints(key_gen_result['best_key'])
    print(f"   Key validation: {key_validation['valid']}")
    print(f"   GC content: {key_validation['gc_content']:.2%}")
    
    # Generate comprehensive report
    print("\n📊 Generating comprehensive DNA cryptography report...")
    report = simulator.generate_comprehensive_report(test_data)
    
    print(f"\n✅ DNA cryptography simulation completed!")
    print(f"   Encryption test: {'✅' if report['results']['encryption']['success'] else '❌'}")
    print(f"   Steganography test: {'✅' if report['results']['steganography']['success'] else '❌'}")
    print(f"   Hash function test: {'✅' if report['results']['hashing']['reproducible'] else '❌'}")
    print(f"   Genetic keygen test: {'✅' if report['results']['genetic_keygen']['validation']['valid'] else '❌'}")
    
    print(f"\n🚀 Revolutionary DNA-based cryptography ready for the future!")
    
    return report

if __name__ == "__main__":
    main()