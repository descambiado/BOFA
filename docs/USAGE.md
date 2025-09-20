# 📖 BOFA v2.5.1 Usage Guide

Complete guide for using BOFA Extended Systems v2.5.1 - Professional Cybersecurity Platform

## 🎯 Platform Overview

BOFA provides three main interfaces:
1. **Web Interface** - Educational platform for learning and exploring
2. **CLI Interface** - Professional tools for real security operations  
3. **Labs Interface** - Hands-on practical testing environments

## 🌐 Web Interface

### Getting Started
1. **Access**: http://localhost:3000
2. **Login**: Use provided credentials or register new account
3. **Navigation**: Use sidebar to explore different sections

### Scripts Library
The heart of the educational platform:

#### Browsing Scripts
- **Filter by Category**: Red Team, Blue Team, Purple Team, etc.
- **Search**: Find tools by name, description, or functionality
- **View Code**: Complete source code with syntax highlighting
- **Copy/Download**: Get scripts for local use

#### Understanding Tools
Each script shows:
- **Purpose**: What the tool does and why it's useful
- **Parameters**: Configuration options and requirements
- **Examples**: How to use the tool effectively
- **Learning Materials**: Educational context and explanations

## 💻 CLI Interface

### Quick Start
```bash
# Interactive menu
./bofa.sh

# Direct execution
python3 cli/bofa_cli.py

# Help
python3 cli/bofa_cli.py --help
```

### Tool Categories

#### 🔴 Red Team Tools (35+ scripts)
Offensive security and penetration testing:
```bash
# Network reconnaissance
python3 scripts/red/ghost_scanner.py -t 192.168.1.0/24

# Payload generation  
python3 scripts/red/reverse_shell_generator.py --ip 10.0.0.1 --port 4444

# Supply chain analysis
python3 scripts/red/supply_chain_scanner.py --target npm --package express
```

#### 🔵 Blue Team Tools (28+ scripts)
Defensive security and threat detection:
```bash
# AI-powered threat hunting
python3 scripts/blue/ai_threat_hunter.py --log-file /var/log/auth.log

# Real-time correlation
python3 scripts/blue/real_time_threat_correlator.py --sources syslog,network

# Zero trust validation
python3 scripts/blue/zero_trust_validator.py --network 192.168.1.0/24
```

#### 🟣 Purple Team Tools (20+ scripts)
Coordinated security exercises:
```bash
# Autonomous testing
python3 scripts/purple/autonomous_pentest_agent.py --target web

# Threat prediction
python3 scripts/purple/neural_threat_predictor.py --model lstm
```

#### 🔍 OSINT Tools (18+ scripts)
Intelligence gathering and analysis:
```bash
# Multi-source intelligence
python3 scripts/osint/multi_vector_osint.py --target example.com

# IoT device mapping
python3 scripts/osint/iot_security_mapper.py --network 192.168.1.0/24

# Repository scanning
python3 scripts/osint/github_repo_leak_detector.py --org mycompany
```

## 🧪 Lab Environments

### Available Labs

#### Web Application Security Lab
```bash
# Start lab
docker-compose --profile labs up web-security-lab -d

# Access: http://localhost:8080
# Focus: OWASP Top 10, web vulnerabilities
# Time: ~4 hours
```

#### Corporate Network Lab
```bash
# Start lab
docker-compose --profile labs up network-lab -d

# Access: SSH to localhost:2222
# Focus: Network penetration testing
# Time: ~3 hours
```

#### Android Security Lab
```bash
# Start lab
docker-compose --profile labs up android-lab -d

# Access: http://localhost:6080 (noVNC)
# Focus: Mobile application security
# Time: ~2.5 hours
```

## 📊 Best Practices

### Before Testing
1. **Get Authorization**: Only test systems you own or have permission for
2. **Read Documentation**: Understand tool capabilities and limitations
3. **Plan Approach**: Define objectives and methodology
4. **Prepare Environment**: Set up proper testing infrastructure

### During Testing
1. **Document Everything**: Keep detailed notes of findings
2. **Use Methodology**: Follow structured testing approaches
3. **Stay Legal**: Respect boundaries and permissions
4. **Monitor Impact**: Ensure testing doesn't cause damage

### After Testing
1. **Generate Reports**: Document findings and recommendations
2. **Clean Up**: Remove test artifacts and restore systems
3. **Share Knowledge**: Contribute back to the community
4. **Continue Learning**: Practice new techniques and tools

## 🔐 Security Considerations

### Data Protection
- **Encrypt Sensitive Data**: Protect credentials and findings
- **Secure Communications**: Use encrypted channels when possible
- **Access Control**: Implement proper user permissions
- **Audit Logging**: Track all security activities

### Ethical Guidelines
- **Responsible Disclosure**: Report vulnerabilities ethically
- **Minimize Impact**: Avoid disrupting production systems
- **Respect Privacy**: Protect personal and confidential information
- **Follow Laws**: Comply with local and international regulations

## 🆘 Troubleshooting

### Common Issues

#### Web Interface Problems
```bash
# Check service status
docker-compose ps

# View logs
docker-compose logs frontend api

# Restart services
docker-compose restart
```

#### CLI Script Issues
```bash
# Fix permissions
chmod +x scripts/category/script.py

# Install dependencies
pip install -r requirements.txt

# Check Python path
export PYTHONPATH="/path/to/BOFA:$PYTHONPATH"
```

#### Lab Environment Issues
```bash
# Check lab status
docker-compose --profile labs ps

# View lab logs
docker-compose --profile labs logs lab-name

# Clean and restart
docker-compose --profile labs down && docker-compose --profile labs up -d
```

### Performance Optimization
```bash
# Clean Docker resources
docker system prune -f

# Monitor resource usage
docker stats

# Optimize script parameters
python3 scripts/recon/web_discover.py --threads 10 --timeout 30
```

## 📈 Advanced Usage

### Automation Scripts
```bash
# Batch execution
cat > batch_scan.sh << EOF
#!/bin/bash
python3 scripts/recon/web_discover.py -d example.com
python3 scripts/red/ghost_scanner.py -t 192.168.1.0/24
python3 scripts/blue/ai_threat_hunter.py --log-file results.log
EOF

chmod +x batch_scan.sh
./batch_scan.sh
```

### Report Generation
```bash
# HTML reports
python3 scripts/blue/ai_threat_hunter.py --report-format html > report.html

# JSON output for automation
python3 scripts/osint/multi_vector_osint.py --output json > data.json

# PDF reports (when supported)
python3 scripts/red/ghost_scanner.py --report-format pdf
```

### Integration with Other Tools
```bash
# Export to SIEM
python3 scripts/blue/log_guardian.py --output syslog --destination 192.168.1.100

# Import threat intelligence
python3 scripts/blue/real_time_threat_correlator.py --import-iocs threats.json

# API integration
curl -X POST http://localhost:8000/execute \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"module":"red","script":"ghost_scanner","parameters":{"target":"192.168.1.0/24"}}'
```

## 🎓 Learning Resources

### Beginner Path
1. Start with Web Interface to explore tools
2. Try basic OSINT and reconnaissance tools
3. Practice with Web Security Lab
4. Learn defensive techniques with Blue Team tools

### Intermediate Path  
1. Master CLI interface and automation
2. Explore Purple Team coordination tools
3. Practice with multiple lab environments
4. Develop custom scripts and modifications

### Advanced Path
1. Contribute new tools and techniques
2. Research cutting-edge security methods
3. Integrate with enterprise security tools
4. Mentor others in the community

## 📞 Getting Help

### Documentation
- **Installation Guide**: [INSTALLATION.md](INSTALLATION.md)
- **API Reference**: [api/README.md](../api/README.md)
- **CLI Reference**: [cli/README.md](../cli/README.md)

### Community Support
- **GitHub Issues**: [Report problems](https://github.com/descambiado/BOFA/issues)
- **Discord**: [Join community](https://discord.gg/bofa-security)  
- **Email**: david@descambiado.com

### Professional Services
- **Training**: Corporate cybersecurity programs
- **Consulting**: Security assessments and implementation
- **Custom Development**: Tailored solutions

---

**Master cybersecurity with BOFA! 🛡️**

Continue exploring, learning, and securing the digital world responsibly.