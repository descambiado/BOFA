# 🤝 Contributing to BOFA v2.8.0

Thank you for your interest in contributing to BOFA Extended Systems! This guide will help you get started with contributing to our professional cybersecurity platform.

## 🎯 Ways to Contribute

### 🐛 Bug Reports and Feature Requests
- **GitHub Issues**: [Report bugs or request features](https://github.com/descambiado/BOFA/issues)
- **Good first issues**: [Issues con etiqueta good-first-issue](https://github.com/descambiado/BOFA/issues?q=is%3Aissue+is%3Aopen+label%3Agood-first-issue) — ideal para empezar.
- **Security Issues**: Email david@descambiado.com for security vulnerabilities

### ✨ Code Contributions
- **New Security Tools**: Add scripts to appropriate modules
- **Web Interface**: Improve React/TypeScript frontend
- **CLI Improvements**: Enhance Python CLI interface
- **Documentation**: Improve guides and references

### 🧪 Lab Environments
- **New Labs**: Create Docker-based security environments
- **Lab Improvements**: Enhance existing lab scenarios

## 🚀 Getting Started

### 1. Fork and Clone
```bash
git clone https://github.com/yourusername/BOFA
cd BOFA
git checkout -b feature/your-feature-name
```

### 2. Development Setup
```bash
# Frontend development
npm install
npm run dev

# CLI development
pip install -r requirements.txt
python3 cli/bofa_cli.py
```

### 3. Add Your Contribution
- Follow existing code patterns
- Add proper documentation
- Include usage examples
- Test thoroughly

### 4. Submit Pull Request
- Clear description of changes
- Reference related issues
- Include testing instructions

## 📋 Standards

### Python Code (CLI Tools)
- **Style**: Follow PEP 8
- **Documentation**: Comprehensive docstrings
- **Testing**: Include test cases when possible
- **Dependencies**: Minimize external requirements

### TypeScript/React (Web Interface)
- **Style**: ESLint + Prettier configuration
- **Components**: Reusable, well-documented components
- **Accessibility**: WCAG compliance
- **Performance**: Optimize bundle size

### Security Tools
- **Ethical Use**: Educational and authorized testing only
- **Documentation**: Clear usage instructions and warnings
- **Parameters**: Flexible configuration options
- **Output**: Structured, parseable results

## 🛡️ Security Guidelines

### Responsible Development
- **No Malicious Code**: Tools must be for educational/defensive use
- **Clear Warnings**: Include ethical usage guidelines
- **Safe Defaults**: Prevent accidental misuse
- **Documentation**: Explain security implications

## 📞 Community

- **Discord**: [BOFA Security Community](https://discord.gg/bofa-security)
- **Email**: david@descambiado.com
- **GitHub Discussions**: Use for questions and ideas

Thank you for contributing to cybersecurity education! 🛡️
