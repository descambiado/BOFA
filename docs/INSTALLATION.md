# 📦 BOFA v2.5.1 Installation Guide

Complete installation guide for BOFA Extended Systems v2.5.1 - Professional Cybersecurity Platform

## 🔧 Prerequisites

### Operating Systems
- **Linux**: Ubuntu 20.04+, Debian 11+, CentOS 8+, Arch Linux
- **macOS**: macOS 11.0+ (Big Sur or later)
- **Windows**: Windows 10/11 with WSL2 (recommended) or native Windows

### Required Software
- **Docker**: Version 20.10+ and Docker Compose v2.0+
- **Node.js**: Version 18.0+ (for web interface)
- **Python**: Version 3.8+ (for CLI tools)
- **Git**: Latest version for repository cloning

### Minimum Hardware
- **RAM**: 4GB (8GB recommended for labs)
- **Storage**: 10GB free space (20GB for full lab environments)
- **Processor**: x64 architecture, 2+ cores
- **Network**: Internet connection for initial setup

## 🐳 Method 1: Docker Installation (Recommended)

### Step 1: System Preparation
```bash
# Update system packages
# Ubuntu/Debian
sudo apt update && sudo apt upgrade -y

# CentOS/RHEL/Fedora  
sudo dnf update -y

# macOS (with Homebrew)
brew update && brew upgrade
```

### Step 2: Docker Installation
```bash
# Ubuntu/Debian
sudo apt install docker.io docker-compose-plugin -y
sudo systemctl enable --now docker
sudo usermod -aG docker $USER

# CentOS/RHEL/Fedora
sudo dnf install docker docker-compose -y
sudo systemctl enable --now docker
sudo usermod -aG docker $USER

# macOS - Install Docker Desktop
# Download from: https://docs.docker.com/desktop/mac/install/

# Windows - Install Docker Desktop with WSL2
# Download from: https://docs.docker.com/desktop/windows/install/
```

### Step 3: Clone and Deploy BOFA
```bash
# Clone the repository
git clone https://github.com/descambiado/BOFA
cd BOFA

# Create environment file (optional)
cp .env.template .env
# Edit .env with your preferred settings

# Deploy BOFA platform (lightweight by default)
docker-compose up --build -d

# Verify deployment
docker-compose ps
docker-compose logs -f frontend api
```

### Step 4: Access the Platform
- **Web Interface**: http://localhost:3000
- **API Documentation**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

### Default Credentials
```
Username: admin
Password: admin123

Username: redteam  
Password: red123

Username: blueteam
Password: blue123
```

## 💻 Method 2: Local Development Installation

### Step 1: Install Dependencies
```bash
# Node.js (via NodeSource - Ubuntu/Debian)
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Python 3.8+ (Ubuntu/Debian)
sudo apt install python3 python3-pip python3-venv -y

# macOS
brew install node python3

# Windows (use Chocolatey or manual installation)
# Node.js: https://nodejs.org/en/download/
# Python: https://python.org/downloads/
```

### Step 2: Setup Frontend
```bash
# Clone repository
git clone https://github.com/descambiado/BOFA
cd BOFA

# Install frontend dependencies
npm install

# Start development server
npm run dev

# Access web interface: http://localhost:5173
```

### Step 3: Setup CLI Tools (Optional)
```bash
# Create Python virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install Python dependencies
pip install -r requirements.txt

# Test CLI
python3 cli/bofa_cli.py
# Or use the convenience script
./bofa.sh
```

## 🧪 Optional Features

### Integración MCP (Cursor y otros clientes)
Para usar BOFA como backend de herramientas desde Cursor u otros clientes MCP:
```bash
pip install .[mcp]
python3 mcp/bofa_mcp.py   # arranca el servidor (stdio)
```
Configuración: copia `.cursor/mcp.json.example` a `.cursor/mcp.json` y sustituye `ABSOLUTE_PATH_TO_BOFA` por la ruta real. Ver [MCP_CURSOR_INTEGRATION.md](MCP_CURSOR_INTEGRATION.md).

### Enable Labs
```bash
# Start web security lab
docker-compose --profile labs up web-security-lab -d

# Start all labs
docker-compose --profile labs up -d
```

### Enable Monitoring
```bash
# Start monitoring stack (Grafana + Prometheus)
docker-compose --profile monitoring up -d

# Access Grafana: http://localhost:3001 (admin/bofa123)
```

### Enable Advanced Database
```bash
# Use PostgreSQL instead of SQLite
docker-compose --profile database up -d
```

## Verificacion de instalacion

### Verify Web Interface
```bash
# Check frontend
curl -f http://localhost:3000 || echo "Frontend not accessible"

# Check API
curl -f http://localhost:8000/health || echo "API not accessible"

# Check authentication
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}' || echo "Auth not working"
```

### Verify CLI Tools
```bash
# Test CLI
python3 cli/bofa_cli.py --help || echo "CLI not working"

# Test script execution
python3 scripts/blue/ai_threat_hunter.py --help || echo "Scripts not accessible"
```

## 🔧 Troubleshooting

### Port Conflicts
```bash
# Check what's using port 3000
sudo netstat -tulpn | grep :3000

# Change ports in docker-compose.yml if needed
```

### Docker Permission Issues
```bash
# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker  # Or logout and login again
```

### Memory Issues
```bash
# Clean up Docker resources
docker system prune -f

# Increase Docker memory (Docker Desktop)
# Settings > Resources > Advanced > Memory
```

## 📞 Support

For issues, consult:
- **GitHub Issues**: [Report Problems](https://github.com/descambiado/BOFA/issues)
- **Documentation**: [Usage Guide](USAGE.md)
- **Email**: david@descambiado.com

---

**Installation complete! 🎉**

Access your BOFA platform at http://localhost:3000