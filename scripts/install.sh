#!/bin/bash

# BOFA Extended Systems v2.5.0 - Installation Script
# Automated installation for Linux/macOS systems

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
NC='\033[0m' # No Color

# ASCII Art
echo -e "${GREEN}"
cat << "EOF"
██████╗  ██████╗ ███████╗ █████╗     ██╗   ██╗██████╗ ██╗███████╗ ██████╗ 
██╔══██╗██╔═══██╗██╔════╝██╔══██╗    ██║   ██║╚════██╗██║██╔════╝██╔═████╗
██████╔╝██║   ██║█████╗  ███████║    ██║   ██║ █████╔╝██║███████╗██║██╔██║
██╔══██╗██║   ██║██╔══╝  ██╔══██║    ╚██╗ ██╔╝██╔═══╝ ██║╚════██║████╔╝██║
██████╔╝╚██████╔╝██║     ██║  ██║     ╚████╔╝ ███████╗██║███████║╚██████╔╝
╚═════╝  ╚═════╝ ╚═╝     ╚═╝  ╚═╝      ╚═══╝  ╚══════╝╚═╝╚══════╝ ╚═════╝ 

                Extended Systems - Cybersecurity Platform
EOF
echo -e "${NC}"

echo -e "${BLUE}🚀 BOFA Extended Systems v2.5.0 Installation${NC}"
echo "============================================="
echo ""

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command_exists apt-get; then
            echo "ubuntu"
        elif command_exists yum; then
            echo "centos"
        elif command_exists pacman; then
            echo "arch"
        else
            echo "linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    else
        echo "unknown"
    fi
}

# Function to install Docker
install_docker() {
    local os=$1
    echo -e "${YELLOW}📦 Installing Docker...${NC}"
    
    case $os in
        "ubuntu")
            curl -fsSL https://get.docker.com -o get-docker.sh
            sudo sh get-docker.sh
            sudo usermod -aG docker $USER
            rm get-docker.sh
            ;;
        "centos")
            sudo yum update -y
            sudo yum install -y yum-utils
            sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
            sudo yum install -y docker-ce docker-ce-cli containerd.io
            sudo systemctl start docker
            sudo systemctl enable docker
            sudo usermod -aG docker $USER
            ;;
        "arch")
            sudo pacman -S docker docker-compose
            sudo systemctl start docker
            sudo systemctl enable docker
            sudo usermod -aG docker $USER
            ;;
        "macos")
            if ! command_exists brew; then
                echo -e "${RED}❌ Homebrew is required on macOS. Please install it first.${NC}"
                echo "Visit: https://brew.sh/"
                exit 1
            fi
            brew install --cask docker
            ;;
        *)
            echo -e "${RED}❌ Unsupported OS for automatic Docker installation.${NC}"
            echo "Please install Docker manually: https://docs.docker.com/get-docker/"
            exit 1
            ;;
    esac
}

# Function to install Docker Compose
install_docker_compose() {
    echo -e "${YELLOW}📦 Installing Docker Compose...${NC}"
    
    # For newer Docker versions, compose is included
    if docker compose version >/dev/null 2>&1; then
        echo -e "${GREEN}✅ Docker Compose is already available${NC}"
        return
    fi
    
    # Install standalone docker-compose
    sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
}

# Function to install Node.js
install_nodejs() {
    local os=$1
    echo -e "${YELLOW}📦 Installing Node.js...${NC}"
    
    case $os in
        "ubuntu")
            curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
            sudo apt-get install -y nodejs
            ;;
        "centos")
            curl -fsSL https://rpm.nodesource.com/setup_18.x | sudo bash -
            sudo yum install -y nodejs
            ;;
        "arch")
            sudo pacman -S nodejs npm
            ;;
        "macos")
            brew install node
            ;;
        *)
            echo -e "${YELLOW}⚠️ Please install Node.js 18+ manually${NC}"
            ;;
    esac
}

# Function to install Python
install_python() {
    local os=$1
    echo -e "${YELLOW}📦 Installing Python...${NC}"
    
    case $os in
        "ubuntu")
            sudo apt-get update
            sudo apt-get install -y python3 python3-pip python3-venv
            ;;
        "centos")
            sudo yum install -y python3 python3-pip
            ;;
        "arch")
            sudo pacman -S python python-pip
            ;;
        "macos")
            brew install python3
            ;;
        *)
            echo -e "${YELLOW}⚠️ Please install Python 3.8+ manually${NC}"
            ;;
    esac
}

# Main installation function
main() {
    local os=$(detect_os)
    echo -e "${BLUE}🔍 Detected OS: $os${NC}"
    echo ""
    
    # Check prerequisites
    echo -e "${YELLOW}🔍 Checking prerequisites...${NC}"
    
    # Check Docker
    if ! command_exists docker; then
        install_docker $os
        echo -e "${GREEN}✅ Docker installed successfully${NC}"
    else
        echo -e "${GREEN}✅ Docker is already installed${NC}"
    fi
    
    # Check Docker Compose
    if ! docker compose version >/dev/null 2>&1 && ! command_exists docker-compose; then
        install_docker_compose
        echo -e "${GREEN}✅ Docker Compose installed successfully${NC}"
    else
        echo -e "${GREEN}✅ Docker Compose is already available${NC}"
    fi
    
    # Check Node.js
    if ! command_exists node; then
        install_nodejs $os
        echo -e "${GREEN}✅ Node.js installed successfully${NC}"
    else
        local node_version=$(node --version | cut -d'v' -f2 | cut -d'.' -f1)
        if [ "$node_version" -lt 18 ]; then
            echo -e "${YELLOW}⚠️ Node.js version is too old. Installing newer version...${NC}"
            install_nodejs $os
        else
            echo -e "${GREEN}✅ Node.js is already installed ($(node --version))${NC}"
        fi
    fi
    
    # Check Python
    if ! command_exists python3; then
        install_python $os
        echo -e "${GREEN}✅ Python installed successfully${NC}"
    else
        echo -e "${GREEN}✅ Python is already installed ($(python3 --version))${NC}"
    fi
    
    echo ""
    echo -e "${BLUE}📥 Setting up BOFA...${NC}"
    
    # Create .env file from template
    if [ ! -f ".env" ]; then
        if [ -f ".env.template" ]; then
            cp .env.template .env
            echo -e "${GREEN}✅ Environment file created from template${NC}"
        else
            echo -e "${YELLOW}⚠️ .env.template not found, you may need to create .env manually${NC}"
        fi
    else
        echo -e "${GREEN}✅ Environment file already exists${NC}"
    fi
    
    # Install frontend dependencies
    if [ -f "package.json" ]; then
        echo -e "${YELLOW}📦 Installing frontend dependencies...${NC}"
        npm install
        echo -e "${GREEN}✅ Frontend dependencies installed${NC}"
    fi
    
    # Generate SSL certificates
    if [ -f "scripts/generate-ssl.sh" ]; then
        echo -e "${YELLOW}🔐 Generating SSL certificates...${NC}"
        chmod +x scripts/generate-ssl.sh
        ./scripts/generate-ssl.sh
    fi
    
    # Build and start services
    echo -e "${YELLOW}🏗️ Building and starting BOFA services...${NC}"
    docker compose up --build -d
    
    echo ""
    echo -e "${GREEN}🎉 BOFA Extended Systems v2.5.0 Installation Complete!${NC}"
    echo "========================================================="
    echo ""
    echo -e "${BLUE}🌐 Access BOFA:${NC}"
    echo "  • Frontend: http://localhost:3000"
    echo "  • API: http://localhost:8000"
    echo "  • API Docs: http://localhost:8000/docs"
    echo ""
    echo -e "${BLUE}📊 Monitoring (optional):${NC}"
    echo "  • Grafana: http://localhost:3001 (admin/bofa123)"
    echo "  • Prometheus: http://localhost:9090"
    echo ""
    echo -e "${BLUE}🔧 Useful commands:${NC}"
    echo "  • View logs: docker compose logs -f"
    echo "  • Stop services: docker compose down"
    echo "  • Restart: docker compose restart"
    echo ""
    echo -e "${YELLOW}⚠️ Note: If you were added to the docker group, you may need to log out and back in.${NC}"
    
    # Check if services are running
    echo -e "${YELLOW}🔍 Checking service status...${NC}"
    sleep 5
    if curl -s http://localhost:3000 >/dev/null; then
        echo -e "${GREEN}✅ Frontend is running${NC}"
    else
        echo -e "${RED}❌ Frontend is not responding${NC}"
    fi
    
    if curl -s http://localhost:8000/health >/dev/null; then
        echo -e "${GREEN}✅ API is running${NC}"
    else
        echo -e "${RED}❌ API is not responding${NC}"
    fi
}

# Run main function
main "$@"
# Automated installation for Linux/macOS systems

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
NC='\033[0m' # No Color

# ASCII Art
echo -e "${GREEN}"
cat << "EOF"
██████╗  ██████╗ ███████╗ █████╗     ██╗   ██╗██████╗ ██╗███████╗ ██████╗ 
██╔══██╗██╔═══██╗██╔════╝██╔══██╗    ██║   ██║╚════██╗██║██╔════╝██╔═████╗
██████╔╝██║   ██║█████╗  ███████║    ██║   ██║ █████╔╝██║███████╗██║██╔██║
██╔══██╗██║   ██║██╔══╝  ██╔══██║    ╚██╗ ██╔╝██╔═══╝ ██║╚════██║████╔╝██║
██████╔╝╚██████╔╝██║     ██║  ██║     ╚████╔╝ ███████╗██║███████║╚██████╔╝
╚═════╝  ╚═════╝ ╚═╝     ╚═╝  ╚═╝      ╚═══╝  ╚══════╝╚═╝╚══════╝ ╚═════╝ 

                Extended Systems - Cybersecurity Platform
EOF
echo -e "${NC}"

echo -e "${BLUE}🚀 BOFA Extended Systems v2.5.0 Installation${NC}"
echo "============================================="
echo ""

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command_exists apt-get; then
            echo "ubuntu"
        elif command_exists yum; then
            echo "centos"
        elif command_exists pacman; then
            echo "arch"
        else
            echo "linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    else
        echo "unknown"
    fi
}

# Function to install Docker
install_docker() {
    local os=$1
    echo -e "${YELLOW}📦 Installing Docker...${NC}"
    
    case $os in
        "ubuntu")
            curl -fsSL https://get.docker.com -o get-docker.sh
            sudo sh get-docker.sh
            sudo usermod -aG docker $USER
            rm get-docker.sh
            ;;
        "centos")
            sudo yum update -y
            sudo yum install -y yum-utils
            sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
            sudo yum install -y docker-ce docker-ce-cli containerd.io
            sudo systemctl start docker
            sudo systemctl enable docker
            sudo usermod -aG docker $USER
            ;;
        "arch")
            sudo pacman -S docker docker-compose
            sudo systemctl start docker
            sudo systemctl enable docker
            sudo usermod -aG docker $USER
            ;;
        "macos")
            if ! command_exists brew; then
                echo -e "${RED}❌ Homebrew is required on macOS. Please install it first.${NC}"
                echo "Visit: https://brew.sh/"
                exit 1
            fi
            brew install --cask docker
            ;;
        *)
            echo -e "${RED}❌ Unsupported OS for automatic Docker installation.${NC}"
            echo "Please install Docker manually: https://docs.docker.com/get-docker/"
            exit 1
            ;;
    esac
}

# Function to install Docker Compose
install_docker_compose() {
    echo -e "${YELLOW}📦 Installing Docker Compose...${NC}"
    
    # For newer Docker versions, compose is included
    if docker compose version >/dev/null 2>&1; then
        echo -e "${GREEN}✅ Docker Compose is already available${NC}"
        return
    fi
    
    # Install standalone docker-compose
    sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
}

# Function to install Node.js
install_nodejs() {
    local os=$1
    echo -e "${YELLOW}📦 Installing Node.js...${NC}"
    
    case $os in
        "ubuntu")
            curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
            sudo apt-get install -y nodejs
            ;;
        "centos")
            curl -fsSL https://rpm.nodesource.com/setup_18.x | sudo bash -
            sudo yum install -y nodejs
            ;;
        "arch")
            sudo pacman -S nodejs npm
            ;;
        "macos")
            brew install node
            ;;
        *)
            echo -e "${YELLOW}⚠️ Please install Node.js 18+ manually${NC}"
            ;;
    esac
}

# Function to install Python
install_python() {
    local os=$1
    echo -e "${YELLOW}📦 Installing Python...${NC}"
    
    case $os in
        "ubuntu")
            sudo apt-get update
            sudo apt-get install -y python3 python3-pip python3-venv
            ;;
        "centos")
            sudo yum install -y python3 python3-pip
            ;;
        "arch")
            sudo pacman -S python python-pip
            ;;
        "macos")
            brew install python3
            ;;
        *)
            echo -e "${YELLOW}⚠️ Please install Python 3.8+ manually${NC}"
            ;;
    esac
}

# Main installation function
main() {
    local os=$(detect_os)
    echo -e "${BLUE}🔍 Detected OS: $os${NC}"
    echo ""
    
    # Check prerequisites
    echo -e "${YELLOW}🔍 Checking prerequisites...${NC}"
    
    # Check Docker
    if ! command_exists docker; then
        install_docker $os
        echo -e "${GREEN}✅ Docker installed successfully${NC}"
    else
        echo -e "${GREEN}✅ Docker is already installed${NC}"
    fi
    
    # Check Docker Compose
    if ! docker compose version >/dev/null 2>&1 && ! command_exists docker-compose; then
        install_docker_compose
        echo -e "${GREEN}✅ Docker Compose installed successfully${NC}"
    else
        echo -e "${GREEN}✅ Docker Compose is already available${NC}"
    fi
    
    # Check Node.js
    if ! command_exists node; then
        install_nodejs $os
        echo -e "${GREEN}✅ Node.js installed successfully${NC}"
    else
        local node_version=$(node --version | cut -d'v' -f2 | cut -d'.' -f1)
        if [ "$node_version" -lt 18 ]; then
            echo -e "${YELLOW}⚠️ Node.js version is too old. Installing newer version...${NC}"
            install_nodejs $os
        else
            echo -e "${GREEN}✅ Node.js is already installed ($(node --version))${NC}"
        fi
    fi
    
    # Check Python
    if ! command_exists python3; then
        install_python $os
        echo -e "${GREEN}✅ Python installed successfully${NC}"
    else
        echo -e "${GREEN}✅ Python is already installed ($(python3 --version))${NC}"
    fi
    
    echo ""
    echo -e "${BLUE}📥 Setting up BOFA...${NC}"
    
    # Create .env file from template
    if [ ! -f ".env" ]; then
        if [ -f ".env.template" ]; then
            cp .env.template .env
            echo -e "${GREEN}✅ Environment file created from template${NC}"
        else
            echo -e "${YELLOW}⚠️ .env.template not found, you may need to create .env manually${NC}"
        fi
    else
        echo -e "${GREEN}✅ Environment file already exists${NC}"
    fi
    
    # Install frontend dependencies
    if [ -f "package.json" ]; then
        echo -e "${YELLOW}📦 Installing frontend dependencies...${NC}"
        npm install
        echo -e "${GREEN}✅ Frontend dependencies installed${NC}"
    fi
    
    # Generate SSL certificates
    if [ -f "scripts/generate-ssl.sh" ]; then
        echo -e "${YELLOW}🔐 Generating SSL certificates...${NC}"
        chmod +x scripts/generate-ssl.sh
        ./scripts/generate-ssl.sh
    fi
    
    # Build and start services
    echo -e "${YELLOW}🏗️ Building and starting BOFA services...${NC}"
    docker compose up --build -d
    
    echo ""
    echo -e "${GREEN}🎉 BOFA Extended Systems v2.5.0 Installation Complete!${NC}"
    echo "========================================================="
    echo ""
    echo -e "${BLUE}🌐 Access BOFA:${NC}"
    echo "  • Frontend: http://localhost:3000"
    echo "  • API: http://localhost:8000"
    echo "  • API Docs: http://localhost:8000/docs"
    echo ""
    echo -e "${BLUE}📊 Monitoring (optional):${NC}"
    echo "  • Grafana: http://localhost:3001 (admin/bofa123)"
    echo "  • Prometheus: http://localhost:9090"
    echo ""
    echo -e "${BLUE}🔧 Useful commands:${NC}"
    echo "  • View logs: docker compose logs -f"
    echo "  • Stop services: docker compose down"
    echo "  • Restart: docker compose restart"
    echo ""
    echo -e "${YELLOW}⚠️ Note: If you were added to the docker group, you may need to log out and back in.${NC}"
    
    # Check if services are running
    echo -e "${YELLOW}🔍 Checking service status...${NC}"
    sleep 5
    if curl -s http://localhost:3000 >/dev/null; then
        echo -e "${GREEN}✅ Frontend is running${NC}"
    else
        echo -e "${RED}❌ Frontend is not responding${NC}"
    fi
    
    if curl -s http://localhost:8000/health >/dev/null; then
        echo -e "${GREEN}✅ API is running${NC}"
    else
        echo -e "${RED}❌ API is not responding${NC}"
    fi
}

# Run main function
main "$@"