
#!/bin/bash

# BOFA Universal Launcher
# Funciona en Windows (Git Bash), WSL2, y Linux nativo
# Desarrollado por @descambiado

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Detectar entorno
detect_environment() {
    if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
        ENVIRONMENT="Git Bash"
        OS_TYPE="windows"
    elif [[ -n "$WSL_DISTRO_NAME" ]] || grep -qi microsoft /proc/version 2>/dev/null; then
        ENVIRONMENT="WSL2"
        OS_TYPE="wsl"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        ENVIRONMENT="Linux"
        OS_TYPE="linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        ENVIRONMENT="macOS"
        OS_TYPE="macos"
    else
        ENVIRONMENT="Unix"
        OS_TYPE="unix"
    fi
}

print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════╗"
    echo "║           BOFA Universal Launcher        ║"
    echo "║         Desarrollado por @descambiado    ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${YELLOW}🖥️  Entorno detectado: $ENVIRONMENT${NC}"
}

check_python() {
    if command -v python3 &> /dev/null; then
        PYTHON_CMD="python3"
        echo -e "${GREEN}✅ Python3 encontrado${NC}"
    elif command -v python &> /dev/null; then
        PYTHON_CMD="python"
        echo -e "${GREEN}✅ Python encontrado${NC}"
    else
        echo -e "${RED}❌ Python no encontrado${NC}"
        show_install_help
        exit 1
    fi
}

check_docker() {
    if command -v docker &> /dev/null; then
        if docker info &> /dev/null; then
            DOCKER_AVAILABLE=true
            echo -e "${GREEN}✅ Docker disponible${NC}"
        else
            DOCKER_AVAILABLE=false
            echo -e "${YELLOW}⚠️  Docker instalado pero no corriendo${NC}"
        fi
    else
        DOCKER_AVAILABLE=false
        echo -e "${YELLOW}⚠️  Docker no encontrado${NC}"
    fi
}

show_install_help() {
    echo -e "${CYAN}💡 Ayuda de instalación para $ENVIRONMENT:${NC}"
    
    case $OS_TYPE in
        "windows")
            echo "  • Instala Python desde: https://python.org/downloads"
            echo "  • O desde Microsoft Store: Python 3.11"
            echo "  • Para Docker: https://docker.com/products/docker-desktop"
            ;;
        "wsl"|"linux")
            echo "  • Ubuntu/Debian: sudo apt install python3 python3-pip"
            echo "  • Fedora: sudo dnf install python3 python3-pip"  
            echo "  • Arch: sudo pacman -S python python-pip"
            echo "  • Para Docker: curl -fsSL https://get.docker.com | sh"
            ;;
        "macos")
            echo "  • Instala Python: brew install python3"
            echo "  • Para Docker: https://docker.com/products/docker-desktop"
            ;;
    esac
}

install_dependencies() {
    echo -e "${YELLOW}📦 Instalando dependencias Python...${NC}"
    
    if [[ -f "cli/requirements.txt" ]]; then
        $PYTHON_CMD -m pip install --user -r cli/requirements.txt
        echo -e "${GREEN}✅ Dependencias instaladas${NC}"
    else
        echo -e "${YELLOW}⚠️  Archivo requirements.txt no encontrado${NC}"
    fi
}

show_menu() {
    echo -e "${CYAN}"
    echo "┌─────────────────────────────────────────┐"
    echo "│              MODO DE EJECUCIÓN          │"
    echo "├─────────────────────────────────────────┤"
    echo "│                                         │"
    echo "│  [1] 🖥️  CLI Directo (Python)           │"
    echo "│  [2] 🐳 Docker Compose (Completo)       │"
    echo "│  [3] ⚙️  Instalar Dependencias          │"
    echo "│  [4] 📊 Ver Estado del Sistema          │"
    echo "│  [0] 🚪 Salir                           │"
    echo "│                                         │"
    echo "└─────────────────────────────────────────┘"
    echo -e "${NC}"
}

run_cli() {
    echo -e "${CYAN}🚀 Iniciando BOFA CLI...${NC}"
    cd "$(dirname "$0")"
    
    if [[ ! -f "cli/bo
fa_cli.py" ]]; then
        echo -e "${RED}❌ Error: cli/bofa_cli.py no encontrado${NC}"
        exit 1
    fi
    
    $PYTHON_CMD cli/bofa_cli.py
}

run_docker() {
    if [[ "$DOCKER_AVAILABLE" != true ]]; then
        echo -e "${RED}❌ Docker no está disponible${NC}"
        echo -e "${YELLOW}💡 Inicia Docker Desktop o instala Docker${NC}"
        return 1
    fi
    
    echo -e "${CYAN}🐳 Iniciando BOFA con Docker...${NC}"
    cd "$(dirname "$0")"
    
    if [[ ! -f "docker-compose.yml" ]]; then
        echo -e "${RED}❌ Error: docker-compose.yml no encontrado${NC}"
        return 1
    fi
    
    # Intentar formato nuevo de docker compose
    if docker compose version &> /dev/null; then
        docker compose up --build
    elif command -v docker-compose &> /dev/null; then
        docker-compose up --build
    else
        echo -e "${RED}❌ Docker Compose no encontrado${NC}"
        return 1
    fi
}

show_system_status() {
    echo -e "${CYAN}═══════════════════════════════════════════${NC}"
    echo -e "${CYAN}           ESTADO DEL SISTEMA${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════${NC}"
    
    echo -e "${GREEN}🖥️  Sistema Operativo:${NC}"
    echo "   • Entorno: $ENVIRONMENT"
    echo "   • Tipo: $OS_TYPE"
    
    echo -e "\n${GREEN}🐍 Python:${NC}"
    if [[ -n "$PYTHON_CMD" ]]; then
        echo "   • Comando: $PYTHON_CMD"
        echo "   • Versión: $($PYTHON_CMD --version 2>/dev/null || echo 'No disponible')"
    else
        echo "   • Estado: No encontrado"
    fi
    
    echo -e "\n${GREEN}🐳 Docker:${NC}"
    if [[ "$DOCKER_AVAILABLE" == true ]]; then
        echo "   • Estado: Disponible y corriendo"
        echo "   • Versión: $(docker --version 2>/dev/null || echo 'No disponible')"
    else
        echo "   • Estado: No disponible"
    fi
    
    echo -e "\n${GREEN}📁 Archivos BOFA:${NC}"
    echo "   • CLI: $([ -f 'cli/bofa_cli.py' ] && echo '✅' || echo '❌') cli/bofa_cli.py"
    echo "   • Docker: $([ -f 'docker-compose.yml' ] && echo '✅' || echo '❌') docker-compose.yml"
    echo "   • Scripts: $([ -d 'scripts' ] && echo "✅ $(find scripts -name '*.py' -o -name '*.sh' | wc -l) archivos" || echo '❌')"
    
    read -p "Presiona Enter para continuar..."
}

main() {
    detect_environment
    print_banner
    check_python
    check_docker
    
    while true; do
        echo
        show_menu
        
        read -p "Selecciona una opción [0-4]: " choice
        
        case $choice in
            1)
                run_cli
                ;;
            2)
                run_docker
                ;;
            3)
                install_dependencies
                ;;
            4)
                show_system_status
                ;;
            0)
                echo -e "${CYAN}👋 ¡Hasta la próxima!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}❌ Opción inválida${NC}"
                ;;
        esac
        
        echo
        read -p "Presiona Enter para continuar..."
    done
}

# Manejo de errores y señales
trap 'echo -e "\n${YELLOW}⚠️  Operación cancelada${NC}"; exit 1' INT TERM

main "$@"
