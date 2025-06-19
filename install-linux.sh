
#!/bin/bash

# BOFA Universal Installer for Linux (Ubuntu, Kali, Debian, etc.)
# Desarrollado por @descambiado

set -e

INSTALL_PATH="$HOME/BOFA"
SKIP_DOCKER=false
FORCE_INSTALL=false

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

print_banner() {
    echo -e "${CYAN}🛡️  BOFA Universal Installer para Linux${NC}"
    echo -e "${YELLOW}Desarrollado por @descambiado${NC}"
    echo -e "${CYAN}================================${NC}"
}

detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
        echo -e "${GREEN}✅ Distribución detectada: $PRETTY_NAME${NC}"
    else
        DISTRO="unknown"
        echo -e "${YELLOW}⚠️  No se pudo detectar la distribución${NC}"
    fi
}

check_root() {
    if [ "$EUID" -eq 0 ]; then
        echo -e "${YELLOW}⚠️  Ejecutándose como root. Se recomienda usar un usuario normal.${NC}"
        read -p "¿Continuar? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

install_dependencies() {
    echo -e "${YELLOW}📦 Instalando dependencias del sistema...${NC}"
    
    case $DISTRO in
        ubuntu|debian)
            sudo apt update
            sudo apt install -y git python3 python3-pip curl wget gnupg2 software-properties-common
            ;;
        kali)
            sudo apt update
            sudo apt install -y git python3 python3-pip curl wget
            ;;
        fedora|centos|rhel)
            sudo dnf install -y git python3 python3-pip curl wget
            ;;
        arch|manjaro)
            sudo pacman -Sy --noconfirm git python python-pip curl wget
            ;;
        *)
            echo -e "${YELLOW}⚠️  Distribución no reconocida. Instala manualmente: git, python3, python3-pip${NC}"
            ;;
    esac
}

install_docker() {
    if command -v docker &> /dev/null && docker --version &> /dev/null; then
        echo -e "${GREEN}✅ Docker ya está instalado${NC}"
        return
    fi
    
    echo -e "${YELLOW}📥 Instalando Docker...${NC}"
    
    case $DISTRO in
        ubuntu|debian)
            # Instalar Docker desde el repositorio oficial
            curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
            echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
            sudo apt update
            sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
            ;;
        kali)
            sudo apt update
            sudo apt install -y docker.io docker-compose
            ;;
        fedora)
            sudo dnf install -y docker docker-compose
            ;;
        arch|manjaro)
            sudo pacman -S --noconfirm docker docker-compose
            ;;
        *)
            echo -e "${YELLOW}⚠️  Instala Docker manualmente para tu distribución${NC}"
            return
            ;;
    esac
    
    # Configurar Docker
    sudo systemctl enable docker
    sudo systemctl start docker
    sudo usermod -aG docker $USER
    
    echo -e "${GREEN}✅ Docker instalado. Necesitas hacer logout/login para usar Docker sin sudo${NC}"
}

clone_repository() {
    echo -e "${YELLOW}📥 Clonando repositorio BOFA...${NC}"
    
    if [ -d "$INSTALL_PATH" ]; then
        if [ "$FORCE_INSTALL" = true ]; then
            rm -rf "$INSTALL_PATH"
        else
            echo -e "${YELLOW}⚠️  Directorio $INSTALL_PATH ya existe${NC}"
            read -p "¿Sobrescribir? (y/N): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                rm -rf "$INSTALL_PATH"
            else
                echo -e "${CYAN}💡 Actualizando repositorio existente...${NC}"
                cd "$INSTALL_PATH"
                git pull
                return
            fi
        fi
    fi
    
    git clone https://github.com/descambiado/BOFA.git "$INSTALL_PATH"
    cd "$INSTALL_PATH"
}

install_python_deps() {
    echo -e "${YELLOW}🐍 Instalando dependencias Python...${NC}"
    
    if [ -f "cli/requirements.txt" ]; then
        python3 -m pip install --user -r cli/requirements.txt
    fi
}

setup_docker() {
    if [ "$SKIP_DOCKER" = true ]; then
        return
    fi
    
    echo -e "${YELLOW}🐳 Configurando Docker...${NC}"
    
    # Verificar si Docker está corriendo
    if ! docker info &> /dev/null; then
        echo -e "${YELLOW}⚠️  Docker no está corriendo. Iniciando...${NC}"
        sudo systemctl start docker
        
        # Esperar a que Docker inicie
        sleep 5
        
        if ! docker info &> /dev/null; then
            echo -e "${RED}❌ No se pudo iniciar Docker${NC}"
            return
        fi
    fi
    
    echo -e "${YELLOW}🚀 Construyendo contenedores BOFA...${NC}"
    docker-compose build
    
    echo -e "${GREEN}✅ Docker configurado correctamente${NC}"
}

create_launchers() {
    echo -e "${YELLOW}📝 Creando scripts de inicio...${NC}"
    
    # Script de inicio directo
    cat > "$INSTALL_PATH/start-bofa.sh" << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
python3 cli/bofa_cli.py
EOF
    
    # Script de inicio con Docker
    cat > "$INSTALL_PATH/start-bofa-docker.sh" << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
echo "🐳 Iniciando BOFA con Docker..."
docker-compose up
EOF
    
    chmod +x "$INSTALL_PATH/start-bofa.sh"
    chmod +x "$INSTALL_PATH/start-bofa-docker.sh"
    
    # Crear enlace simbólico en PATH si es posible
    if [ -d "$HOME/.local/bin" ]; then
        mkdir -p "$HOME/.local/bin"
        ln -sf "$INSTALL_PATH/start-bofa.sh" "$HOME/.local/bin/bofa"
        echo -e "${GREEN}✅ Comando 'bofa' disponible en terminal${NC}"
    fi
}

show_completion_message() {
    echo -e "${GREEN}✅ Instalación completada!${NC}"
    echo -e "${CYAN}🚀 Para usar BOFA:${NC}"
    echo -e "   CLI directo: $INSTALL_PATH/start-bofa.sh"
    echo -e "   Con Docker: $INSTALL_PATH/start-bofa-docker.sh"
    echo -e "   Comando: bofa (si está en PATH)"
    echo -e "   Web: http://localhost:3000 (con Docker)"
    echo ""
    echo -e "${YELLOW}💡 Consejos:${NC}"
    echo -e "   • Si instalaste Docker, haz logout/login para usarlo sin sudo"
    echo -e "   • Añade $HOME/.local/bin a tu PATH si no está"
    echo -e "   • Visita https://github.com/descambiado/BOFA para documentación"
}

# Procesar argumentos
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-docker)
            SKIP_DOCKER=true
            shift
            ;;
        --force)
            FORCE_INSTALL=true
            shift
            ;;
        --install-path)
            INSTALL_PATH="$2"
            shift 2
            ;;
        -h|--help)
            echo "BOFA Universal Installer"
            echo "Uso: $0 [opciones]"
            echo "  --skip-docker     No instalar Docker"
            echo "  --force          Sobrescribir instalación existente"
            echo "  --install-path   Directorio de instalación (default: $HOME/BOFA)"
            echo "  -h, --help       Mostrar esta ayuda"
            exit 0
            ;;
        *)
            echo "Opción desconocida: $1"
            exit 1
            ;;
    esac
done

# Ejecutar instalación
main() {
    print_banner
    check_root
    detect_distro
    install_dependencies
    
    if [ "$SKIP_DOCKER" = false ]; then
        install_docker
    fi
    
    clone_repository
    install_python_deps
    setup_docker
    create_launchers
    show_completion_message
}

# Manejo de errores
trap 'echo -e "${RED}❌ Error durante la instalación${NC}"; exit 1' ERR

main "$@"
