
#!/bin/bash

# Port Slayer - Advanced Port Scanner
# Author: @descambiado (David Hernández Jiménez)
# BOFA - Best Of All Cybersecurity Suite
# Educational/Professional Use Only

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
show_banner() {
    echo -e "${CYAN}"
    echo "🛡️  BOFA - Port Slayer v1.0"
    echo "Desarrollado por @descambiado"
    echo "=================================="
    echo -e "${NC}"
}

# Help function
show_help() {
    echo "Uso: $0 [OPCIONES] TARGET"
    echo ""
    echo "OPCIONES:"
    echo "  -f, --fast     Escaneo rápido (puertos comunes)"
    echo "  -s, --stealth  Escaneo sigiloso (SYN scan)"
    echo "  -a, --all      Escaneo completo (todos los puertos)"
    echo "  -u, --udp      Incluir escaneo UDP"
    echo "  -o, --output   Archivo de salida"
    echo "  -t, --timing   Timing template (0-5, default: 3)"
    echo "  -h, --help     Mostrar esta ayuda"
    echo ""
    echo "EJEMPLOS:"
    echo "  $0 -f 192.168.1.1"
    echo "  $0 -s -o results.txt example.com"
    echo "  $0 -a -u --timing 2 target.com"
    echo ""
    echo "MODOS DE ESCANEO:"
    echo "  Fast    - Top 1000 puertos TCP"
    echo "  Stealth - SYN scan sigiloso"
    echo "  All     - Todos los puertos (1-65535)"
}

# Check if nmap is installed
check_nmap() {
    if ! command -v nmap &> /dev/null; then
        echo -e "${RED}❌ Error: nmap no está instalado${NC}"
        echo "Instala nmap con:"
        echo "  sudo apt install nmap     # Debian/Ubuntu"
        echo "  sudo yum install nmap     # CentOS/RHEL"
        echo "  sudo pacman -S nmap       # Arch Linux"
        exit 1
    fi
}

# Fast scan - common ports
fast_scan() {
    local target=$1
    local output=$2
    local timing=${3:-3}
    
    echo -e "${YELLOW}🚀 Iniciando escaneo rápido de ${target}${NC}"
    echo -e "${BLUE}⏱️  Escaneando top 1000 puertos TCP...${NC}"
    
    local cmd="nmap -T${timing} --top-ports 1000 -sV --version-intensity 5 ${target}"
    
    if [[ -n "$output" ]]; then
        cmd="$cmd -oN $output"
        echo -e "${CYAN}💾 Guardando resultados en: $output${NC}"
    fi
    
    echo -e "${GREEN}🔍 Ejecutando: $cmd${NC}"
    eval $cmd
}

# Stealth scan
stealth_scan() {
    local target=$1
    local output=$2
    local timing=${3:-2}
    
    echo -e "${YELLOW}🥷 Iniciando escaneo sigiloso de ${target}${NC}"
    echo -e "${BLUE}⚡ Usando SYN scan para evadir detección...${NC}"
    
    local cmd="nmap -sS -T${timing} -f --data-length 25 --scan-delay 1 ${target}"
    
    if [[ -n "$output" ]]; then
        cmd="$cmd -oN $output"
        echo -e "${CYAN}💾 Guardando resultados en: $output${NC}"
    fi
    
    echo -e "${GREEN}🔍 Ejecutando: $cmd${NC}"
    eval $cmd
}

# Full scan - all ports
full_scan() {
    local target=$1
    local output=$2
    local timing=${3:-3}
    local include_udp=$4
    
    echo -e "${YELLOW}🔥 Iniciando escaneo completo de ${target}${NC}"
    echo -e "${BLUE}⚠️  ADVERTENCIA: Este escaneo puede tomar mucho tiempo${NC}"
    
    # TCP scan
    local cmd="nmap -T${timing} -p- -sV --version-intensity 5 ${target}"
    
    if [[ -n "$output" ]]; then
        cmd="$cmd -oN ${output%.txt}_tcp.txt"
        echo -e "${CYAN}💾 Guardando resultados TCP en: ${output%.txt}_tcp.txt${NC}"
    fi
    
    echo -e "${GREEN}🔍 Ejecutando TCP scan: $cmd${NC}"
    eval $cmd
    
    # UDP scan if requested
    if [[ "$include_udp" == "true" ]]; then
        echo -e "${YELLOW}🌐 Iniciando escaneo UDP (top 1000)...${NC}"
        local udp_cmd="nmap -sU -T${timing} --top-ports 1000 ${target}"
        
        if [[ -n "$output" ]]; then
            udp_cmd="$udp_cmd -oN ${output%.txt}_udp.txt"
            echo -e "${CYAN}💾 Guardando resultados UDP en: ${output%.txt}_udp.txt${NC}"
        fi
        
        echo -e "${GREEN}🔍 Ejecutando UDP scan: $udp_cmd${NC}"
        eval $udp_cmd
    fi
}

# Parse arguments
parse_args() {
    local scan_mode=""
    local target=""
    local output=""
    local timing="3"
    local include_udp="false"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -f|--fast)
                scan_mode="fast"
                shift
                ;;
            -s|--stealth)
                scan_mode="stealth"
                shift
                ;;
            -a|--all)
                scan_mode="full"
                shift
                ;;
            -u|--udp)
                include_udp="true"
                shift
                ;;
            -o|--output)
                output="$2"
                shift 2
                ;;
            -t|--timing)
                timing="$2"
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            -*)
                echo -e "${RED}❌ Opción desconocida: $1${NC}"
                show_help
                exit 1
                ;;
            *)
                target="$1"
                shift
                ;;
        esac
    done
    
    # Validate target
    if [[ -z "$target" ]]; then
        echo -e "${RED}❌ Error: Debes especificar un target${NC}"
        show_help
        exit 1
    fi
    
    # Default to fast scan if no mode specified
    if [[ -z "$scan_mode" ]]; then
        scan_mode="fast"
    fi
    
    # Validate timing
    if [[ ! "$timing" =~ ^[0-5]$ ]]; then
        echo -e "${RED}❌ Error: Timing debe ser un número entre 0-5${NC}"
        exit 1
    fi
    
    # Execute scan based on mode
    case $scan_mode in
        "fast")
            fast_scan "$target" "$output" "$timing"
            ;;
        "stealth")
            stealth_scan "$target" "$output" "$timing"
            ;;
        "full")
            full_scan "$target" "$output" "$timing" "$include_udp"
            ;;
    esac
}

# Main execution
main() {
    show_banner
    check_nmap
    
    if [[ $# -eq 0 ]]; then
        show_help
        exit 1
    fi
    
    # Check if running as root for stealth scans
    if [[ "$*" == *"-s"* ]] || [[ "$*" == *"--stealth"* ]]; then
        if [[ $EUID -ne 0 ]]; then
            echo -e "${YELLOW}⚠️  Nota: El escaneo sigiloso requiere privilegios root${NC}"
            echo -e "${CYAN}💡 Ejecuta con: sudo $0 $*${NC}"
        fi
    fi
    
    parse_args "$@"
    
    echo -e "${GREEN}✅ Escaneo completado${NC}"
    echo -e "${CYAN}🛡️  BOFA - Port Slayer by @descambiado${NC}"
}

# Execute main function
main "$@"
