#!/bin/bash

# BOFA Extended Systems v2.5.0 - Installation Verification Script
# This script verifies that all components are properly installed and configured

echo "🔍 BOFA v2.5.0 - Verificación de Instalación"
echo "=============================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Verification results
PASSED=0
FAILED=0

check_command() {
    if command -v $1 &> /dev/null; then
        echo -e "${GREEN}✅ $1 está instalado${NC}"
        ((PASSED++))
    else
        echo -e "${RED}❌ $1 no está instalado${NC}"
        ((FAILED++))
    fi
}

check_file() {
    if [ -f "$1" ]; then
        echo -e "${GREEN}✅ $1 existe${NC}"
        ((PASSED++))
    else
        echo -e "${RED}❌ $1 no encontrado${NC}"
        ((FAILED++))
    fi
}

check_directory() {
    if [ -d "$1" ]; then
        echo -e "${GREEN}✅ Directorio $1 existe${NC}"
        ((PASSED++))
    else
        echo -e "${RED}❌ Directorio $1 no encontrado${NC}"
        ((FAILED++))
    fi
}

check_service() {
    if curl -s -o /dev/null -w "%{http_code}" $1 | grep -q "200\|201\|404"; then
        echo -e "${GREEN}✅ Servicio $1 respondiendo${NC}"
        ((PASSED++))
    else
        echo -e "${YELLOW}🔄 Servicio $1 no disponible (normal si no está ejecutándose)${NC}"
    fi
}

echo -e "\n${BLUE}📋 Verificando Dependencias del Sistema${NC}"
echo "---------------------------------------"
check_command "docker"
check_command "docker-compose"
check_command "git"
check_command "curl"

echo -e "\n${BLUE}📁 Verificando Estructura de Archivos${NC}"
echo "------------------------------------"
check_file "docker-compose.yml"
check_file ".env.template"
check_file "package.json"
check_file "vite.config.ts"
check_file "tailwind.config.ts"
check_file "Dockerfile.frontend"
check_file "Dockerfile.api"
check_file "nginx.conf"
check_file "requirements.txt"
check_file "pyproject.toml"

echo -e "\n${BLUE}📂 Verificando Directorios Principales${NC}"
echo "-------------------------------------"
check_directory "src"
check_directory "src/components"
check_directory "src/pages"
check_directory "scripts"
check_directory "api"
check_directory "labs"
check_directory "database"
check_directory "monitoring"
check_directory "docs"

echo -e "\n${BLUE}🐍 Verificando Scripts de Python${NC}"
echo "-------------------------------"
SCRIPT_CATEGORIES=("red" "blue" "purple" "osint" "malware" "social" "exploit" "recon" "forensics" "study")
for category in "${SCRIPT_CATEGORIES[@]}"; do
    if [ -d "scripts/$category" ]; then
        count=$(find scripts/$category -name "*.py" | wc -l)
        yaml_count=$(find scripts/$category -name "*.yaml" | wc -l)
        echo -e "${GREEN}✅ Módulo $category: $count scripts Python, $yaml_count archivos YAML${NC}"
        ((PASSED++))
    else
        echo -e "${RED}❌ Módulo $category no encontrado${NC}"
        ((FAILED++))
    fi
done

echo -e "\n${BLUE}🧪 Verificando Laboratorios${NC}"
echo "-------------------------"
LAB_DIRS=("labs/web-application-security" "labs/internal-network" "labs/lab-android-emulation" "labs/lab-ctf-generator" "labs/lab-zero-day-scanner")
for lab in "${LAB_DIRS[@]}"; do
    if [ -d "$lab" ]; then
        if [ -f "$lab/docker-compose.yml" ] || [ -f "$lab/Dockerfile" ]; then
            echo -e "${GREEN}✅ Lab $(basename $lab) configurado correctamente${NC}"
            ((PASSED++))
        else
            echo -e "${YELLOW}⚠️  Lab $(basename $lab) sin configuración Docker${NC}"
        fi
    else
        echo -e "${RED}❌ Lab $(basename $lab) no encontrado${NC}"
        ((FAILED++))
    fi
done

echo -e "\n${BLUE}📖 Verificando Documentación${NC}"
echo "----------------------------"
DOCS=("README.md" "CHANGELOG.md" "docs/INSTALLATION.md" "docs/USAGE.md" "scripts/README.md" "labs/README.md" "api/README.md")
for doc in "${DOCS[@]}"; do
    check_file "$doc"
done

echo -e "\n${BLUE}🔧 Verificando Configuraciones${NC}"
echo "------------------------------"
check_file "database/init.sql"
check_file "monitoring/prometheus.yml"
check_file "logging/logstash.conf"

# Check if services are running (optional)
echo -e "\n${BLUE}🌐 Verificando Servicios (Opcional)${NC}"
echo "--------------------------------"
check_service "http://localhost:8080"
check_service "http://localhost:8000"
check_service "http://localhost:5432"
check_service "http://localhost:6379"

echo -e "\n${BLUE}📊 Resumen de Verificación${NC}"
echo "========================="
echo -e "Verificaciones pasadas: ${GREEN}$PASSED${NC}"
echo -e "Verificaciones fallidas: ${RED}$FAILED${NC}"

if [ $FAILED -eq 0 ]; then
    echo -e "\n${GREEN}🎉 ¡BOFA v2.5.0 está correctamente instalado!${NC}"
    echo -e "${GREEN}Puedes ejecutar: docker-compose up --build${NC}"
    exit 0
else
    echo -e "\n${YELLOW}⚠️  Se encontraron $FAILED problemas que deben solucionarse.${NC}"
    echo -e "${YELLOW}Revisa la documentación en docs/INSTALLATION.md${NC}"
    exit 1
fi