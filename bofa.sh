
#!/bin/bash

# BOFA - Best Of All
# Desarrollado por @descambiado (David Hernández Jiménez)
# Script de inicialización de la CLI

echo "🛡️  Iniciando BOFA CLI..."
echo "Desarrollado por @descambiado"
echo "================================"

# Verificar si Python3 está instalado
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 no está instalado. Por favor instálalo primero."
    exit 1
fi

# Verificar si las dependencias están instaladas
if [ ! -f "cli/requirements.txt" ]; then
    echo "⚠️  Archivo de dependencias no encontrado."
else
    echo "📦 Instalando dependencias..."
    pip3 install -r cli/requirements.txt --quiet
fi

# Ejecutar la CLI
echo "🚀 Lanzando BOFA CLI..."
python3 cli/bofa_cli.py
