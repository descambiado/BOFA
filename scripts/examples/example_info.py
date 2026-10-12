#!/usr/bin/env python3
"""
Example Info - Módulo de Ejemplo Simple
========================================

Este es el módulo de ejemplo más simple de BOFA.
Sirve como "hello world" del framework y referencia oficial.

CARACTERÍSTICAS:
- ✅ Estructura básica de un script BOFA
- ✅ Uso de variables de entorno del core
- ✅ Salida simple y clara a stdout
- ✅ Código de salida apropiado (0 = éxito)
- ✅ Sin dependencias externas
- ✅ Código limpio y bien documentado

USO DIRECTO:
    python3 example_info.py

USO CON EL CORE:
    from core.engine import get_engine
    engine = get_engine()
    result = engine.execute_script("examples", "example_info")

ESTRUCTURA:
Este script demuestra la estructura mínima necesaria:
1. Shebang para ejecución directa
2. Docstring descriptivo
3. Función main() que retorna código de salida
4. Uso de variables de entorno del core
5. Manejo apropiado de salida
"""

import os
import sys
from datetime import datetime


def main():
    """
    Función principal del script.
    
    Esta función:
    - Obtiene variables de entorno del core
    - Muestra información del entorno
    - Retorna código de salida apropiado
    
    Returns:
        int: Código de salida (0 = éxito, != 0 = error)
    """
    # ============================================================
    # OBTENER VARIABLES DE ENTORNO DEL CORE
    # ============================================================
    # El core establece estas variables automáticamente antes de ejecutar
    # Si el script se ejecuta directamente, usamos valores por defecto
    base_path = os.getenv("BOFA_BASE_PATH", ".")
    scripts_path = os.getenv("BOFA_SCRIPTS_PATH", ".")
    output_path = os.getenv("BOFA_OUTPUT_PATH", "./output")
    logs_path = os.getenv("BOFA_LOGS_PATH", "./logs")
    
    # Imprimir información básica
    print("=" * 60)
    print("BOFA Example Info - Módulo de Ejemplo Simple")
    print("=" * 60)
    print()
    print(f"Fecha/Hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    print("Variables de Entorno BOFA:")
    print(f"   - BOFA_BASE_PATH: {base_path}")
    print(f"   - BOFA_SCRIPTS_PATH: {scripts_path}")
    print(f"   - BOFA_OUTPUT_PATH: {output_path}")
    print(f"   - BOFA_LOGS_PATH: {logs_path}")
    print()
    print("[OK] Script ejecutado exitosamente")
    print("=" * 60)
    
    # Retornar código de éxito
    return 0


if __name__ == "__main__":
    # Ejecutar función principal y salir con su código de retorno
    sys.exit(main())
