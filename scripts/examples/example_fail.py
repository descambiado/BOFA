#!/usr/bin/env python3
"""
Example Fail - Módulo de Ejemplo que Falla Controladamente
===========================================================

Este módulo demuestra cómo fallar de forma controlada
y proporcionar información útil para debugging.

CARACTERÍSTICAS:
- ✅ Manejo de errores apropiado
- ✅ Mensajes de error claros y descriptivos
- ✅ Códigos de salida apropiados (0, 1, 2)
- ✅ Salida a stderr para errores (correcto)
- ✅ Salida a stdout para información normal
- ✅ Diferentes tipos de errores (ejecución, validación)

USO DIRECTO:
    python3 example_fail.py --mode success    # Éxito (exit code 0)
    python3 example_fail.py --mode error      # Error de ejecución (exit code 1)
    python3 example_fail.py --mode validation # Error de validación (exit code 2)

USO CON EL CORE:
    from core.engine import get_engine
    engine = get_engine()
    
    # Caso exitoso
    result = engine.execute_script("examples", "example_fail", {"mode": "success"})
    # result.status = "success", result.exit_code = 0
    
    # Error
    result = engine.execute_script("examples", "example_fail", {"mode": "error"})
    # result.status = "error", result.exit_code = 1, result.stderr contiene el error

BUENAS PRÁCTICAS DEMOSTRADAS:
1. Errores van a stderr, no a stdout
2. Mensajes de error son claros y útiles
3. Códigos de salida diferentes para diferentes tipos de error
4. Información normal va a stdout
"""

import argparse
import sys
from datetime import datetime


def main():
    """
    Función principal del script.
    
    Returns:
        int: Código de salida (0 = éxito, != 0 = error)
    """
    parser = argparse.ArgumentParser(
        description="Módulo de ejemplo que demuestra manejo de errores"
    )
    
    parser.add_argument(
        "--mode",
        type=str,
        required=True,
        choices=["success", "error", "validation"],
        help="Modo de ejecución: success, error, o validation"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("BOFA Example Fail - Manejo de Errores")
    print("=" * 60)
    print()
    print(f"📅 Fecha/Hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🔧 Modo: {args.mode}")
    print()
    
    # ============================================================
    # SIMULAR DIFERENTES TIPOS DE RESULTADOS
    # ============================================================
    # Este script demuestra cómo manejar diferentes escenarios
    
    if args.mode == "success":
        # ============================================================
        # CASO EXITOSO
        # ============================================================
        # Todo salió bien, información va a stdout
        print("✅ Ejecución exitosa")
        print("   Este es el comportamiento normal del script")
        print("   La información útil va a stdout")
        print("=" * 60)
        return 0  # Código de éxito
    
    elif args.mode == "error":
        # ============================================================
        # ERROR DE EJECUCIÓN
        # ============================================================
        # Error durante la ejecución (no de validación)
        # IMPORTANTE: Errores van a stderr, no a stdout
        print("❌ Error de ejecución simulado", file=sys.stderr)
        print("   Este tipo de error ocurre durante la ejecución", file=sys.stderr)
        print("   Ejemplos:", file=sys.stderr)
        print("     - Fallo de conexión a servidor", file=sys.stderr)
        print("     - Archivo no encontrado", file=sys.stderr)
        print("     - Permisos insuficientes", file=sys.stderr)
        print("     - Timeout de operación", file=sys.stderr)
        print("=" * 60)
        return 1  # Código de error genérico
    
    elif args.mode == "validation":
        # ============================================================
        # ERROR DE VALIDACIÓN
        # ============================================================
        # Error de validación de datos/parámetros
        # IMPORTANTE: Errores van a stderr, no a stdout
        print("❌ Error de validación simulado", file=sys.stderr)
        print("   Este tipo de error ocurre cuando los datos no son válidos", file=sys.stderr)
        print("   Ejemplos:", file=sys.stderr)
        print("     - Parámetro fuera de rango permitido", file=sys.stderr)
        print("     - Formato de datos incorrecto", file=sys.stderr)
        print("     - Valor requerido faltante", file=sys.stderr)
        print("     - Tipo de dato incorrecto", file=sys.stderr)
        print("=" * 60)
        return 2  # Código de error de validación (diferente del genérico)
    
    # Este caso no debería alcanzarse debido a choices en argparse
    # pero lo incluimos por seguridad
    print("❌ Modo desconocido", file=sys.stderr)
    return 3


if __name__ == "__main__":
    # Ejecutar función principal y salir con su código de retorno
    sys.exit(main())
