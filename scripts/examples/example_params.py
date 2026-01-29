#!/usr/bin/env python3
"""
Example Params - Módulo de Ejemplo con Parámetros
==================================================

Este módulo demuestra cómo recibir y validar parámetros
que el core pasa como argumentos de línea de comandos.

CARACTERÍSTICAS:
- ✅ Recepción de parámetros por argparse
- ✅ Validación de parámetros (requeridos, tipos, rangos)
- ✅ Diferentes tipos de parámetros (str, int, bool)
- ✅ Valores por defecto
- ✅ Mensajes de error claros
- ✅ Manejo apropiado de errores

USO DIRECTO:
    python3 example_params.py --target example.com --timeout 30 --verbose

USO CON EL CORE:
    from core.engine import get_engine
    engine = get_engine()
    result = engine.execute_script(
        "examples",
        "example_params",
        parameters={
            "target": "example.com",
            "timeout": 30,
            "verbose": True
        }
    )

IMPORTANTE:
- Los parámetros se pasan SIN el prefijo '--' desde el core
- El core añade automáticamente '--' al construir el comando
- argparse espera '--', así que lo definimos en el script
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
    # ============================================================
    # CONFIGURAR PARSER DE ARGUMENTOS
    # ============================================================
    # NOTA: El core pasa parámetros como: --key value
    #       argparse espera exactamente ese formato
    parser = argparse.ArgumentParser(
        description="Módulo de ejemplo que acepta parámetros",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  python3 example_params.py --target example.com
  python3 example_params.py --target example.com --timeout 60
  python3 example_params.py --target example.com --timeout 60 --verbose
        """
    )
    
    # Parámetro requerido: string
    # Este parámetro es obligatorio según el YAML
    parser.add_argument(
        "--target",
        type=str,
        required=True,
        help="Target a procesar (requerido, tipo: str)"
    )
    
    # Parámetro opcional: int con valor por defecto
    # Si no se proporciona, usa el valor por defecto
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Timeout en segundos (default: 30, tipo: int)"
    )
    
    # Parámetro opcional: bool (flag)
    # Si se proporciona, es True; si no, es False
    parser.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="Modo verbose - muestra información adicional (tipo: bool)"
    )
    
    # ============================================================
    # PARSEAR Y VALIDAR ARGUMENTOS
    # ============================================================
    args = parser.parse_args()
    
    # Validación adicional de parámetros
    # argparse valida tipos básicos, pero podemos añadir validación de negocio
    if args.timeout < 1:
        print("❌ Error: timeout debe ser mayor que 0", file=sys.stderr)
        print(f"   Valor recibido: {args.timeout}", file=sys.stderr)
        return 1
    
    if args.timeout > 3600:
        print("⚠️  Advertencia: timeout muy alto (>3600s)", file=sys.stderr)
        print(f"   Valor recibido: {args.timeout}", file=sys.stderr)
        # No fallamos, solo advertimos
    
    if not args.target or not args.target.strip():
        print("❌ Error: target no puede estar vacío", file=sys.stderr)
        return 1
    
    # Procesar con los parámetros recibidos
    print("=" * 60)
    print("BOFA Example Params - Módulo con Parámetros")
    print("=" * 60)
    print()
    print(f"📅 Fecha/Hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    print("📋 Parámetros Recibidos:")
    print(f"   • Target: {args.target}")
    print(f"   • Timeout: {args.timeout} segundos")
    print(f"   • Verbose: {'Sí' if args.verbose else 'No'}")
    print()
    
    # Simular procesamiento
    print(f"🔄 Procesando target: {args.target}")
    print(f"⏱️  Timeout configurado: {args.timeout}s")
    
    if args.verbose:
        print()
        print("📊 Información Detallada (modo verbose):")
        print(f"   • Tipo de target: {type(args.target).__name__}")
        print(f"   • Tipo de timeout: {type(args.timeout).__name__}")
        print(f"   • Longitud del target: {len(args.target)} caracteres")
    
    print()
    print("✅ Procesamiento completado exitosamente")
    print("=" * 60)
    
    # Retornar código de éxito
    return 0


if __name__ == "__main__":
    # Ejecutar función principal y salir con su código de retorno
    sys.exit(main())
