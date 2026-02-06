#!/usr/bin/env python3
"""
Hash Calculator - Cálculo de hashes para forense
================================================

Calcula hash MD5 o SHA256 de una cadena. Útil para comparar muestras, payloads o archivos (contenido leído).
Uso: python3 hash_calculator.py --input "texto" --algorithm sha256
"""

import argparse
import hashlib
import sys


def main():
    parser = argparse.ArgumentParser(description="Calcular hash MD5 o SHA256 de una cadena (forense)")
    parser.add_argument("--input", type=str, required=True, help="Cadena o ruta de archivo a hashear")
    parser.add_argument("--algorithm", type=str, default="sha256", choices=["md5", "sha256"], help="Algoritmo de hash")
    parser.add_argument("--file", action="store_true", help="Tratar input como ruta de archivo y hashear su contenido")
    args = parser.parse_args()

    try:
        data = args.input
        if args.file:
            with open(args.input, "rb") as f:
                data = f.read()
        else:
            data = data.encode("utf-8")

        if args.algorithm == "md5":
            h = hashlib.md5(data).hexdigest()
        else:
            h = hashlib.sha256(data).hexdigest()
        print(h)
        return 0
    except FileNotFoundError:
        print(f"Error: archivo no encontrado: {args.input}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
