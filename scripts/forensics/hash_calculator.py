#!/usr/bin/env python3
"""
Hash Calculator - Cálculo de hashes para forense
================================================

Calcula hash MD5 o SHA256 de una cadena. Útil para comparar muestras, payloads o archivos (contenido leído).
Uso: python3 hash_calculator.py --input "texto" --algorithm sha256
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path


def compute_hash(input_value: str, as_file: bool, algorithm: str):
    try:
        if as_file:
            path = Path(input_value)
            if not path.exists():
                return None, f"Archivo no encontrado: {input_value}"
            data = path.read_bytes()
        else:
            data = input_value.encode("utf-8")
        if algorithm == "md5":
            digest = hashlib.md5(data).hexdigest()
        else:
            digest = hashlib.sha256(data).hexdigest()
        return digest, None
    except Exception as exc:
        return None, str(exc)


def main():
    parser = argparse.ArgumentParser(description="Calcular hash MD5 o SHA256 de una cadena o fichero (forense)")
    parser.add_argument("--input", type=str, required=True, help="Cadena o ruta de archivo a hashear")
    parser.add_argument("--algorithm", type=str, default="sha256", choices=["md5", "sha256"], help="Algoritmo de hash")
    parser.add_argument("--file", action="store_true", help="Tratar input como ruta de archivo y hashear su contenido")
    parser.add_argument("--json", action="store_true", help="Si es true, salida JSON (para IA/flows)")
    args = parser.parse_args()

    digest, error = compute_hash(args.input, getattr(args, "file", False), args.algorithm)
    if error:
        if args.json:
            print(json.dumps({"error": error, "input": args.input, "algorithm": args.algorithm}, indent=2))
        else:
            print(f"Error: {error}", file=sys.stderr)
        return 1

    if args.json:
        out = {
            "input": args.input,
            "file": bool(args.file),
            "algorithm": args.algorithm,
            "hash": digest,
        }
        print(json.dumps(out, indent=2))
    else:
        print(digest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
