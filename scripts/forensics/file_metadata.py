#!/usr/bin/env python3
"""
File Metadata Extractor - BOFA Forensics
=======================================

Extrae metadatos basicos de un fichero:
- tamano en bytes
- fechas de acceso/modificacion/creacion
- permisos (modo)

Uso:
    python3 file_metadata.py --path ruta/al/fichero --json
"""

import argparse
import json
import os
import sys
from datetime import datetime


def _fmt(ts: float) -> str:
    try:
        return datetime.fromtimestamp(ts).isoformat()
    except Exception:
        return ""


def get_metadata(path: str):
    if not os.path.exists(path):
        return {"error": "Ruta no encontrada", "path": path}
    try:
        st = os.stat(path)
    except Exception as e:
        return {"error": str(e), "path": path}

    return {
        "path": path,
        "is_dir": os.path.isdir(path),
        "is_file": os.path.isfile(path),
        "size": st.st_size,
        "mode": st.st_mode,
        "mtime": _fmt(st.st_mtime),
        "atime": _fmt(st.st_atime),
        "ctime": _fmt(st.st_ctime),
    }


def main():
    parser = argparse.ArgumentParser(description="Extraer metadatos basicos de un fichero")
    parser.add_argument("--path", required=True, help="Ruta al fichero a analizar")
    parser.add_argument("--json", action="store_true", help="Si es true, salida JSON (para IA/flows)")
    args = parser.parse_args()

    result = get_metadata(args.path)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if "error" in result:
            print(f"Error: {result['error']} ({result.get('path')})", file=sys.stderr)
            return 1
        print(f"Path: {result['path']}")
        print(f"Is file: {result['is_file']}")
        print(f"Is dir: {result['is_dir']}")
        print(f"Size: {result['size']} bytes")
        print(f"Mode: {result['mode']}")
        print(f"Modified: {result['mtime']}")
        print(f"Accessed: {result['atime']}")
        print(f"Created: {result['ctime']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

