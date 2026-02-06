#!/usr/bin/env python3
"""
Filesystem Timeline - BOFA Forensics
====================================

Construye una linea de tiempo simple de ficheros en un directorio:
- ruta relativa
- tamano
- fecha de modificacion

Uso:
    python3 filesystem_timeline.py --directory . --max-files 100 --json
"""

import argparse
import json
import os
import sys
from datetime import datetime
from typing import List, Dict, Any


def build_timeline(directory: str, max_files: int) -> Dict[str, Any]:
    if not os.path.isdir(directory):
        return {"error": "Directorio no encontrado o no es directorio", "directory": directory}
    entries: List[Dict[str, Any]] = []
    root = os.path.abspath(directory)
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            full = os.path.join(dirpath, name)
            try:
                st = os.stat(full)
            except Exception:
                continue
            rel = os.path.relpath(full, root)
            entries.append(
                {
                    "path": rel,
                    "size": st.st_size,
                    "mtime": st.st_mtime,
                }
            )
            if len(entries) >= max_files:
                break
        if len(entries) >= max_files:
            break
    entries.sort(key=lambda x: x["mtime"])
    for e in entries:
        e["mtime_iso"] = datetime.fromtimestamp(e["mtime"]).isoformat()
    return {
        "directory": directory,
        "count": len(entries),
        "entries": entries,
    }


def main():
    parser = argparse.ArgumentParser(description="Construir una linea de tiempo simple de un directorio")
    parser.add_argument("--directory", required=True, help="Directorio raiz a analizar")
    parser.add_argument(
        "--max-files",
        type=int,
        default=100,
        help="Numero maximo de ficheros a incluir (default 100)",
    )
    parser.add_argument("--json", action="store_true", help="Si es true, salida JSON (para IA/flows)")
    args = parser.parse_args()

    result = build_timeline(args.directory, args.max_files)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if "error" in result:
            print(f"Error: {result['error']} ({result.get('directory')})", file=sys.stderr)
            return 1
        print(f"Directory: {result['directory']}")
        print(f"Files: {result['count']}")
        for e in result["entries"]:
            print(f"{e['mtime_iso']}  {e['size']:>8}  {e['path']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

