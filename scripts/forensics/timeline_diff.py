#!/usr/bin/env python3
"""
Timeline Diff - BOFA Forensics
==============================

Compara dos timelines generados por forensics/filesystem_timeline (JSON) y
detecta:
- ficheros añadidos
- ficheros eliminados
- ficheros modificados (tamano o mtime)

Uso:
    python3 timeline_diff.py --before timeline_before.json --after timeline_after.json --json
"""

import argparse
import json
import sys
from typing import Dict, Any, List


def _load_timeline(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return {"error": f"Archivo no encontrado: {path}", "path": path}
    except json.JSONDecodeError as e:
        return {"error": f"JSON invalido: {e}", "path": path}
    if "entries" not in data:
        return {"error": "Formato de timeline no valido (falta 'entries')", "path": path}
    return data


def diff_timelines(before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, Any]:
    before_entries = {e["path"]: e for e in before.get("entries", []) if "path" in e}
    after_entries = {e["path"]: e for e in after.get("entries", []) if "path" in e}

    added: List[Dict[str, Any]] = []
    removed: List[Dict[str, Any]] = []
    modified: List[Dict[str, Any]] = []

    for path, b in before_entries.items():
        a = after_entries.get(path)
        if not a:
            removed.append({"path": path, "before": b, "after": None})
        else:
            if b.get("size") != a.get("size") or int(b.get("mtime", 0)) != int(a.get("mtime", 0)):
                modified.append({"path": path, "before": b, "after": a})

    for path, a in after_entries.items():
        if path not in before_entries:
            added.append({"path": path, "before": None, "after": a})

    summary = {
        "added_count": len(added),
        "removed_count": len(removed),
        "modified_count": len(modified),
    }

    return {
        "before_directory": before.get("directory"),
        "after_directory": after.get("directory"),
        "summary": summary,
        "added": added,
        "removed": removed,
        "modified": modified,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Comparar dos timelines JSON generados por filesystem_timeline y mostrar ficheros añadidos, eliminados o modificados"
    )
    parser.add_argument("--before", required=True, help="Timeline JSON 'antes'")
    parser.add_argument("--after", required=True, help="Timeline JSON 'despues'")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Si es true, imprime salida JSON parseable (para IA/flows). Por defecto imprime resumen humano.",
    )
    args = parser.parse_args()

    before = _load_timeline(args.before)
    after = _load_timeline(args.after)

    if "error" in before:
        if args.json:
            print(json.dumps(before, indent=2))
        else:
            print(f"Error en before: {before['error']}", file=sys.stderr)
        return 1
    if "error" in after:
        if args.json:
            print(json.dumps(after, indent=2))
        else:
            print(f"Error en after: {after['error']}", file=sys.stderr)
        return 1

    result = diff_timelines(before, after)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Before directory: {result['before_directory']}")
        print(f"After directory: {result['after_directory']}")
        print(f"Added: {result['summary']['added_count']}")
        print(f"Removed: {result['summary']['removed_count']}")
        print(f"Modified: {result['summary']['modified_count']}")
        if result["summary"]["modified_count"]:
            print("\nModified files (path):")
            for item in result["modified"][:20]:
                print(f"  {item['path']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

