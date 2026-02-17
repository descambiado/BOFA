#!/usr/bin/env python3
"""
CTF String Hunter - BOFA Study
==============================

Extrae strings interesantes de un fichero (binario o texto) para CTF y estudio:
- URLs
- rutas de fichero
- emails
- cadenas tipo JWT
- flags con prefijo configurable (por defecto "BOFA{" y "CTF{")

Uso:
    python3 ctf_string_hunter.py --path reto.bin --json
"""

import argparse
import json
import os
import re
import sys
from typing import Dict, List, Any


def _read_file(path: str) -> str:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Archivo no encontrado: {path}")
    with open(path, "rb") as f:
        data = f.read()
    # Decodificar como latin-1 para conservar bytes y luego filtrar ASCII imprimible
    text = data.decode("latin-1", errors="ignore")
    return text


def _extract_raw_strings(text: str, min_length: int) -> List[str]:
    # Caracteres imprimibles ASCII [32-126]
    pattern = rf"[ -~]{{{min_length},}}"
    return re.findall(pattern, text)


def analyze_strings(strings: List[str], flag_prefix: str) -> Dict[str, Any]:
    urls: List[str] = []
    paths: List[str] = []
    emails: List[str] = []
    jwt_like: List[str] = []
    flags: List[str] = []
    other: List[str] = []

    re_url = re.compile(r"https?://[^\s\"'>)]+", re.IGNORECASE)
    re_path = re.compile(r"/[A-Za-z0-9_\-./]{3,}")
    re_email = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
    re_jwt = re.compile(r"^[A-Za-z0-9\-_]+?\.[A-Za-z0-9\-_]+?\.[A-Za-z0-9\-_+/=]+$")
    # Flags: prefijo configurable, mas dos prefijos comunes
    flag_prefixes = [flag_prefix] if flag_prefix else []
    flag_prefixes.extend(["BOFA{", "CTF{"])

    for s in strings:
        s_stripped = s.strip()
        if not s_stripped:
            continue
        if re_url.search(s_stripped):
            urls.append(s_stripped)
            continue
        if re_email.search(s_stripped):
            emails.append(s_stripped)
            continue
        if re_path.search(s_stripped):
            paths.append(s_stripped)
            continue
        if re_jwt.match(s_stripped):
            jwt_like.append(s_stripped)
            continue
        if any(pref in s_stripped for pref in flag_prefixes):
            flags.append(s_stripped)
            continue
        other.append(s_stripped)

    return {
        "urls": sorted(list(dict.fromkeys(urls)))[:100],
        "paths": sorted(list(dict.fromkeys(paths)))[:100],
        "emails": sorted(list(dict.fromkeys(emails)))[:100],
        "jwt_like": sorted(list(dict.fromkeys(jwt_like)))[:100],
        "flags": sorted(list(dict.fromkeys(flags)))[:100],
        "other_sample": sorted(list(dict.fromkeys(other)))[:50],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extraer strings interesantes (URLs, rutas, emails, JWT, flags) de un fichero para CTF/estudio"
    )
    parser.add_argument("--path", required=True, help="Ruta al fichero (binario o texto) a analizar")
    parser.add_argument(
        "--min-length",
        type=int,
        default=4,
        help="Longitud minima de string a considerar (por defecto 4)",
    )
    parser.add_argument(
        "--flag-prefix",
        type=str,
        default="BOFA{",
        help="Prefijo de flag a resaltar (por defecto BOFA{, tambien se buscan CTF{ de forma automatica)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Si es true, imprime salida JSON parseable (para IA/flows); si no, resumen humano",
    )
    args = parser.parse_args()

    try:
        text = _read_file(args.path)
    except FileNotFoundError as e:
        err = {"error": str(e), "path": args.path}
        if args.json:
            print(json.dumps(err, indent=2))
        else:
            print(f"Error: {e}", file=sys.stderr)
        return 1

    raw_strings = _extract_raw_strings(text, max(args.min_length, 1))
    categorized = analyze_strings(raw_strings, args.flag_prefix)

    result = {
        "file": args.path,
        "min_length": args.min_length,
        "total_strings": len(raw_strings),
        "categories": categorized,
    }

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"File: {result['file']}")
        print(f"Total strings (>= {result['min_length']}): {result['total_strings']}")
        for key in ["urls", "paths", "emails", "jwt_like", "flags"]:
            items = result["categories"][key]
            if items:
                print(f"\n{key.upper()} ({len(items)}):")
                for s in items[:10]:
                    print(f"  {s}")
        if result["categories"]["other_sample"]:
            print("\nOTHER SAMPLE:")
            for s in result["categories"]["other_sample"][:10]:
                print(f"  {s}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

