#!/usr/bin/env python3
"""
Param Finder - BOFA Web
=======================

Extrae parametros potenciales de una pagina web:
- nombres de campos de formulario (name=)
- parametros en enlaces (?param=, &param=)
- patrones simples en el HTML que parezcan parámetros.

Uso:
    python3 param_finder.py --url https://example.com --json
"""

import argparse
import json
import re
import sys
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from urllib.parse import urlparse


def _normalize_url(url: str) -> str:
    url = url.strip()
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "https://" + url
    return url


def extract_params(html: str):
    params = []
    # Formularios: name="..."
    form_pattern = re.compile(r'name\\s*=\\s*"(?P<name>[a-zA-Z0-9_\\-]+)"')
    for m in form_pattern.finditer(html):
        name = m.group("name")
        params.append({"name": name, "source": "form"})
    # Enlaces: ?param= o &param=
    link_pattern = re.compile(r'[?&](?P<name>[a-zA-Z0-9_\\-]+)=')
    for m in link_pattern.finditer(html):
        name = m.group("name")
        params.append({"name": name, "source": "url"})
    # Normalizar: agrupar por nombre y acumular fuentes
    merged = {}
    for p in params:
        key = p["name"]
        if key not in merged:
            merged[key] = {"name": key, "sources": set()}
        merged[key]["sources"].add(p["source"])
    result = []
    for v in merged.values():
        result.append({"name": v["name"], "sources": sorted(v["sources"])})
    return sorted(result, key=lambda x: x["name"])


def main():
    parser = argparse.ArgumentParser(description="Extraer parametros potenciales de una pagina web")
    parser.add_argument("--url", type=str, required=True, help="URL a analizar (ej. https://example.com)")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout en segundos (default 10)")
    parser.add_argument("--json", action="store_true", help="Salida JSON (para IA/flows)")
    args = parser.parse_args()

    url = _normalize_url(args.url)
    try:
        req = Request(url, method="GET")
        req.add_header("User-Agent", "BOFA-ParamFinder/1.0")
        with urlopen(req, timeout=args.timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except (HTTPError, URLError, OSError) as e:
        err = {"error": str(e), "url": url}
        if args.json:
            print(json.dumps(err, indent=2))
        else:
            print(f"Error: {e}", file=sys.stderr)
        return 1

    params = extract_params(body)
    if args.json:
        out = {
            "url": url,
            "params_count": len(params),
            "params": params,
        }
        print(json.dumps(out, indent=2))
    else:
        if not params:
            print(f"URL: {url}")
            print("No se encontraron parametros.")
        else:
            print(f"URL: {url}")
            print("Parametros encontrados:")
            for p in params:
                sources = ",".join(p["sources"])
                print(f"  {p['name']} (sources={sources})")
    return 0


if __name__ == "__main__":
    sys.exit(main())

