#!/usr/bin/env python3
"""
Web Path Scanner - Simple bug bounty helper
===========================================

Escanea una lista de rutas comunes sobre una URL base y muestra
que rutas devuelven codigo 200/301/302/401/403.

Uso:
    python3 path_scanner.py --url https://example.com \\
        --paths admin,login,wp-admin,phpinfo.php \\
        --timeout 5 --json
"""

import argparse
import json
import sys
from urllib.parse import urljoin, urlparse
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError


def _normalize_base(url: str) -> str:
    url = url.strip()
    parsed = urlparse(url)
    if not parsed.scheme:
        # Asumir https por defecto
        url = "https://" + url
        parsed = urlparse(url)
    # Asegurar que termina en '/'
    if not url.endswith("/"):
        url = url + "/"
    return url


def main():
    parser = argparse.ArgumentParser(description="Escanear rutas comunes en una URL para bug bounty")
    parser.add_argument("--url", type=str, required=True, help="URL base (ej. https://example.com)")
    parser.add_argument(
        "--paths",
        type=str,
        default="admin,login,wp-admin,phpinfo.php,config,backup,.git,server-status",
        help="Lista de rutas separadas por coma (sin barra inicial)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="Timeout en segundos por peticion (default 5)",
    )
    parser.add_argument(
        "--status-codes",
        type=str,
        default="200,301,302,401,403",
        help="Codigos de estado HTTP a considerar como hallazgo, separados por coma",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Salida JSON (incluye rutas encontradas y errores)",
    )
    args = parser.parse_args()

    base = _normalize_base(args.url)
    try:
        wanted_codes = {int(x.strip()) for x in args.status_codes.split(",") if x.strip()}
    except ValueError:
        print("Error: status-codes debe ser una lista de numeros separados por coma", file=sys.stderr)
        return 1

    paths = [p.strip().lstrip("/") for p in args.paths.split(",") if p.strip()]
    found = []
    errors = []

    for p in paths:
        target = urljoin(base, p)
        req = Request(target, method="GET")
        req.add_header("User-Agent", "BOFA-PathScanner/1.0")
        try:
            with urlopen(req, timeout=args.timeout) as resp:
                status = getattr(resp, "status", None)
                length = None
                try:
                    body = resp.read()
                    length = len(body)
                except Exception:
                    length = None
                if status in wanted_codes:
                    found.append(
                        {
                            "path": "/" + p,
                            "url": target,
                            "status": status,
                            "length": length,
                        }
                    )
        except HTTPError as e:
            # Contar como posible hallazgo si el codigo esta en la lista
            code = e.code
            if code in wanted_codes:
                found.append(
                    {
                        "path": "/" + p,
                        "url": target,
                        "status": code,
                        "length": None,
                    }
                )
            else:
                errors.append({"path": "/" + p, "url": target, "error": str(e)})
        except (URLError, OSError) as e:
            errors.append({"path": "/" + p, "url": target, "error": str(e)})

    if args.json:
        out = {
            "base_url": base,
            "paths_total": len(paths),
            "found_count": len(found),
            "findings": found,
            "errors": errors,
        }
        print(json.dumps(out, indent=2))
    else:
        print(f"Base URL: {base}")
        print(f"Rutas probadas: {len(paths)}")
        if not found:
            print("No se encontraron rutas interesantes con los codigos indicados.")
        else:
            print("Rutas encontradas:")
            for item in found:
                print(f"  {item['status']} {item['url']} (len={item['length']})")
        if errors:
            print("\nErrores:")
            for err in errors:
                print(f"  {err['url']}: {err['error']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

