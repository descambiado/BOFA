#!/usr/bin/env python3
"""
HTTP Headers - Reconocimiento de cabeceras HTTP
==============================================

Obtiene las cabeceras HTTP de una URL. Útil para fingerprinting y seguridad.
Uso: python3 http_headers.py --url https://example.com [--timeout 10]
"""

import argparse
import json
import ssl
import sys
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError


def main():
    parser = argparse.ArgumentParser(description="Obtener cabeceras HTTP de una URL")
    parser.add_argument("--url", type=str, required=True, help="URL objetivo")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout en segundos (default 10)")
    parser.add_argument("--json", action="store_true", help="Salida JSON")
    parser.add_argument("--insecure", action="store_true", help="No verificar certificado SSL (para entornos dev/test)")
    args = parser.parse_args()

    ctx = None
    if args.insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    try:
        req = Request(args.url, method="HEAD")
        req.add_header("User-Agent", "BOFA-Recon/1.0")
        with urlopen(req, timeout=args.timeout, context=ctx) as resp:
            headers = dict(resp.headers)
            if args.json:
                print(json.dumps({"url": args.url, "status": resp.status, "headers": headers}, indent=2))
            else:
                print(f"URL: {args.url}\nStatus: {resp.status}\n")
                for k, v in headers.items():
                    print(f"  {k}: {v}")
        return 0
    except (URLError, HTTPError, OSError) as e:
        print(json.dumps({"error": str(e), "url": args.url}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
