#!/usr/bin/env python3
"""
Robots.txt fetcher - Recon web
=============================

Obtiene el contenido de robots.txt de una URL. Util para recon y comprobar
directivas de rastreo. Por descambiado. BOFA.

Uso: python3 robots_txt.py --url https://example.com [--timeout 10] [--json]
"""

import argparse
import json
import sys
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from urllib.parse import urljoin, urlparse


def main():
    parser = argparse.ArgumentParser(description="Obtener robots.txt de una URL")
    parser.add_argument("--url", type=str, required=True, help="URL base (ej. https://example.com)")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout en segundos (default 10)")
    parser.add_argument("--json", action="store_true", help="Salida JSON")
    args = parser.parse_args()

    base = args.url.rstrip("/")
    parsed = urlparse(base)
    if not parsed.scheme:
        base = "https://" + base
    robots_url = urljoin(base + "/", "robots.txt")

    try:
        req = Request(robots_url, method="GET")
        req.add_header("User-Agent", "BOFA-Recon/1.0")
        with urlopen(req, timeout=args.timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            status = resp.status

        if args.json:
            out = {
                "url": robots_url,
                "status": status,
                "content": body,
                "lines": len([l for l in body.splitlines() if l.strip()]),
            }
            print(json.dumps(out, indent=2))
        else:
            print(f"URL: {robots_url}\nStatus: {status}\n")
            print(body)
        return 0
    except HTTPError as e:
        err = {"error": str(e), "url": robots_url, "code": e.code}
        if args.json:
            print(json.dumps(err, indent=2))
        else:
            print(f"Error HTTP: {e.code} - {robots_url}", file=sys.stderr)
        return 1
    except (URLError, OSError) as e:
        err = {"error": str(e), "url": robots_url}
        if args.json:
            print(json.dumps(err, indent=2))
        else:
            print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
