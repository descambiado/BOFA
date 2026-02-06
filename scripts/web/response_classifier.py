#!/usr/bin/env python3
"""
Response Classifier - BOFA Web
==============================

Clasifica respuestas HTTP para un conjunto de rutas de una URL base.
- Calcula longitud de respuesta y codigo de estado.
- Marca como \"interesting\" las rutas con longitud muy distinta al grupo.

Uso:
    python3 response_classifier.py --url https://example.com \\
        --paths admin,login,wp-admin --timeout 5 --json
"""

import argparse
import json
import statistics
import sys
from urllib.parse import urljoin, urlparse
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError


def _normalize_base(url: str) -> str:
    url = url.strip()
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "https://" + url
        parsed = urlparse(url)
    if not url.endswith("/"):
        url = url + "/"
    return url


def classify_responses(base: str, paths, timeout: int):
    entries = []
    for p in paths:
        target = urljoin(base, p)
        req = Request(target, method="GET")
        req.add_header("User-Agent", "BOFA-ResponseClassifier/1.0")
        try:
            with urlopen(req, timeout=timeout) as resp:
                status = getattr(resp, "status", None)
                try:
                    body = resp.read()
                    size = len(body)
                except Exception:
                    size = None
                entries.append({"path": "/" + p, "url": target, "status": status, "size": size})
        except HTTPError as e:
            entries.append({"path": "/" + p, "url": target, "status": e.code, "size": None, "error": str(e)})
        except (URLError, OSError) as e:
            entries.append({"path": "/" + p, "url": target, "status": None, "size": None, "error": str(e)})
    # Calcular baseline de tamanos (ignorando None)
    sizes = [e["size"] for e in entries if isinstance(e.get("size"), int)]
    baseline = statistics.median(sizes) if sizes else None
    for e in entries:
        e["baseline_size"] = baseline
        if baseline is not None and isinstance(e.get("size"), int):
            diff = abs(e["size"] - baseline)
            e["deviation"] = diff
        else:
            e["deviation"] = None
    # Clasificar: interesante si desviacion es mayor que 50% de la mediana
    interesting = []
    baseline_list = []
    if baseline is not None and baseline > 0:
        threshold = baseline * 0.5
        for e in entries:
            if isinstance(e.get("deviation"), (int, float)) and e["deviation"] is not None and e["deviation"] > threshold:
                interesting.append(e)
            else:
                baseline_list.append(e)
    else:
        baseline_list = entries
    return {
        "entries": entries,
        "baseline": baseline,
        "baseline_group": baseline_list,
        "interesting": interesting,
    }


def main():
    parser = argparse.ArgumentParser(description="Clasificar respuestas HTTP de un conjunto de rutas sobre una URL base")
    parser.add_argument("--url", type=str, required=True, help="URL base (ej. https://example.com)")
    parser.add_argument(
        "--paths",
        type=str,
        default="admin,login,wp-admin,phpinfo.php,config,backup,.git,server-status",
        help="Lista de rutas separadas por coma (sin barra inicial)",
    )
    parser.add_argument("--timeout", type=int, default=5, help="Timeout en segundos (default 5)")
    parser.add_argument("--json", action="store_true", help="Salida JSON (para IA/flows)")
    args = parser.parse_args()

    base = _normalize_base(args.url)
    paths = [p.strip().lstrip("/") for p in args.paths.split(",") if p.strip()]
    result = classify_responses(base, paths, args.timeout)

    if args.json:
        out = {
            "base_url": base,
            "paths_total": len(paths),
            "baseline_size": result["baseline"],
            "interesting_count": len(result["interesting"]),
            "interesting": result["interesting"],
        }
        print(json.dumps(out, indent=2))
    else:
        print(f"Base URL: {base}")
        print(f"Rutas probadas: {len(paths)}")
        if not result["interesting"]:
            print("No se detectaron respuestas especialmente diferentes en tamano.")
        else:
            print("Rutas interesantes por tamano de respuesta:")
            for e in result["interesting"]:
                print(f"  {e['status']} {e['url']} size={e['size']} (baseline={result['baseline']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())

