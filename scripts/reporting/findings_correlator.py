#!/usr/bin/env python3
"""
Findings Correlator - BOFA Reporting
=====================================

Correlaciona hallazgos de param_finder, path_scanner, http_param_fuzzer
y security_headers_analyzer para producir hotspots priorizados y recomendaciones.

Entrada: JSON de los scripts anteriores (por --input o --stdin).
Salida: hotspots con prioridad, summary y recomendaciones.

Uso:
    python3 findings_correlator.py --target https://example.com --input param.json path.json fuzzer.json --json
    python3 findings_correlator.py --target https://example.com --stdin < flow_steps.json --json
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


def _detect_and_parse(data: Dict[str, Any]) -> Optional[str]:
    """Detecta tipo de JSON y devuelve 'param_finder'|'path_scanner'|'http_param_fuzzer'|'security_headers'|None."""
    if "params" in data and "params_count" in data and "url" in data:
        return "param_finder"
    if "findings" in data and "base_url" in data:
        return "path_scanner"
    if "anomalies" in data and "target_url" in data:
        return "http_param_fuzzer"
    if "issues" in data and "score" in data:
        return "security_headers"
    return None


def _extract_param_names(params_data: List[Dict]) -> List[str]:
    """Extrae nombres de params del output de param_finder."""
    names = []
    for p in params_data or []:
        if isinstance(p, dict) and "name" in p:
            names.append(str(p["name"]))
        elif isinstance(p, str):
            names.append(p)
    return names


def correlate(
    target: str,
    param_finder_data: Optional[Dict] = None,
    path_scanner_data: Optional[Dict] = None,
    fuzzer_data: Optional[Dict] = None,
    security_headers_data: Optional[Dict] = None,
) -> Dict[str, Any]:
    """
    Correlaciona hallazgos y produce hotspots priorizados.
    """
    hotspots: List[Dict[str, Any]] = []
    param_names: List[str] = []
    paths_found: List[Dict[str, Any]] = []
    anomalies_count = 0
    header_issues: List[Dict[str, Any]] = []

    if param_finder_data:
        params_list = param_finder_data.get("params") or []
        param_names = _extract_param_names(params_list)

    if path_scanner_data:
        paths_found = path_scanner_data.get("findings") or []
        base = path_scanner_data.get("base_url") or target

    if fuzzer_data:
        anomalies_count = len(fuzzer_data.get("anomalies") or [])
        fuzzer_params = fuzzer_data.get("params") or fuzzer_data.get("param")
        if isinstance(fuzzer_params, list):
            param_names = list(set(param_names + fuzzer_params))
        elif fuzzer_params and fuzzer_params not in param_names:
            param_names.append(str(fuzzer_params))

    if security_headers_data:
        header_issues = security_headers_data.get("issues") or []

    # Construir hotspots: rutas + params
    sensitive_paths = ["admin", "login", "config", "backup", "api", "debug", "wp-admin"]
    for pf in paths_found:
        url = pf.get("url") or ""
        path = pf.get("path") or ""
        status = pf.get("status")
        path_lower = path.lower()

        priority = "low"
        reasons: List[str] = []

        if status in (200, 201):
            priority = "medium"
            reasons.append("Ruta accesible (200)")
        elif status in (401, 403):
            priority = "medium"
            reasons.append("Ruta con auth (401/403)")

        for sp in sensitive_paths:
            if sp in path_lower:
                priority = "high"
                reasons.append(f"Ruta sensible ({sp})")
                break

        if param_names:
            reasons.append(f"Params conocidos: {','.join(param_names[:5])}")

        if anomalies_count > 0:
            priority = "high"
            reasons.append(f"Fuzzer detectó {anomalies_count} anomalías")

        is_base = path in ("/", "") or url.rstrip("/") == target.rstrip("/")
        hotspots.append({
            "url": url,
            "path": path or "/",
            "params": param_names[:10],
            "path_status": status,
            "fuzzer_anomalies": anomalies_count if is_base else 0,
            "priority": priority,
            "reason": "; ".join(reasons) if reasons else "Ruta escaneada",
        })

    # Si no hay paths pero hay params, crear hotspot base
    if not hotspots and param_names:
        hotspots.append({
            "url": target,
            "path": "/",
            "params": param_names,
            "path_status": None,
            "fuzzer_anomalies": anomalies_count,
            "priority": "high" if anomalies_count > 0 else "medium",
            "reason": f"Params encontrados: {','.join(param_names)}; fuzzer anomalías: {anomalies_count}",
        })

    # Summary
    high = sum(1 for h in hotspots if h["priority"] == "high")
    medium = sum(1 for h in hotspots if h["priority"] == "medium")
    low = sum(1 for h in hotspots if h["priority"] == "low")
    summary = {"high": high, "medium": medium, "low": low}

    # Recomendaciones
    recommendations: List[str] = []
    if param_names:
        recommendations.append(f"Priorizar params {','.join(param_names[:5])} para SQLi/XSS/SSTI")
    if high > 0:
        recommendations.append(f"Revisar {high} hotspot(s) de prioridad alta")
    if header_issues:
        crit = [i for i in header_issues if (i.get("severity") or "").upper() == "HIGH"]
        if crit:
            recommendations.append(f"Cabeceras críticas faltantes: {', '.join(i.get('header','') for i in crit[:3])}")
    if anomalies_count > 0:
        recommendations.append("Investigar anomalías de longitud en respuestas del fuzzer")

    return {
        "target": target,
        "hotspots": hotspots,
        "summary": summary,
        "param_count": len(param_names),
        "path_count": len(paths_found),
        "anomalies_count": anomalies_count,
        "header_issues_count": len(header_issues),
        "recommendations": recommendations,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Correlacionar hallazgos de param_finder, path_scanner, http_param_fuzzer y security_headers"
    )
    parser.add_argument(
        "--target",
        type=str,
        required=True,
        help="URL base del target (ej. https://example.com)",
    )
    parser.add_argument(
        "--input",
        type=str,
        nargs="*",
        default=[],
        help="Rutas a ficheros JSON (outputs de los scripts)",
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="Leer array de JSON desde stdin (cada linea un JSON o un array)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Salida JSON",
    )
    args = parser.parse_args()

    param_finder_data: Optional[Dict] = None
    path_scanner_data: Optional[Dict] = None
    fuzzer_data: Optional[Dict] = None
    security_headers_data: Optional[Dict] = None

    def process_obj(obj: Any) -> None:
        nonlocal param_finder_data, path_scanner_data, fuzzer_data, security_headers_data
        if not isinstance(obj, dict):
            return
        kind = _detect_and_parse(obj)
        if kind == "param_finder":
            param_finder_data = obj
        elif kind == "path_scanner":
            path_scanner_data = obj
        elif kind == "http_param_fuzzer":
            fuzzer_data = obj
        elif kind == "security_headers":
            security_headers_data = obj

    # Cargar desde --input
    for path in args.input or []:
        p = Path(path)
        if p.exists():
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        for item in data:
                            process_obj(item)
                    else:
                        process_obj(data)
            except (json.JSONDecodeError, OSError):
                pass

    # Cargar desde stdin
    if args.stdin and not sys.stdin.isatty():
        try:
            raw = sys.stdin.read()
            data = json.loads(raw)
            if isinstance(data, list):
                for item in data:
                    process_obj(item)
            elif isinstance(data, dict):
                steps = data.get("steps") or []
                for s in steps:
                    preview = s.get("stdout_preview") or ""
                    try:
                        obj = json.loads(preview)
                        process_obj(obj)
                    except json.JSONDecodeError:
                        pass
                process_obj(data)
        except json.JSONDecodeError:
            pass

    result = correlate(
        target=args.target,
        param_finder_data=param_finder_data,
        path_scanner_data=path_scanner_data,
        fuzzer_data=fuzzer_data,
        security_headers_data=security_headers_data,
    )

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Target: {result['target']}")
        print(f"Hotspots: {len(result['hotspots'])} (high={result['summary']['high']}, medium={result['summary']['medium']}, low={result['summary']['low']})")
        for h in result["hotspots"][:10]:
            print(f"  [{h['priority']}] {h['url']} params={h['params']} - {h['reason']}")
        if result["recommendations"]:
            print("\nRecomendaciones:")
            for r in result["recommendations"]:
                print(f"  - {r}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
