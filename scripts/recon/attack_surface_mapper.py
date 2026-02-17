#!/usr/bin/env python3
"""
Attack Surface Mapper - BOFA
============================

Genera un mapa unificado de superficie de ataque para un target (URL o host).
Agrega todas las capacidades de recon de BOFA en un plan de campaña ordenado:
qué ejecutar, en qué orden, con qué parámetros. La IA puede ejecutar el plan.

Uso:
    python3 attack_surface_mapper.py --target https://example.com --json
    python3 attack_surface_mapper.py --target 192.168.1.1 --type host --json
"""

import argparse
import json
import sys
from typing import Dict, Any, List
from urllib.parse import urlparse


def _is_url(s: str) -> bool:
    return s.startswith("http://") or s.startswith("https://")


def _map_url_target(target: str) -> Dict[str, Any]:
    """Plan de campaña para target URL."""
    return {
        "target": target,
        "target_type": "url",
        "domain": urlparse(target).netloc if _is_url(target) else target,
        "phases": [
            {
                "phase": 1,
                "name": "Recon básico",
                "steps": [
                    {"module": "recon", "script": "web_discover", "params": {"url": target}},
                    {"module": "recon", "script": "http_headers", "params": {"url": target, "json": True}},
                    {"module": "web", "script": "robots_txt", "params": {"url": target, "json": True}},
                ],
                "goal": "Descubrir estructura y cabeceras",
            },
            {
                "phase": 2,
                "name": "Seguridad web",
                "steps": [
                    {"module": "web", "script": "security_headers_analyzer", "params": {"url": target, "json": True}},
                    {"module": "web", "script": "path_scanner", "params": {"url": target, "json": True}},
                ],
                "goal": "Cabeceras de seguridad y rutas expuestas",
            },
            {
                "phase": 3,
                "name": "Parámetros y diferencias",
                "steps": [
                    {"module": "web", "script": "param_finder", "params": {"url": target, "json": True}},
                    {"module": "web", "script": "response_classifier", "params": {"url": target, "json": True}},
                ],
                "goal": "Parámetros para fuzzing, rutas con respuestas anómalas",
            },
            {
                "phase": 4,
                "name": "Inteligencia de vulnerabilidades",
                "steps": [
                    {"module": "vulnerability", "script": "cve_lookup", "params": {"limit": 10}},
                    {"module": "vulnerability", "script": "exploit_chain_suggester", "params": {"product": "web_framework", "json": True}},
                ],
                "goal": "CVE relevantes y cadenas sugeridas",
            },
        ],
        "flows_recommended": ["full_recon", "bug_bounty_web_full", "web_security_review"],
        "total_steps": 10,
    }


def _map_host_target(target: str) -> Dict[str, Any]:
    """Plan de campaña para target host (IP)."""
    return {
        "target": target,
        "target_type": "host",
        "phases": [
            {
                "phase": 1,
                "name": "Recon de servicios",
                "steps": [
                    {"module": "red", "script": "service_banner_collector", "params": {"target": target, "ports": "22,80,443,3306,5432,8080", "safe": False, "json": True}},
                ],
                "goal": "Banners de servicios expuestos",
            },
            {
                "phase": 2,
                "name": "Segmentación y zero trust",
                "steps": [
                    {"module": "zero_trust", "script": "segment_policy_checker", "params": {"policy": "scripts/zero_trust/sample_segment_policy.json", "json": True}},
                ],
                "goal": "Validar políticas de segmentación",
            },
            {
                "phase": 3,
                "name": "Inteligencia de vulnerabilidades",
                "steps": [
                    {"module": "vulnerability", "script": "exploit_chain_suggester", "params": {"product": "local_service", "json": True}},
                ],
                "goal": "Cadenas sugeridas para servicios locales",
            },
        ],
        "flows_recommended": ["network_zero_trust_overview"],
        "total_steps": 3,
    }


def map_surface(target: str, target_type: str = "auto") -> Dict[str, Any]:
    """Genera mapa de superficie de ataque."""
    if target_type == "host" or (target_type == "auto" and not _is_url(target)):
        return _map_host_target(target)
    return _map_url_target(target)


def main():
    parser = argparse.ArgumentParser(description="Mapa unificado de superficie de ataque para un target")
    parser.add_argument("--target", type=str, required=True, help="URL (https://...) o host (IP)")
    parser.add_argument("--type", type=str, choices=["auto", "url", "host"], default="auto", help="Tipo de target (auto detecta)")
    parser.add_argument("--json", action="store_true", help="Salida JSON")
    args = parser.parse_args()

    result = map_surface(args.target, args.type)

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"Target: {result['target']} ({result['target_type']})")
        print(f"Total pasos: {result['total_steps']}")
        print("\nFases:")
        for p in result["phases"]:
            print(f"  Fase {p['phase']}: {p['name']} - {p['goal']}")
            for s in p["steps"]:
                print(f"    -> {s['module']}/{s['script']}")
        print("\nFlujos recomendados:", ", ".join(result["flows_recommended"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
