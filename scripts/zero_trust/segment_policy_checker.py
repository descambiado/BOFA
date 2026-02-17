#!/usr/bin/env python3
"""
Segment Policy Checker - BOFA
==============================

Valida políticas de segmentación de red (Zero Trust) desde ficheros JSON.
Detecta reglas excesivamente permisivas, ausencia de deny-by-default,
puertos amplios, etc. No realiza conexiones de red; solo analiza la configuración.

Uso:
    python3 segment_policy_checker.py --policy policy.json --json
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional


def _load_policy(path: str) -> Optional[Dict]:
    """Carga política desde JSON."""
    p = Path(path)
    if not p.exists():
        return None
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def _extract_rules(policy: Dict) -> List[Dict]:
    """Extrae reglas de la política."""
    rules = []
    for key in ("rules", "Rules", "policies", "segments"):
        if key in policy:
            val = policy[key]
            if isinstance(val, list):
                rules.extend(val)
            elif isinstance(val, dict):
                rules.extend(val.values() if isinstance(next(iter(val.values()), None), dict) else [val])
            break
    if "allow" in policy or "deny" in policy:
        rules.append({"action": policy.get("allow", policy.get("deny")), "source": policy.get("source"), "dest": policy.get("dest")})
    return rules


def _check_deny_default(policy: Dict) -> List[Dict]:
    """Verifica si hay deny-by-default."""
    issues = []
    default = (policy.get("default") or policy.get("default_action") or "").lower()
    if default not in ("deny", "drop", "block"):
        issues.append({
            "type": "no_deny_default",
            "severity": "HIGH",
            "detail": f"default_action no es deny/drop (actual: {default or 'allow'})",
            "remediation": "Aplicar deny-by-default en segmentación Zero Trust",
        })
    return issues


def _check_wildcard_rules(rules: List[Dict]) -> List[Dict]:
    """Detecta reglas con wildcards peligrosos."""
    issues = []
    for i, r in enumerate(rules):
        src = r.get("source") or r.get("src") or r.get("Source") or "*"
        dst = r.get("dest") or r.get("destination") or r.get("Dest") or "*"
        ports = r.get("ports") or r.get("port") or r.get("Port") or []
        if isinstance(ports, int):
            ports = [ports]
        action = (r.get("action") or r.get("Action") or "allow").lower()
        if action in ("allow", "permit"):
            if src == "*" or src == "0.0.0.0/0":
                issues.append({
                    "type": "wildcard_source",
                    "severity": "CRITICAL",
                    "detail": f"Regla {i+1}: source * o 0.0.0.0/0 permite cualquier origen",
                    "remediation": "Restringir source a segmentos específicos",
                })
            if dst == "*" or dst == "0.0.0.0/0":
                issues.append({
                    "type": "wildcard_dest",
                    "severity": "CRITICAL",
                    "detail": f"Regla {i+1}: destination * permite cualquier destino",
                    "remediation": "Restringir destination a segmentos específicos",
                })
            if ports == "*" or (isinstance(ports, list) and len(ports) > 100):
                issues.append({
                    "type": "broad_port_range",
                    "severity": "HIGH",
                    "detail": f"Regla {i+1}: rango de puertos muy amplio",
                    "remediation": "Especificar solo los puertos necesarios",
                })
    return issues


def _check_missing_egress_restriction(policy: Dict) -> List[Dict]:
    """Verifica si falta restricción de egress."""
    issues = []
    if "egress" not in str(policy).lower() and "outbound" not in str(policy).lower():
        issues.append({
            "type": "no_egress_policy",
            "severity": "MEDIUM",
            "detail": "No se detecta política explícita de egress/outbound",
            "remediation": "Definir reglas de egress para limitar tráfico saliente",
        })
    return issues


def check_policy(path: str) -> Dict[str, Any]:
    """Ejecuta la validación y devuelve resultado estructurado."""
    policy = _load_policy(path)
    if policy is None:
        return {"error": f"No se pudo cargar la política desde {path}", "path": path, "issues": []}

    all_issues = []
    all_issues.extend(_check_deny_default(policy))
    rules = _extract_rules(policy)
    all_issues.extend(_check_wildcard_rules(rules))
    all_issues.extend(_check_missing_egress_restriction(policy))

    # Deduplicar
    seen = set()
    unique = []
    for iss in all_issues:
        key = (iss["type"], iss["detail"])
        if key not in seen:
            seen.add(key)
            unique.append(iss)

    critical = sum(1 for u in unique if u["severity"] == "CRITICAL")
    high = sum(1 for u in unique if u["severity"] == "HIGH")
    medium = sum(1 for u in unique if u["severity"] == "MEDIUM")

    return {
        "policy_path": path,
        "rules_count": len(rules),
        "issues_count": len(unique),
        "issues": unique,
        "summary": {"critical": critical, "high": high, "medium": medium},
        "score": max(0, 100 - critical * 40 - high * 15 - medium * 5),
    }


def main():
    parser = argparse.ArgumentParser(description="Validar políticas de segmentación Zero Trust desde JSON")
    parser.add_argument("--policy", type=str, required=True, help="Ruta al fichero de política JSON")
    parser.add_argument("--json", action="store_true", help="Salida JSON (recomendada para IA/flows)")
    args = parser.parse_args()

    result = check_policy(args.policy)

    if "error" in result and result["issues_count"] == 0:
        if args.json:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print(f"Error: {result['error']}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"Política: {result['policy_path']}")
        print(f"Reglas: {result['rules_count']}")
        print(f"Issues: {result['issues_count']} (score: {result['score']})")
        if result["issues"]:
            for iss in result["issues"]:
                print(f"  [{iss['severity']}] {iss['type']}: {iss['detail']}")
        else:
            print("No se detectaron problemas evidentes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
