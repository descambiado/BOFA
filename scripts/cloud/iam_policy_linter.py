#!/usr/bin/env python3
"""
IAM Policy Linter - BOFA
========================

Analiza políticas IAM (JSON) en formato AWS/GCP/Azure genérico para detectar
configuraciones inseguras: permisos excesivos, wildcards peligrosos, acciones
críticas sin restricción, etc. Opera sobre ficheros locales; no requiere APIs.

Uso:
    python3 iam_policy_linter.py --policy policy.json --json
    python3 iam_policy_linter.py --policy policy.json
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional


# Acciones consideradas de alto riesgo (ejemplos genéricos)
_HIGH_RISK_ACTIONS = {
    "*", "iam:*", "iam:Create*", "iam:Delete*", "iam:Put*", "iam:Attach*", "iam:Detach*",
    "sts:AssumeRole*", "sts:GetFederationToken", "cloudtrail:StopLogging",
    "logs:DeleteLogGroup", "s3:DeleteBucket", "s3:PutBucketPolicy",
}
_WILDCARD_PATTERNS = ("*", "?*", "*:*", "**")


def _load_policy(path: str) -> Optional[Dict]:
    """Carga y parsea un fichero de política JSON."""
    p = Path(path)
    if not p.exists():
        return None
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def _extract_statements(policy: Dict) -> List[Dict]:
    """Extrae statements de una política (AWS-style o GCP/Azure adaptado)."""
    statements = []
    if "Statement" in policy:
        sts = policy["Statement"]
        if isinstance(sts, dict):
            sts = [sts]
        statements.extend(sts)
    if "policy" in policy and isinstance(policy["policy"], dict):
        statements.extend(_extract_statements(policy["policy"]))
    return statements


def _extract_actions(stmt: Dict) -> List[str]:
    """Extrae acciones de un statement."""
    actions = []
    for key in ("Action", "action", "actions"):
        if key in stmt:
            val = stmt[key]
            if isinstance(val, str):
                actions.append(val)
            elif isinstance(val, list):
                actions.extend(val)
            break
    return actions


def _extract_resources(stmt: Dict) -> List[str]:
    """Extrae recursos de un statement."""
    resources = []
    for key in ("Resource", "resource", "resources"):
        if key in stmt:
            val = stmt[key]
            if isinstance(val, str):
                resources.append(val)
            elif isinstance(val, list):
                resources.extend(val)
            break
    return resources


def _check_wildcards(actions: List[str], resources: List[str]) -> List[Dict]:
    """Detecta wildcards peligrosos en acciones y recursos."""
    issues = []
    for a in actions:
        if a in _WILDCARD_PATTERNS or a == "*" or (isinstance(a, str) and "*" in a and a.endswith("*")):
            issues.append({
                "type": "wildcard_action",
                "severity": "HIGH",
                "detail": f"Acción con wildcard: {a}",
                "remediation": "Usar acciones específicas en lugar de wildcards",
            })
    for r in resources:
        if isinstance(r, str) and r in ("*", "arn:aws:*:*:*:*"):
            issues.append({
                "type": "wildcard_resource",
                "severity": "CRITICAL",
                "detail": f"Recurso con wildcard: {r}",
                "remediation": "Restringir recursos a ARNs específicos",
            })
    return issues


def _check_high_risk_actions(actions: List[str]) -> List[Dict]:
    """Detecta acciones de alto riesgo."""
    issues = []
    for a in actions:
        a_norm = (a or "").strip().lower()
        if a_norm in {x.lower() for x in _HIGH_RISK_ACTIONS}:
            issues.append({
                "type": "high_risk_action",
                "severity": "HIGH",
                "detail": f"Acción de alto riesgo: {a}",
                "remediation": "Revisar si es estrictamente necesaria; aplicar condiciones",
            })
        elif "*" in a and "iam" in a_norm:
            issues.append({
                "type": "iam_wildcard",
                "severity": "CRITICAL",
                "detail": f"Permiso IAM amplio: {a}",
                "remediation": "Evitar wildcards en IAM; usar permisos mínimos",
            })
    return issues


def _check_effect_allow_all(stmt: Dict, actions: List[str], resources: List[str]) -> List[Dict]:
    """Detecta Allow con acciones/recursos muy amplios."""
    issues = []
    effect = (stmt.get("Effect") or stmt.get("effect") or "").upper()
    if effect != "ALLOW":
        return issues
    if not actions and not resources:
        return issues
    has_wildcard_action = any("*" in str(a) for a in actions)
    has_wildcard_resource = any("*" in str(r) or "arn:aws:*" in str(r) for r in resources)
    if has_wildcard_action and has_wildcard_resource:
        issues.append({
            "type": "allow_all",
            "severity": "CRITICAL",
            "detail": "Allow con acciones y recursos con wildcard (equivalente a admin)",
            "remediation": "Aplicar principio de mínimo privilegio",
        })
    return issues


def lint_policy(policy_path: str) -> Dict[str, Any]:
    """Ejecuta el análisis de la política y devuelve resultado estructurado."""
    policy = _load_policy(policy_path)
    if policy is None:
        return {"error": f"No se pudo cargar la política desde {policy_path}", "issues": []}

    all_issues = []
    statements = _extract_statements(policy)

    for i, stmt in enumerate(statements):
        actions = _extract_actions(stmt)
        resources = _extract_resources(stmt)
        all_issues.extend(_check_wildcards(actions, resources))
        all_issues.extend(_check_high_risk_actions(actions))
        all_issues.extend(_check_effect_allow_all(stmt, actions, resources))

    # Deduplicar por tipo+detail
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
        "policy_path": policy_path,
        "statements_count": len(statements),
        "issues_count": len(unique),
        "issues": unique,
        "summary": {
            "critical": critical,
            "high": high,
            "medium": medium,
        },
        "score": max(0, 100 - critical * 40 - high * 15 - medium * 5),
    }


def main():
    parser = argparse.ArgumentParser(description="Analizar política IAM (JSON) para detectar misconfiguraciones")
    parser.add_argument("--policy", type=str, required=True, help="Ruta al fichero de política JSON")
    parser.add_argument("--json", action="store_true", help="Salida JSON (recomendada para IA/flows)")
    args = parser.parse_args()

    result = lint_policy(args.policy)

    if "error" in result and result["issues_count"] == 0:
        if args.json:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print(f"Error: {result['error']}", file=sys.stderr)
        sys.exit(1)

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"Política: {result['policy_path']}")
        print(f"Statements: {result['statements_count']}")
        print(f"Issues: {result['issues_count']} (score: {result['score']})")
        if result["issues"]:
            print("Problemas detectados:")
            for iss in result["issues"]:
                print(f"  [{iss['severity']}] {iss['type']}: {iss['detail']}")
        else:
            print("No se detectaron problemas evidentes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
