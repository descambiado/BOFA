#!/usr/bin/env python3
"""
Storage ACL Auditor - BOFA
==========================

Audita configuraciones de ACL de almacenamiento (S3/GCS/Azure Blob style)
desde ficheros JSON locales. Detecta buckets/containers públicos, ACLs
excesivamente permisivas, políticas sin restricción de origen, etc.
No requiere APIs ni conexión a cloud; opera sobre ficheros de configuración.

Uso:
    python3 storage_acl_auditor.py --config bucket_config.json --json
    python3 storage_acl_auditor.py --config bucket_config.json
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional


_PUBLIC_INDICATORS = ("public", "public-read", "public-read-write", "allUsers", "allAuthenticatedUsers")
_RESTRICTIVE_INDICATORS = ("private", "authenticated-read", "project-private")


def _load_config(path: str) -> Optional[Dict]:
    """Carga configuración de storage desde JSON."""
    p = Path(path)
    if not p.exists():
        return None
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def _extract_buckets(config: Dict) -> List[Dict]:
    """Extrae definiciones de buckets/containers de la config."""
    buckets = []
    if "buckets" in config:
        buckets.extend(config["buckets"] if isinstance(config["buckets"], list) else [config["buckets"]])
    if "Buckets" in config:
        buckets.extend(config["Buckets"] if isinstance(config["Buckets"], list) else [config["Buckets"]])
    if "storage" in config and isinstance(config["storage"], dict):
        buckets.extend(_extract_buckets(config["storage"]))
    # Si es un solo bucket
    if "name" in config or "Name" in config:
        buckets.append(config)
    return buckets


def _extract_policies(config: Dict) -> List[Dict]:
    """Extrae políticas/ACLs de la config."""
    policies = []
    if "policy" in config:
        policies.append(config["policy"] if isinstance(config["policy"], dict) else {})
    if "acl" in config:
        acl = config["acl"]
        if isinstance(acl, str):
            policies.append({"acl": acl})
        elif isinstance(acl, dict):
            policies.append(acl)
    if "iamConfiguration" in config:
        policies.append(config.get("iamConfiguration", {}))
    if "publicAccessBlock" in config:
        policies.append({"publicAccessBlock": config["publicAccessBlock"]})
    return policies


def _check_public_access(bucket: Dict, bucket_name: str) -> List[Dict]:
    """Detecta acceso público explícito."""
    issues = []
    acl = bucket.get("acl") or bucket.get("ACL") or bucket.get("Acl")
    if isinstance(acl, str) and acl.lower() in [x.lower() for x in _PUBLIC_INDICATORS]:
        issues.append({
            "type": "public_acl",
            "severity": "CRITICAL",
            "detail": f"ACL pública en {bucket_name}: {acl}",
            "remediation": "Usar ACL privada o authenticated-read",
        })
    if isinstance(acl, list):
        for grant in acl:
            grantee = (grant.get("Grantee") or grant.get("grantee") or {}).get("URI") or grant.get("uri", "")
            if "allUsers" in str(grantee) or "AllUsers" in str(grantee):
                issues.append({
                    "type": "public_grant",
                    "severity": "CRITICAL",
                    "detail": f"Grant a allUsers en {bucket_name}",
                    "remediation": "Eliminar grants públicos",
                })
    return issues


def _check_bucket_policy(bucket: Dict, bucket_name: str) -> List[Dict]:
    """Analiza política de bucket para Principals amplios."""
    issues = []
    policy = bucket.get("Policy") or bucket.get("policy")
    if not policy or not isinstance(policy, dict):
        return issues
    statements = policy.get("Statement") or policy.get("statement") or []
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        principal = stmt.get("Principal") or stmt.get("principal") or {}
        if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
            issues.append({
                "type": "policy_principal_wildcard",
                "severity": "CRITICAL",
                "detail": f"Política con Principal * en {bucket_name}",
                "remediation": "Restringir Principal a cuentas/roles específicos",
            })
        if isinstance(principal, dict):
            svc = principal.get("Service") or principal.get("service")
            if svc and "*" in str(svc):
                issues.append({
                    "type": "policy_service_wildcard",
                    "severity": "HIGH",
                    "detail": f"Política con Service wildcard en {bucket_name}",
                    "remediation": "Especificar servicios concretos",
                })
    return issues


def _check_public_access_block(bucket: Dict, bucket_name: str) -> List[Dict]:
    """Verifica si publicAccessBlock está habilitado."""
    issues = []
    pab = bucket.get("PublicAccessBlockConfiguration") or bucket.get("publicAccessBlock") or bucket.get("public_access_block")
    if pab is None:
        issues.append({
            "type": "no_public_access_block",
            "severity": "MEDIUM",
            "detail": f"Sin publicAccessBlock en {bucket_name}",
            "remediation": "Habilitar BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls, RestrictPublicBuckets",
        })
    elif isinstance(pab, dict):
        for key in ("BlockPublicAcls", "block_public_acls", "BlockPublicPolicy", "block_public_policy"):
            if pab.get(key) is False:
                issues.append({
                    "type": "public_access_not_blocked",
                    "severity": "HIGH",
                    "detail": f"publicAccessBlock permite acceso público en {bucket_name}",
                    "remediation": "Bloquear todas las opciones de acceso público",
                })
                break
    return issues


def audit_storage(config_path: str) -> Dict[str, Any]:
    """Ejecuta la auditoría de ACL de storage y devuelve resultado estructurado."""
    config = _load_config(config_path)
    if config is None:
        return {"error": f"No se pudo cargar la config desde {config_path}", "findings": []}

    all_findings = []
    buckets = _extract_buckets(config)

    if not buckets:
        # Intentar como política directa
        policies = _extract_policies(config)
        if policies:
            buckets = [{"policy": p, "name": "default"} for p in policies]

    for bucket in buckets:
        name = bucket.get("name") or bucket.get("Name") or bucket.get("id") or "unknown"
        all_findings.extend(_check_public_access(bucket, str(name)))
        all_findings.extend(_check_bucket_policy(bucket, str(name)))
        all_findings.extend(_check_public_access_block(bucket, str(name)))

    # Deduplicar
    seen = set()
    unique = []
    for f in all_findings:
        key = (f["type"], f["detail"])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    critical = sum(1 for u in unique if u["severity"] == "CRITICAL")
    high = sum(1 for u in unique if u["severity"] == "HIGH")
    medium = sum(1 for u in unique if u["severity"] == "MEDIUM")

    return {
        "config_path": config_path,
        "buckets_reviewed": len(buckets),
        "findings_count": len(unique),
        "findings": unique,
        "summary": {"critical": critical, "high": high, "medium": medium},
        "score": max(0, 100 - critical * 40 - high * 15 - medium * 5),
    }


def main():
    parser = argparse.ArgumentParser(description="Auditar ACL de storage (S3/GCS style) desde JSON local")
    parser.add_argument("--config", type=str, required=True, help="Ruta al fichero de configuración JSON")
    parser.add_argument("--json", action="store_true", help="Salida JSON (recomendada para IA/flows)")
    args = parser.parse_args()

    result = audit_storage(args.config)

    if "error" in result and result["findings_count"] == 0:
        if args.json:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print(f"Error: {result['error']}", file=sys.stderr)
        sys.exit(1)

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"Config: {result['config_path']}")
        print(f"Buckets revisados: {result['buckets_reviewed']}")
        print(f"Findings: {result['findings_count']} (score: {result['score']})")
        if result["findings"]:
            print("Hallazgos:")
            for f in result["findings"]:
                print(f"  [{f['severity']}] {f['type']}: {f['detail']}")
        else:
            print("No se detectaron problemas evidentes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
