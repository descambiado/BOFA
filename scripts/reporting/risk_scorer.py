#!/usr/bin/env python3
"""
Risk Scorer - BOFA Reporting
=============================

Calcula puntuación de riesgo (0-10) a partir de hallazgos correlacionados.
Acepta output de findings_correlator o estructura similar.

Pesos: hotspot high=3, medium=2, low=1; anomaly=2; missing critical header=1.

Uso:
    python3 risk_scorer.py --input findings.json --json
    python3 risk_scorer.py --stdin < findings.json --json
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


def compute_risk(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calcula score de riesgo y nivel a partir de hallazgos.
    """
    hotspots = data.get("hotspots") or []
    anomalies_count = data.get("anomalies_count", 0)
    header_issues = data.get("header_issues") or []
    header_issues_count = data.get("header_issues_count", 0)
    if isinstance(header_issues, int):
        header_issues = []
    if not header_issues and isinstance(header_issues_count, int) and header_issues_count > 0:
        header_issues = [{"severity": "HIGH"}] * min(header_issues_count, 5)

    score = 0.0
    breakdown: Dict[str, float] = {}
    factors: List[str] = []

    for h in hotspots:
        prio = (h.get("priority") or "low").lower()
        if prio == "high":
            score += 3.0
            factors.append(f"Hotspot high: {h.get('url', '')[:60]}")
        elif prio == "medium":
            score += 2.0
            factors.append(f"Hotspot medium: {h.get('path', '')}")
        else:
            score += 1.0

    if hotspots:
        breakdown["hotspots"] = min(6.0, len(hotspots) * 1.5)

    if anomalies_count > 0:
        add = min(4.0, anomalies_count * 2.0)
        score += add
        breakdown["anomalies"] = add
        factors.append(f"Fuzzer: {anomalies_count} anomalías")

    high_headers = sum(
        1 for i in header_issues
        if isinstance(i, dict) and (i.get("severity") or "").upper() == "HIGH"
    )
    if high_headers > 0:
        add = min(2.0, high_headers * 1.0)
        score += add
        breakdown["header_issues"] = add
        factors.append(f"Cabeceras críticas faltantes: {high_headers}")

    score = min(10.0, score)

    if score >= 7:
        level = "critical"
    elif score >= 5:
        level = "high"
    elif score >= 3:
        level = "medium"
    elif score >= 1:
        level = "low"
    else:
        level = "info"

    return {
        "score": round(score, 1),
        "level": level,
        "breakdown": breakdown,
        "factors": factors[:10],
        "hotspots_count": len(hotspots),
        "anomalies_count": anomalies_count,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Calcular puntuación de riesgo desde hallazgos correlacionados"
    )
    parser.add_argument(
        "--input",
        type=str,
        default=None,
        help="Ruta al JSON de findings_correlator o similar",
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="Leer JSON desde stdin",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Salida JSON",
    )
    args = parser.parse_args()

    data: Optional[Dict] = None
    if args.stdin and not sys.stdin.isatty():
        try:
            data = json.load(sys.stdin)
        except json.JSONDecodeError:
            print("Error: JSON inválido", file=sys.stderr)
            return 1
    elif args.input:
        p = Path(args.input)
        if not p.exists():
            print(f"Error: no encontrado {args.input}", file=sys.stderr)
            return 1
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
    else:
        print("Error: usar --input o --stdin", file=sys.stderr)
        return 1

    if not data:
        data = {}

    result = compute_risk(data)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Risk Score: {result['score']}/10 ({result['level']})")
        print(f"Hotspots: {result['hotspots_count']} | Anomalies: {result['anomalies_count']}")
        if result.get("factors"):
            print("Factors:")
            for f in result["factors"]:
                print(f"  - {f}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
