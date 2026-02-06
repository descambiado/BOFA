#!/usr/bin/env python3
"""
Log Anomaly Score - BOFA Blue
=============================

Calcula un score de riesgo sencillo a partir de la salida JSON de:
- blue/log_guardian (detections, suspicious_ips, threat_summary)
- blue/log_quick_summary (failed_logins, sudo_events, error_lines, ips, users)

Entrada:
- Fichero JSON con la salida de uno de esos scripts (o similar).

Uso:
    python3 log_anomaly_score.py --input log_guardian.json --json
"""

import argparse
import json
import sys
from datetime import datetime
from typing import Dict, Any


def _detect_source(data: Dict[str, Any]) -> str:
    if "detections" in data or "threat_summary" in data:
        return "log_guardian"
    if "failed_logins" in data or "sudo_events" in data:
        return "log_quick_summary"
    return "unknown"


def compute_score(data: Dict[str, Any]) -> Dict[str, Any]:
    source = _detect_source(data)
    metrics: Dict[str, Any] = {}
    score = 0.0
    notes = []

    # Campos comunes
    total_lines = data.get("total_lines") or data.get("total_lines".upper()) or 0
    metrics["total_lines"] = total_lines

    # Caso log_quick_summary
    if source in ("log_quick_summary", "unknown"):
        failed = int(data.get("failed_logins", 0) or 0)
        accepted = int(data.get("accepted_logins", 0) or 0)
        sudo_events = int(data.get("sudo_events", 0) or 0)
        error_lines = int(data.get("error_lines", 0) or 0)
        ips = data.get("ips") or {}
        users = data.get("users") or {}

        metrics.update(
            {
                "failed_logins": failed,
                "accepted_logins": accepted,
                "sudo_events": sudo_events,
                "error_lines": error_lines,
                "ips_count": len(ips),
                "users_count": len(users),
            }
        )

        score += failed * 0.8
        score += sudo_events * 1.0
        score += error_lines * 0.2

        if failed > 20:
            notes.append("Muchos intentos de login fallidos (posible fuerza bruta).")
        if sudo_events > 50:
            notes.append("Muchos eventos sudo (posible abuso de privilegios).")

    # Caso log_guardian
    if source in ("log_guardian", "unknown"):
        threat_summary = data.get("threat_summary") or {}
        suspicious_ips = data.get("suspicious_ips") or {}
        detections = data.get("detections") or {}

        total_threats = sum(int(v) for v in threat_summary.values())
        metrics.update(
            {
                "total_threats": total_threats,
                "suspicious_ips_count": len(suspicious_ips),
                "detections_types": len(detections.keys()),
            }
        )

        score += total_threats * 1.5
        score += len(suspicious_ips) * 5.0

        if total_threats > 0:
            notes.append("Se han detectado eventos de amenaza en el log.")
        if suspicious_ips:
            notes.append("Hay IPs marcadas como sospechosas (actividad repetida).")

    # Normalizar a 0-100
    if score < 0:
        score = 0.0
    if score > 100:
        score = 100.0

    # Top IPs / usuarios si existen
    top_ips = []
    if isinstance(data.get("ips"), dict):
        top_ips = sorted(data["ips"].items(), key=lambda x: x[1], reverse=True)[:5]
    if isinstance(data.get("suspicious_ips"), dict) and not top_ips:
        top_ips = sorted(data["suspicious_ips"].items(), key=lambda x: x[1], reverse=True)[:5]
    top_users = []
    if isinstance(data.get("users"), dict):
        top_users = sorted(data["users"].items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        "source": source,
        "file": data.get("file"),
        "risk_score": round(score, 2),
        "metrics": metrics,
        "top_ips": [{"ip": ip, "count": count} for ip, count in top_ips],
        "top_users": [{"user": user, "count": count} for user, count in top_users],
        "notes": notes,
        "analysis_time": datetime.now().isoformat(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Calcular un score de riesgo a partir de la salida JSON de log_guardian o log_quick_summary"
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Fichero JSON de entrada (salida de blue/log_guardian --json o blue/log_quick_summary --json)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Si es true, imprime salida JSON (para IA/flows). Por defecto imprime resumen humano.",
    )
    args = parser.parse_args()

    try:
        with open(args.input, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        err = {"error": f"Archivo no encontrado: {args.input}", "input": args.input}
        if args.json:
            print(json.dumps(err, indent=2))
        else:
            print(f"Error: archivo no encontrado: {args.input}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        err = {"error": f"JSON invalido: {e}", "input": args.input}
        if args.json:
            print(json.dumps(err, indent=2))
        else:
            print(f"Error: JSON invalido en {args.input}: {e}", file=sys.stderr)
        return 1

    result = compute_score(data)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Log file: {result.get('file') or args.input}")
        print(f"Source: {result['source']}")
        print(f"Risk score: {result['risk_score']}/100")
        if result["top_ips"]:
            print("\nTop IPs:")
            for item in result["top_ips"]:
                print(f"  {item['ip']}: {item['count']}")
        if result["top_users"]:
            print("\nTop users:")
            for item in result["top_users"]:
                print(f"  {item['user']}: {item['count']}")
        if result["notes"]:
            print("\nNotes:")
            for n in result["notes"]:
                print(f"  - {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

