#!/usr/bin/env python3
"""
Log Quick Summary - BOFA Blue
=============================

Resumen rapido de un fichero de log (auth/syslog):
- Cuenta intentos de login fallidos y aceptados.
- Cuenta lineas con sudo y errores.
- Resume IPs y usuarios mas frecuentes.

Uso:
    python3 log_quick_summary.py --file /var/log/auth.log --json
"""

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime


def analyze_log(path: str):
    stats = {
        "file": path,
        "total_lines": 0,
        "failed_logins": 0,
        "accepted_logins": 0,
        "sudo_events": 0,
        "error_lines": 0,
        "ips": Counter(),
        "users": Counter(),
        "analysis_time": datetime.now().isoformat(),
    }

    re_failed = re.compile(r"Failed password for (invalid user )?(?P<user>\\S+) from (?P<ip>\\d+\\.\\d+\\.\\d+\\.\\d+)", re.IGNORECASE)
    re_accepted = re.compile(r"Accepted password for (?P<user>\\S+)", re.IGNORECASE)
    re_ip_generic = re.compile(r"(?P<ip>\\d+\\.\\d+\\.\\d+\\.\\d+)")

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                stats["total_lines"] += 1
                lower = line.lower()
                m_fail = re_failed.search(line)
                if m_fail:
                    stats["failed_logins"] += 1
                    ip = m_fail.group("ip")
                    user = m_fail.group("user")
                    stats["ips"][ip] += 1
                    stats["users"][user] += 1
                m_acc = re_accepted.search(line)
                if m_acc:
                    stats["accepted_logins"] += 1
                    user = m_acc.group("user")
                    stats["users"][user] += 1
                    m_ip2 = re_ip_generic.search(line)
                    if m_ip2:
                        stats["ips"][m_ip2.group("ip")] += 1
                if "sudo" in lower:
                    stats["sudo_events"] += 1
                if "error" in lower or "fail" in lower:
                    stats["error_lines"] += 1
    except FileNotFoundError:
        return {"error": f"Archivo no encontrado: {path}", "file": path}
    except Exception as e:
        return {"error": str(e), "file": path}

    # Convertir Counters a dict normales
    stats["ips"] = dict(stats["ips"].most_common(20))
    stats["users"] = dict(stats["users"].most_common(20))
    return stats


def main():
    parser = argparse.ArgumentParser(description="Resumen rapido de eventos en un fichero de log")
    parser.add_argument("--file", required=True, help="Ruta del fichero de log a analizar")
    parser.add_argument("--json", action="store_true", help="Mostrar salida JSON (para IA/flows)")
    args = parser.parse_args()

    result = analyze_log(args.file)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if "error" in result:
            print(f"Error: {result['error']}", file=sys.stderr)
            return 1
        print(f"File: {result['file']}")
        print(f"Total lines: {result['total_lines']}")
        print(f"Failed logins: {result['failed_logins']}")
        print(f"Accepted logins: {result['accepted_logins']}")
        print(f"Sudo events: {result['sudo_events']}")
        print(f"Error lines: {result['error_lines']}")
        if result["ips"]:
            print("\nTop IPs:")
            for ip, count in result["ips"].items():
                print(f"  {ip}: {count}")
        if result["users"]:
            print("\nTop users:")
            for user, count in result["users"].items():
                print(f"  {user}: {count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

