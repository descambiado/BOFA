#!/usr/bin/env python3
"""
Service Banner Collector - BOFA
===============================

Recolecta banners de servicios (SSH, HTTP, etc.) en hosts:puertos.
Modo --safe: devuelve banners simulados sin conexión real (para pruebas/verify).
Sin --safe: intenta conexión TCP (requiere red; puede fallar).

Uso:
    python3 service_banner_collector.py --target 127.0.0.1 --safe --json
    python3 service_banner_collector.py --target 192.168.1.1 --ports 22,80,443 --json
"""

import argparse
import json
import socket
import sys
from typing import Dict, Any, List, Optional

# Puertos por defecto a probar
_DEFAULT_PORTS = [22, 80, 443, 3306, 5432, 8080, 8443]

# Banners simulados para modo safe (sin conexión)
_SAFE_BANNERS = {
    22: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
    80: "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0",
    443: "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0",
    3306: "5.7.42-MySQL",
    5432: "E",
    8080: "HTTP/1.1 200 OK\r\nServer: Apache-Coyote/1.1",
    8443: "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0",
}


def _parse_ports(ports_str: str) -> List[int]:
    """Parsea lista de puertos (ej. 22,80,443)."""
    result = []
    for p in ports_str.replace(" ", "").split(","):
        if p.isdigit():
            result.append(int(p))
    return result or _DEFAULT_PORTS


def _grab_banner_safe(host: str, port: int) -> Dict[str, Any]:
    """Devuelve banner simulado (modo safe)."""
    banner = _SAFE_BANNERS.get(port, f"[simulated] port {port}")
    return {
        "host": host,
        "port": port,
        "banner": banner[:200] if isinstance(banner, str) else str(banner)[:200],
        "mode": "simulated",
    }


def _grab_banner_real(host: str, port: int, timeout: float = 3.0) -> Dict[str, Any]:
    """Intenta obtener banner real por TCP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.send(b"\r\n")
        data = sock.recv(1024).decode("utf-8", errors="replace").strip()
        sock.close()
        return {
            "host": host,
            "port": port,
            "banner": data[:200] if data else "(empty)",
            "mode": "real",
        }
    except (socket.timeout, socket.error, OSError) as e:
        return {
            "host": host,
            "port": port,
            "banner": None,
            "error": str(e),
            "mode": "real",
        }


def collect(target: str, ports: List[int], safe: bool, timeout: float) -> Dict[str, Any]:
    """Recolecta banners y devuelve resultado estructurado."""
    # Parsear host:puerto si viene en target
    host = target
    if ":" in target:
        parts = target.rsplit(":", 1)
        if parts[1].isdigit():
            host = parts[0]
            ports = [int(parts[1])]

    results = []
    for port in ports:
        if safe:
            results.append(_grab_banner_safe(host, port))
        else:
            results.append(_grab_banner_real(host, port, timeout))

    return {
        "target": target,
        "host": host,
        "ports": ports,
        "safe_mode": safe,
        "banners": results,
        "count": len(results),
    }


def main():
    parser = argparse.ArgumentParser(description="Recolectar banners de servicios (SSH, HTTP, etc.)")
    parser.add_argument("--target", type=str, required=True, help="Host o host:puerto (ej. 127.0.0.1 o 192.168.1.1:22)")
    parser.add_argument("--ports", type=str, default="22,80,443", help="Puertos separados por coma (default: 22,80,443)")
    parser.add_argument("--safe", action="store_true", help="Modo seguro: banners simulados sin conexión real")
    parser.add_argument("--timeout", type=float, default=3.0, help="Timeout por puerto en segundos (solo modo real)")
    parser.add_argument("--json", action="store_true", help="Salida JSON (recomendada para IA/flows)")
    args = parser.parse_args()

    ports = _parse_ports(args.ports)
    result = collect(args.target, ports, args.safe, args.timeout)

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"Target: {result['target']}")
        print(f"Safe: {result['safe_mode']}")
        for b in result["banners"]:
            bn = b.get("banner") or b.get("error", "?")
            print(f"  {b['port']}: {bn[:80]}...")
    return 0


if __name__ == "__main__":
    sys.exit(main())
