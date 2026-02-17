#!/usr/bin/env python3
"""
PCAP Proto Counter - BOFA Forensics
===================================

Cuenta protocolos basicos en un fichero PCAP pequeno:
- TCP, UDP, ICMP
- HTTP (puertos 80, 8080, 8000)
- TLS (puertos 443, 8443)
- DNS (puerto 53)

Uso:
    python3 pcap_proto_counter.py --file captura.pcap --json

Nota: este script intenta usar scapy si esta instalado. Si no, devuelve un error
claro en JSON/STDERR y codigo de salida distinto de cero.
"""

import argparse
import json
import sys
from typing import Dict, Any

try:
    from scapy.all import rdpcap  # type: ignore
    from scapy.layers.inet import TCP, UDP, ICMP  # type: ignore
except Exception:  # pragma: no cover - import opcional
    rdpcap = None  # type: ignore
    TCP = UDP = ICMP = None  # type: ignore


def analyze_pcap(path: str, limit: int) -> Dict[str, Any]:
    if rdpcap is None:
        return {"error": "scapy no esta instalado (pip install scapy)", "file": path}
    try:
        packets = rdpcap(path, count=limit)  # type: ignore
    except FileNotFoundError:
        return {"error": f"Archivo no encontrado: {path}", "file": path}
    except Exception as e:
        return {"error": str(e), "file": path}

    counts = {
        "total_packets": 0,
        "tcp": 0,
        "udp": 0,
        "icmp": 0,
        "dns": 0,
        "http": 0,
        "tls": 0,
        "other": 0,
    }

    for pkt in packets:
        counts["total_packets"] += 1
        proto_tag = "other"
        if TCP is not None and pkt.haslayer(TCP):  # type: ignore
            counts["tcp"] += 1
            proto_tag = "tcp"
            dport = int(pkt[TCP].dport)  # type: ignore
            sport = int(pkt[TCP].sport)  # type: ignore
            if dport in (80, 8080, 8000) or sport in (80, 8080, 8000):
                counts["http"] += 1
            if dport in (443, 8443) or sport in (443, 8443):
                counts["tls"] += 1
        elif UDP is not None and pkt.haslayer(UDP):  # type: ignore
            counts["udp"] += 1
            proto_tag = "udp"
            dport = int(pkt[UDP].dport)  # type: ignore
            sport = int(pkt[UDP].sport)  # type: ignore
            if dport == 53 or sport == 53:
                counts["dns"] += 1
        elif ICMP is not None and pkt.haslayer(ICMP):  # type: ignore
            counts["icmp"] += 1
            proto_tag = "icmp"
        else:
            counts["other"] += 1

        # Ajustar other si ya se conto un proto concreto
        if proto_tag != "other":
            # Si ya se incrementó otro conteo, no sumamos en other
            pass

    return counts


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Contar protocolos basicos (TCP, UDP, ICMP, HTTP, TLS, DNS) en un PCAP pequeno"
    )
    parser.add_argument("--file", required=True, help="Ruta al fichero PCAP a analizar")
    parser.add_argument(
        "--limit",
        type=int,
        default=2000,
        help="Numero maximo de paquetes a leer (por defecto 2000)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Si es true, imprime salida JSON parseable (para IA/flows); si no, resumen humano",
    )
    args = parser.parse_args()

    result = analyze_pcap(args.file, args.limit)
    if "error" in result:
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"Error: {result['error']}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps({"file": args.file, "limit": args.limit, "counts": result}, indent=2))
    else:
        print(f"File: {args.file}")
        print(f"Total packets (<= {args.limit}): {result['total_packets']}")
        for key in ["tcp", "udp", "icmp", "dns", "http", "tls", "other"]:
            print(f"{key.upper()}: {result[key]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

