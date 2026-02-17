#!/usr/bin/env python3
"""
Self-Hack Runner - BOFA
========================

Ejecuta el flujo bug_bounty_full_chain contra un target propio (hack ourselves)
usando las mismas herramientas que expone el MCP. Pensado para probar la seguridad
de tus propias webs (yungkuoo.com, sotyhub.com, localhost, etc.).

Usa --insecure automáticamente para certificados autofirmados (dev/test).

Uso:
    python3 tools/self_hack_runner.py https://yungkuoo.com
    python3 tools/self_hack_runner.py https://sotyhub.com   # Si no resuelve DNS: añade
                                                          # 127.0.0.1 sotyhub.com a /etc/hosts
    python3 tools/self_hack_runner.py https://127.0.0.1 --flow bug_bounty_full_chain
"""

import argparse
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# Usar las mismas funciones que expone el MCP (sin depender del paquete mcp)
from flows.flow_runner import run_flow, list_flows


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Self-hack: ejecutar flujo bug bounty contra tu propia infraestructura (MCP-style)"
    )
    parser.add_argument(
        "target",
        type=str,
        help="URL objetivo (ej. https://yungkuoo.com, https://sotyhub.com, https://127.0.0.1)",
    )
    parser.add_argument(
        "--flow",
        type=str,
        default="bug_bounty_full_chain",
        help="ID del flujo a ejecutar (default: bug_bounty_full_chain)",
    )
    parser.add_argument(
        "--suggest",
        action="store_true",
        help="Mostrar sugerencias de herramientas antes de ejecutar",
    )
    parser.add_argument(
        "--capabilities",
        action="store_true",
        help="Mostrar capacidades BOFA antes de ejecutar",
    )
    args = parser.parse_args()

    target = args.target.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    print(f"[Self-Hack] Target: {target}")
    print(f"[Self-Hack] Flow: {args.flow}")
    print()

    if args.capabilities:
        flows = list_flows()
        print("Flujos BOFA disponibles:")
        for f in flows[:10]:
            print(f"  - {f.get('id')}: {f.get('description', '')[:50]}...")
        print()

    if args.suggest:
        print("Sugerencia para 'recon web bug bounty hack ourselves':")
        print("  Flujos: bug_bounty_full_chain, bug_bounty_web_full, full_recon")
        print("  Scripts: web_discover, http_headers, path_scanner, param_finder, http_param_fuzzer")
        print()

    print("[Self-Hack] Ejecutando flujo (esto puede tardar 1-2 min)...")
    result = run_flow(flow_id=args.flow, target=target)

    if result.get("error"):
        print(f"Error: {result['error']}")
        return 1

    status = result.get("status", "unknown")
    report_path = result.get("report_path", "")
    steps = result.get("steps", [])

    print()
    print("=" * 60)
    print(f"RESULTADO: {status.upper()}")
    print("=" * 60)
    print(f"Report: {report_path}")
    print()

    ok = sum(1 for s in steps if s.get("status") == "success")
    err = sum(1 for s in steps if s.get("status") in ("error", "failed"))
    print(f"Pasos OK: {ok} | Con error: {err} | Total: {len(steps)}")
    print()

    for s in steps:
        idx = s.get("index", "?")
        mod = s.get("module", "")
        scr = s.get("script", "")
        st = s.get("status", "")
        sym = "✓" if st == "success" else "✗"
        print(f"  {sym} {idx}. {mod}/{scr} -> {st}")

    # Buscar informe ejecutivo
    target_safe = target.replace("://", "_").replace("/", "_").replace(":", "_")[:80]
    exec_path = _ROOT / "reports" / f"executive_{target_safe}.md"
    if exec_path.exists():
        print()
        print(f"Informe ejecutivo: {exec_path}")
        with open(exec_path, "r", encoding="utf-8") as f:
            content = f.read()
        print("-" * 40)
        print(content[:800])
        if len(content) > 800:
            print("...")

    print()
    print("[Self-Hack] Listo. Revisa los reports/ para el informe completo.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
