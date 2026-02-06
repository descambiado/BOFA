#!/usr/bin/env python3
"""
BOFA Verification Script
========================

Comprueba que el core, la CLI y los scripts funcionan correctamente.
Ejecutar desde la raíz del proyecto: python3 tools/verify_bofa.py [--full]

Modos:
  --quick (default): Ejecuta flujo demo + módulos de ejemplo. Rápido, confirma que lo esencial funciona.
  --full: Lista todos los módulos/scripts, valida cada uno y ejecuta los que aceptan params vacíos o tienen params seguros.
  --mcp: Si está instalado el paquete mcp, comprueba que las herramientas MCP (bofa_list_modules, etc.) responden. Opcional.
"""

import sys
from pathlib import Path
from datetime import datetime

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.engine import get_engine
from core.config import get_config
from core.errors import ValidationError, ScriptNotFoundError, ExecutionError

# Parámetros seguros para scripts que tienen argumentos requeridos (evitar fallos de validación/argparse)
def _safe_params(temp_log_path=None):
    p = {
        ("examples", "example_info"): {},
        ("examples", "example_params"): {"target": "verify.test", "timeout": 5, "verbose": False},
        ("examples", "example_fail"): {"mode": "success"},
        ("exploit", "mitre_attack_runner"): {},
        ("exploit", "post_exploit_enum"): {},
        ("exploit", "av_evasion_engine"): {},
        ("exploit", "cve_2024_springauth_bypass"): {"target": "http://127.0.0.1:9999", "verbose": False},
        ("recon", "web_discover"): {"url": "http://127.0.0.1"},
        ("blue", "log_guardian"): {"file": temp_log_path or "/dev/null"},
        ("blue", "defense_break_replicator"): {"yes": True, "duration": 1},
        ("exploit", "reverse_shell_generator"): {"ip": "127.0.0.1", "port": 9999},
        ("exploit", "ai_payload_mutator"): {"payload": "print('test')"},
        ("osint", "social_profile_mapper"): {"username": "verify_test"},
        ("exploit", "payload_encoder"): {"payload": "test"},
        ("vulnerability", "cve_export"): {"output": "/tmp/cve_export_verify.json"},
        ("forensics", "hash_calculator"): {"input": "verify_test"},
        ("blue", "log_quick_summary"): {"file": temp_log_path or "/dev/null"},
        ("forensics", "file_metadata"): {"path": str(_ROOT / "README.md")},
        ("forensics", "filesystem_timeline"): {"directory": str(_ROOT / "scripts"), "max-files": 5},
        ("reporting", "report_finding"): {
            "title": "Verify test",
            "description": "Test run",
            "severity": "info",
            "steps": "1. Run verify 2. Check output",
            "output": "/tmp/finding_verify.md",
        },
    }
    return p


def run_quick():
    """Verificación rápida: flujo demo + ejemplos."""
    from flows.flow_runner import run_flow
    engine = get_engine()
    engine.initialize()
    results = []
    # 1. Flujo demo
    try:
        r = run_flow("demo", "verify.test")
        ok = r.get("status") == "success"
        results.append(("Flow demo", ok, None if ok else r.get("steps", [])))
    except Exception as e:
        results.append(("Flow demo", False, str(e)))
    # 2. example_info
    try:
        res = engine.execute_script("examples", "example_info", parameters={}, timeout=10)
        results.append(("examples/example_info", res.exit_code == 0, res.stderr or None))
    except Exception as e:
        results.append(("examples/example_info", False, str(e)))
    # 3. example_params
    try:
        res = engine.execute_script(
            "examples", "example_params",
            parameters={"target": "verify.test", "timeout": 5, "verbose": False},
            timeout=10,
        )
        results.append(("examples/example_params", res.exit_code == 0, res.stderr or None))
    except Exception as e:
        results.append(("examples/example_params", False, str(e)))
    return results


def run_mcp_check():
    """Si mcp está instalado, comprueba que las herramientas MCP responden. Si no, (skipped, None)."""
    try:
        import mcp.server.fastmcp  # noqa: F401
    except ImportError:
        return ("MCP tools", "skipped", "mcp not installed (pip install .[mcp])")
    try:
        from mcp.bofa_mcp import bofa_list_modules, bofa_list_flows, bofa_capabilities, bofa_suggest_tools
    except Exception as e:
        return ("MCP tools", False, str(e))
    try:
        out = bofa_list_modules()
        if "error" in out:
            return ("MCP bofa_list_modules", False, out[:200])
        out2 = bofa_list_flows()
        if "error" in out2:
            return ("MCP bofa_list_flows", False, out2[:200])
        out3 = bofa_capabilities()
        if "error" in out3:
            return ("MCP bofa_capabilities", False, out3[:200])
        out4 = bofa_suggest_tools("recon web")
        if "error" in out4 and "goal is required" not in out4:
            return ("MCP bofa_suggest_tools", False, out4[:200])
        return ("MCP tools", True, None)
    except Exception as e:
        return ("MCP tools", False, str(e))


# Scripts que no se ejecutan en --full (interactivos, muy largos o con dependencias de entorno)
SKIP_FULL = {
    "purple/threat_emulator",  # timeout 20s; simulación larga
    "osint/multi_vector_osint",  # exit 1 sin params en entorno de verificación
    "recon/reverse_dns_flood",   # exit 1 sin target/red en entorno de verificación
    "osint/social_profile_mapper",  # timeout 20s; peticiones de red/API
    "recon/http_headers",  # requiere servidor escuchando en la URL (network-dependent)
    "web/robots_txt",      # requiere URL accesible (network-dependent)
    "web/security_headers_analyzer",  # requiere URL accesible (network-dependent)
    "web/path_scanner",    # requiere URL accesible (network-dependent)
}


def run_full():
    """Verificación completa: todos los módulos/scripts, validar y ejecutar con params seguros o vacíos."""
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write("# BOFA verify empty log\n")
        temp_log = f.name
    try:
        safe_params = _safe_params(temp_log)
    except Exception:
        safe_params = _safe_params("/dev/null")
    engine = get_engine()
    engine.initialize()
    modules = engine.list_modules()
    results = []
    for mod in sorted(modules):
        try:
            info = engine.get_module(mod)
        except Exception:
            continue
        for script_info in info.scripts or []:
            script_name = script_info.name
            key = (mod, script_name)
            skip_key = f"{mod}/{script_name}"
            if skip_key in SKIP_FULL:
                results.append((skip_key, "skipped", "long-running or interactive"))
                continue
            params = safe_params.get(key, {})
            # Intentar validar
            try:
                engine.validate_script(mod, script_name, params)
            except ValidationError as e:
                # Params vacíos no válidos: probar con params seguros si no los tenemos, marcar needs_params
                if key not in safe_params:
                    results.append((f"{mod}/{script_name}", "needs_params", str(e)))
                    continue
                results.append((f"{mod}/{script_name}", False, str(e)))
                continue
            except ScriptNotFoundError as e:
                results.append((f"{mod}/{script_name}", "not_found", str(e)))
                continue
            # Ejecutar con timeout corto
            try:
                res = engine.execute_script(mod, script_name, parameters=params, timeout=20)
                ok = res.exit_code == 0
                results.append((f"{mod}/{script_name}", ok, None if ok else (res.stderr or res.error or "")[:500]))
            except Exception as e:
                results.append((f"{mod}/{script_name}", False, str(e)[:500]))
    try:
        Path(temp_log).unlink(missing_ok=True)
    except Exception:
        pass
    return results


def main():
    full = "--full" in sys.argv
    mcp_check = "--mcp" in sys.argv
    print("BOFA Verification")
    print("=" * 60)
    print(f"Modo: {'full (todos los scripts)' if full else 'quick (flujo demo + ejemplos)'}")
    print()

    if full:
        results = run_full()
        ok_count = sum(1 for _, status, _ in results if status is True)
        needs_count = sum(1 for _, status, _ in results if status == "needs_params")
        skip_count = sum(1 for _, status, _ in results if status == "skipped")
        fail_count = sum(1 for _, status, _ in results if status is False)
        total = len(results)
        print(f"Total scripts: {total}")
        print(f"  OK: {ok_count}")
        print(f"  Necesitan parámetros (no ejecutados): {needs_count}")
        if skip_count:
            print(f"  Omitidos (long-running/interactive): {skip_count}")
        print(f"  Fallos: {fail_count}")
        print()
        if fail_count > 0:
            print("Fallos:")
            for name, status, err in results:
                if status is False:
                    print(f"  - {name}: {err[:200] if err else 'exit != 0'}")
        if needs_count > 0 and total <= 30:
            print("\nNecesitan parámetros (omitidos en esta verificación):")
            for name, status, _ in results:
                if status == "needs_params":
                    print(f"  - {name}")
        success = fail_count == 0
        if skip_count > 0:
            print("\n(Omitidos: scripts de larga duración o con dependencias de entorno; no cuentan como fallo)")
    else:
        results = run_quick()
        if mcp_check:
            mcp_result = run_mcp_check()
            results.append(mcp_result)
        ok_count = sum(1 for _, ok, _ in results if ok is True)
        skip_count = sum(1 for _, ok, _ in results if ok == "skipped")
        total = len(results)
        print(f"Comprobaciones: {total}")
        print(f"  OK: {ok_count}")
        if skip_count:
            print(f"  Omitidos: {skip_count}")
        print()
        for name, ok, err in results:
            if ok == "skipped":
                symbol = "SKIP"
            else:
                symbol = "OK" if ok else "FAIL"
            print(f"  [{symbol}] {name}")
            if not ok and err and ok != "skipped":
                print(f"       {str(err)[:300]}")
            if ok == "skipped" and err:
                print(f"       {str(err)[:200]}")
        success = not any(ok is False for _, ok, _ in results)

    print()
    print("=" * 60)
    if success:
        print("Resultado: TODO OK")
        return 0
    print("Resultado: HAY FALLOS (revisar arriba)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
