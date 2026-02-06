"""
BOFA MCP Server - Model Context Protocol
=========================================

Servidor MCP que expone el core de BOFA como herramientas para clientes
(Cursor, Claude Desktop, etc.). No añade IA/LLM; solo expone listar módulos/scripts,
ejecutar scripts y flujos.

Uso:
  pip install mcp   # o: pip install .[mcp]
  python3 mcp/bofa_mcp.py

Configuración en Cursor: .cursor/mcp.json (ver docs/MCP_CURSOR_INTEGRATION.md).
"""

import sys
import json
from pathlib import Path
from typing import Optional

# Raíz del proyecto para imports
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    print(
        "Error: El paquete 'mcp' no está instalado. Instálalo con:\n"
        "  pip install mcp\n"
        "  o desde el proyecto: pip install .[mcp]",
        file=sys.stderr,
    )
    sys.exit(1)

from core.engine import get_engine
from core.errors import (
    ModuleNotFoundError,
    ScriptNotFoundError,
    ExecutionError,
    ValidationError,
)
from flows.flow_runner import list_flows as _list_flows
from flows.flow_runner import run_flow as _run_flow

mcp = FastMCP(
    "BOFA",
    description="BOFA Cybersecurity Framework: 67+ security tools in 20 modules (recon, web, exploit, vulnerability, blue, etc.). Use for autonomous security testing: list modules/scripts, get script parameters, execute scripts, list/run flows. Call bofa_capabilities() to see what you can combine; bofa_suggest_tools(goal) to get suggested flows/scripts for a goal.",
)


def _engine():
    e = get_engine()
    e.initialize()
    return e


@mcp.tool()
def bofa_list_modules() -> str:
    """List all BOFA modules (security tool categories). Use first to discover domains: recon, exploit, vulnerability, blue, purple, osint, forensics, etc. Returns JSON with 'modules' array."""
    try:
        modules = _engine().list_modules()
        return json.dumps({"modules": modules}, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def bofa_list_scripts(module_name: Optional[str] = None) -> str:
    """List BOFA scripts. Pass module_name (e.g. recon, vulnerability, exploit) to list only that module, or omit to list all. Returns JSON: module -> list of script names. Use before execute_script to choose a script."""
    try:
        data = _engine().list_scripts(module_name)
        return json.dumps(data, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def bofa_script_info(module_name: str, script_name: str) -> str:
    """Get description and parameters for a BOFA script. Call before execute_script to build parameters_json. Returns name, module, description, parameters (with types and required/default)."""
    try:
        info = _engine().get_script(module_name, script_name)
        return json.dumps(
            {
                "name": info.name,
                "module": info.module,
                "description": info.description,
                "parameters": info.parameters,
                "author": info.author,
                "version": info.version,
            },
            indent=2,
        )
    except ScriptNotFoundError as e:
        return json.dumps({"error": str(e)})
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def bofa_execute_script(
    module_name: str,
    script_name: str,
    parameters_json: Optional[str] = None,
    timeout_seconds: Optional[int] = None,
) -> str:
    """Execute a BOFA script. Required: module_name (e.g. recon, web, vulnerability), script_name. Optional: parameters_json as JSON string (e.g. {\"url\": \"https://example.com\"} for recon/web_discover or web/robots_txt, {\"product\": \"web_framework\"} for vulnerability/cve_lookup). Many scripts accept \"json\": true for parseable stdout; use stdout to chain into next script or extract findings. Returns status, exit_code, stdout, stderr, duration."""
    try:
        params = {}
        if parameters_json:
            try:
                params = json.loads(parameters_json)
            except json.JSONDecodeError as e:
                return json.dumps({"error": f"Invalid parameters JSON: {e}"})
        result = _engine().execute_script(
            module_name=module_name,
            script_name=script_name,
            parameters=params,
            timeout=timeout_seconds,
        )
        return json.dumps(
            {
                "execution_id": result.execution_id,
                "status": result.status,
                "exit_code": result.exit_code,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "duration": result.duration,
                "error": result.error,
            },
            indent=2,
        )
    except (ScriptNotFoundError, ValidationError) as e:
        return json.dumps({"error": str(e)})
    except ExecutionError as e:
        return json.dumps({"error": str(e), "details": getattr(e, "details", {})})
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def bofa_list_flows() -> str:
    """List available BOFA flows (predefined sequences). Returns id, name, description, steps_count. Use bofa_run_flow(flow_id, target) to run. Flows: demo, recon, web_recon, full_recon (web+headers+robots+CVE), pentest_basic, vulnerability_scan, vuln_triage (CVE by product), blue. Combine: run full_recon(url) then vuln_triage(product) with same or different target."""
    try:
        flows = _list_flows()
        return json.dumps(
            [
                {
                    "id": f["id"],
                    "name": f.get("name", f["id"]),
                    "description": f.get("description", ""),
                    "steps_count": f.get("steps_count", 0),
                }
                for f in flows
            ],
            indent=2,
        )
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def bofa_run_flow(flow_id: str, target: str) -> str:
    """Run a BOFA flow. flow_id: demo, recon, web_recon, full_recon, pentest_basic, vulnerability_scan, vuln_triage, blue. target: value injected into steps (URL for web flows, product name for vuln_triage, domain for recon). Returns status, report_path, steps (each with stdout_preview). Parse stdout_preview when scripts output JSON to feed next tool or report to user."""
    try:
        result = _run_flow(flow_id=flow_id, target=target)
        return json.dumps(
            {
                "flow_id": result["flow_id"],
                "target": result["target"],
                "status": result["status"],
                "report_path": result.get("report_path"),
                "steps": result.get("steps", []),
            },
            indent=2,
        )
    except FileNotFoundError as e:
        return json.dumps({"error": str(e)})
    except Exception as e:
        return json.dumps({"error": str(e)})


# Datos para orquestacion: flujos con sugerencias de combinacion y scripts con salida encadenable
_CAPABILITIES = {
    "flows": [
        {"id": "demo", "name": "Demo", "when": "probar que BOFA funciona", "combine_with": None},
        {"id": "recon", "name": "Recon", "when": "reconocimiento basico", "combine_with": "web_recon o full_recon con misma URL"},
        {"id": "web_recon", "name": "Web Recon", "when": "solo descubrimiento web de una URL", "combine_with": "full_recon para mas pasos (headers, robots, CVE)"},
        {"id": "full_recon", "name": "Full Recon", "when": "recon completo: web + headers + robots.txt + CVE", "combine_with": "vuln_triage(product) para CVE por producto"},
        {"id": "pentest_basic", "name": "Pentest basico", "when": "pentest basico sobre URL", "combine_with": "report_finding para documentar hallazgos"},
        {"id": "vulnerability_scan", "name": "Vulnerability scan", "when": "listar CVE de la base local", "combine_with": "vuln_triage(product) para filtrar por producto"},
        {"id": "vuln_triage", "name": "Vuln triage", "when": "CVE por producto (target=producto ej. web_framework)", "combine_with": "report_finding para informe de hallazgo"},
        {"id": "blue", "name": "Blue team", "when": "simulacion blue team", "combine_with": None},
    ],
    "scripts_with_json": [
        "recon/http_headers",
        "web/robots_txt",
        "vulnerability/cve_lookup",
        "vulnerability/cve_export",
        "reporting/report_finding",
        "forensics/hash_calculator",
    ],
    "chain_examples": [
        "full_recon(URL) -> parse stdout of cve_lookup -> vuln_triage(product from context)",
        "web_recon(URL) -> http_headers(URL, json=true) -> robots_txt(URL, json=true)",
        "cve_lookup(product) -> report_finding(title, description from CVE)",
    ],
}


@mcp.tool()
def bofa_capabilities() -> str:
    """Returns what BOFA can do and how to combine tools. Use first to understand: flows (with when/combine_with), scripts_with_json (parse stdout to chain), chain_examples. Then list_flows/list_scripts/execute_script/run_flow to perform actions. Enables the IA to discover and chain tools without guessing."""
    try:
        return json.dumps(_CAPABILITIES, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def bofa_suggest_tools(goal: str) -> str:
    """Suggest flows and scripts for a goal (free text). Pass goal like 'recon web example.com', 'vulnerabilidades web_framework', 'pentest URL'. Returns suggested_flows and suggested_scripts with short reason. Use to decide what to run before execute_script or run_flow."""
    goal_lower = (goal or "").strip().lower()
    if not goal_lower:
        return json.dumps({"error": "goal is required", "example": "recon web https://example.com"})

    suggested_flows = []
    suggested_scripts = []
    reasons = []

    if "recon" in goal_lower or "reconocimiento" in goal_lower or "web" in goal_lower or "url" in goal_lower or "http" in goal_lower:
        suggested_flows.extend(["web_recon", "full_recon"])
        suggested_scripts.extend(["recon/web_discover", "recon/http_headers", "web/robots_txt"])
        reasons.append("recon/web: run full_recon(URL) or web_recon(URL); then http_headers, robots_txt with same URL")
    if "vuln" in goal_lower or "cve" in goal_lower or "vulnerabilidad" in goal_lower or "producto" in goal_lower:
        suggested_flows.extend(["vulnerability_scan", "vuln_triage"])
        suggested_scripts.extend(["vulnerability/cve_lookup", "vulnerability/cve_export"])
        reasons.append("vuln: run vuln_triage(product) or cve_lookup with product/limit")
    if "pentest" in goal_lower or "test" in goal_lower:
        suggested_flows.append("pentest_basic")
        suggested_scripts.extend(["recon/web_discover", "exploit/payload_encoder"])
        reasons.append("pentest: run pentest_basic(URL) or combine recon + exploit scripts")
    if "reporte" in goal_lower or "report" in goal_lower or "hallazgo" in goal_lower:
        suggested_scripts.append("reporting/report_finding")
        reasons.append("report: use report_finding with title, description, severity, steps, output path")
    if "blue" in goal_lower or "defensa" in goal_lower:
        suggested_flows.append("blue")
        suggested_scripts.extend(["blue/log_guardian", "blue/siem_alert_simulator"])
        reasons.append("blue: run flow blue or log_guardian, siem_alert_simulator")

    suggested_flows = list(dict.fromkeys(suggested_flows))
    suggested_scripts = list(dict.fromkeys(suggested_scripts))
    return json.dumps(
        {
            "goal": goal,
            "suggested_flows": suggested_flows,
            "suggested_scripts": suggested_scripts,
            "reasons": reasons,
        },
        indent=2,
    )


def main() -> None:
    # stdio es el transporte por defecto para clientes como Cursor
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
