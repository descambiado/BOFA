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
        {"id": "full_recon", "name": "Full Recon", "when": "recon completo: web_discover + headers + robots.txt + CVE", "combine_with": "vuln_triage(product) para CVE por producto"},
        {"id": "web_security_review", "name": "Web Security Review", "when": "revisar cabeceras y robots.txt de una URL", "combine_with": "bug_bounty_web_full o vuln_triage"},
        {"id": "bug_bounty_web_light", "name": "Bug Bounty Web Light", "when": "recon rapido de una URL con headers y robots", "combine_with": "bug_bounty_web_full"},
        {"id": "bug_bounty_web_full", "name": "Bug Bounty Web Full", "when": "bug bounty web mas profundo (headers + robots + path scan)", "combine_with": "bug_bounty_web_params o bug_bounty_web_diff, vuln_triage(product) y report_finding"},
        {"id": "bug_bounty_web_params", "name": "Bug Bounty Web Params", "when": "descubrir parametros potenciales en una URL (formularios y enlaces)", "combine_with": "bug_bounty_web_full o report_finding"},
        {"id": "bug_bounty_web_diff", "name": "Bug Bounty Web Diff", "when": "comparar tamanos de respuesta de rutas comunes para detectar rutas raras", "combine_with": "bug_bounty_web_full y report_finding"},
        {"id": "pentest_basic", "name": "Pentest basico", "when": "pentest basico sobre URL", "combine_with": "report_finding para documentar hallazgos"},
        {"id": "vulnerability_scan", "name": "Vulnerability scan", "when": "listar CVE de la base local", "combine_with": "vuln_triage(product) para filtrar por producto"},
        {"id": "vuln_triage", "name": "Vuln triage", "when": "CVE por producto (target=producto ej. web_framework)", "combine_with": "report_finding para informe de hallazgo"},
        {"id": "blue", "name": "Blue team", "when": "simulacion blue team general", "combine_with": "blue_daily para informe diario"},
        {"id": "blue_daily", "name": "Blue daily", "when": "revision diaria de logs de un host", "combine_with": "blue_risk_assessment o report_finding o flujos forenses"},
        {"id": "blue_risk_assessment", "name": "Blue risk assessment", "when": "calcular score de riesgo a partir de logs (auth/syslog)", "combine_with": "forensics_quick o report_finding adicionales"},
        {"id": "forensics_quick", "name": "Forensics quick", "when": "vista rapida de metadatos y linea de tiempo de ficheros", "combine_with": "forensics_diff o report_finding o blue_daily"},
        {"id": "forensics_diff", "name": "Forensics diff", "when": "comparar dos timelines (antes/despues) para ver ficheros añadidos/eliminados/modificados", "combine_with": "forensics_quick o blue_daily"},
    ],
    "scripts_with_json": [
        "recon/http_headers",
        "web/robots_txt",
        "web/security_headers_analyzer",
        "web/path_scanner",
        "web/param_finder",
        "web/response_classifier",
        "blue/log_guardian",
        "blue/log_quick_summary",
        "blue/log_anomaly_score",
        "vulnerability/cve_lookup",
        "vulnerability/cve_export",
        "reporting/report_finding",
        "forensics/hash_calculator",
        "forensics/file_metadata",
        "forensics/filesystem_timeline",
        "forensics/timeline_diff",
    ],
    "chain_examples": [
        "full_recon(URL) -> parse stdout of cve_lookup -> vuln_triage(product from context)",
        "web_security_review(URL) -> revisar headers y robots -> bug_bounty_web_full(URL) para buscar mas rutas",
        "bug_bounty_web_full(URL) -> usar path_scanner findings + security headers -> report_finding resumen manual o automatizado",
        "bug_bounty_web_params(URL) -> usar param_finder.params para construir lista de parametros a probar",
        "bug_bounty_web_diff(URL) -> usar response_classifier.interesting para priorizar rutas con respuestas diferentes",
        "blue_daily(log_path) -> usar JSON de log_guardian + informe generado por report_finding",
        "blue_risk_assessment(log_path) -> usar log_anomaly_score.risk_score y top_ips/top_users para priorizar acciones blue",
        "forensics_quick(dir) -> generar timeline y luego timeline_diff(before, after) -> report_finding(forense detallado)",
        "file_metadata(path) + filesystem_timeline(dir) -> report_finding(forense rapido)",
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

    if "recon" in goal_lower or "reconocimiento" in goal_lower or "web" in goal_lower or "url" in goal_lower or "http" in goal_lower or "bug bounty" in goal_lower:
        suggested_flows.extend(["web_recon", "full_recon", "web_security_review", "bug_bounty_web_light", "bug_bounty_web_full", "bug_bounty_web_params", "bug_bounty_web_diff"])
        suggested_scripts.extend([
            "recon/web_discover",
            "recon/http_headers",
            "web/robots_txt",
            "web/security_headers_analyzer",
            "web/path_scanner",
            "web/param_finder",
            "web/response_classifier",
        ])
        reasons.append("recon/web: usar web_recon o full_recon para mapa basico; web_security_review y bug_bounty_web_* para revision mas profunda (headers, robots, paths, parametros, diferencias de respuesta)")
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
    if "blue" in goal_lower or "defensa" in goal_lower or "log" in goal_lower or "siem" in goal_lower or "deteccion" in goal_lower:
        suggested_flows.extend(["blue", "blue_daily", "blue_risk_assessment"])
        suggested_scripts.extend(["blue/log_guardian", "blue/log_quick_summary", "blue/log_anomaly_score"])
        reasons.append("blue: usar blue para simulacion y blue_daily/log_guardian/log_quick_summary/log_anomaly_score para revision de logs y score de riesgo")

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
