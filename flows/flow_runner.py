"""
BOFA Flow Runner - Ejecutor de flujos de scripts
=================================================

Ejecuta secuencias predefinidas de scripts con un target común
y genera un informe unificado (Markdown/JSON).
Usa exclusivamente el core (get_engine); no modifica el core.
"""

import sys
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

# Raíz del proyecto para importar core
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import yaml
from core.engine import get_engine
from core.config import get_config


def _flows_dir() -> Path:
    """Directorio donde están los YAML de flujos."""
    config = get_config()
    return config.config_path / "flows"


def list_flows() -> List[Dict[str, Any]]:
    """
    Lista los flujos disponibles (leyendo config/flows/*.yaml).

    Returns:
        Lista de dicts con name, description, steps_count.
    """
    flows_path = _flows_dir()
    if not flows_path.exists():
        return []

    result = []
    for f in flows_path.glob("*.yaml"):
        try:
            with open(f, "r", encoding="utf-8") as fp:
                data = yaml.safe_load(fp) or {}
            result.append({
                "id": f.stem,
                "name": data.get("name", f.stem),
                "description": data.get("description", ""),
                "steps_count": len(data.get("steps", [])),
            })
        except Exception:
            continue
    return result


def _load_flow(flow_id: str) -> Dict[str, Any]:
    """Carga un flujo por id (nombre del archivo sin extensión)."""
    flows_path = _flows_dir()
    path = flows_path / f"{flow_id}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"Flujo no encontrado: {flow_id}")
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _substitute_target(parameters: Dict[str, Any], target: str) -> Dict[str, Any]:
    """Sustituye el placeholder {target} en los valores de parameters."""
    if not parameters or not target:
        return dict(parameters) if parameters else {}
    out = {}
    for k, v in parameters.items():
        if isinstance(v, str) and "{target}" in v:
            out[k] = v.replace("{target}", target)
        else:
            out[k] = v
    return out


def run_flow(
    flow_id: str,
    target: str,
    timeout_per_script: Optional[int] = None,
    output_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Ejecuta un flujo con el target dado y genera informe.

    Args:
        flow_id: Id del flujo (nombre del YAML sin .yaml).
        target: Valor a inyectar en los parámetros que usen {target}.
        timeout_per_script: Timeout por script (opcional).
        output_dir: Directorio donde guardar el informe (default: reports/).

    Returns:
        Dict con: flow_id, target, status (success/partial/error), steps (lista de resultados),
                  report_path (ruta del informe Markdown), report_json (datos para JSON).
    """
    flow = _load_flow(flow_id)
    steps_spec = flow.get("steps", [])
    if not steps_spec:
        return {
            "flow_id": flow_id,
            "target": target,
            "status": "error",
            "error": "Flujo sin pasos",
            "steps": [],
            "report_path": None,
            "report_json": None,
        }

    engine = get_engine()
    engine.initialize()

    config = get_config()
    out_dir = output_dir or _ROOT / "reports"
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    steps_results = []
    any_error = False
    for i, step in enumerate(steps_spec):
        module = step.get("module")
        script = step.get("script")
        params = step.get("parameters") or {}
        params = _substitute_target(params, target)

        step_result = {
            "index": i + 1,
            "module": module,
            "script": script,
            "status": "pending",
            "exit_code": None,
            "duration": None,
            "stdout_preview": "",
            "stderr_preview": "",
            "error": None,
        }

        try:
            result = engine.execute_script(
                module_name=module,
                script_name=script,
                parameters=params,
                timeout=timeout_per_script or config.execution_timeout,
            )
            step_result["status"] = result.status
            step_result["exit_code"] = result.exit_code
            step_result["duration"] = result.duration
            step_result["stdout_preview"] = (result.stdout or "")[:2000]
            step_result["stderr_preview"] = (result.stderr or "")[:1000]
            if result.error:
                step_result["error"] = result.error
            if result.exit_code != 0:
                any_error = True
        except Exception as e:
            step_result["status"] = "error"
            step_result["error"] = str(e)
            any_error = True

        steps_results.append(step_result)

    status = "error" if any_error else "success"
    if any_error and any(s["status"] == "success" for s in steps_results):
        status = "partial"

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    report_filename = f"flow_{flow_id}_{timestamp}.md"
    report_path = out_dir / report_filename

    report_json = {
        "flow_id": flow_id,
        "flow_name": flow.get("name", flow_id),
        "target": target,
        "status": status,
        "timestamp": datetime.utcnow().isoformat(),
        "steps": steps_results,
    }

    # Generar Markdown
    md_lines = [
        f"# BOFA Flow Report: {flow.get('name', flow_id)}",
        "",
        f"- **Target:** {target}",
        f"- **Status:** {status}",
        f"- **Timestamp:** {report_json['timestamp']}",
        "",
        "## Steps",
        "",
    ]
    for s in steps_results:
        md_lines.append(f"### {s['index']}. {s['module']}/{s['script']}")
        md_lines.append("")
        md_lines.append(f"- **Status:** {s['status']} | **Exit code:** {s['exit_code']} | **Duration:** {s['duration']}s")
        md_lines.append("")
        if s.get("stdout_preview"):
            md_lines.append("**Stdout (preview):**")
            md_lines.append("```")
            md_lines.append(s["stdout_preview"].strip()[:1500])
            md_lines.append("```")
            md_lines.append("")
        if s.get("stderr_preview"):
            md_lines.append("**Stderr (preview):**")
            md_lines.append("```")
            md_lines.append(s["stderr_preview"].strip()[:500])
            md_lines.append("```")
            md_lines.append("")
        if s.get("error"):
            md_lines.append(f"**Error:** {s['error']}")
            md_lines.append("")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines))

    return {
        "flow_id": flow_id,
        "target": target,
        "status": status,
        "steps": steps_results,
        "report_path": str(report_path),
        "report_json": report_json,
    }


class FlowRunner:
    """
    Clase de conveniencia para listar y ejecutar flujos.
    """

    @staticmethod
    def list_flows() -> List[Dict[str, Any]]:
        return list_flows()

    @staticmethod
    def run(flow_id: str, target: str, **kwargs) -> Dict[str, Any]:
        return run_flow(flow_id, target, **kwargs)
