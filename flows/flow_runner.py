"""
BOFA Flow Runner - Ejecutor de flujos de scripts
=================================================

Ejecuta secuencias predefinidas de scripts con un target común
y genera un informe unificado (Markdown/JSON).
Soporta placeholders {step_N.field} para encadenamiento contextual.
Usa exclusivamente el core (get_engine); no modifica el core.
"""

import json
import re
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


def _try_parse_json(text: str) -> Optional[Dict[str, Any]]:
    """Intenta parsear JSON desde un texto."""
    if not text or not isinstance(text, str):
        return None
    text = text.strip()
    start = text.find("{")
    if start < 0:
        return None
    depth = 0
    end = -1
    for i, c in enumerate(text[start:], start):
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
    if end < 0:
        return None
    try:
        return json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None


def _extract_from_step_json(step_result: Dict[str, Any], path: str) -> Optional[str]:
    """
    Extrae valor de un paso desde su stdout JSON.
    path: "params" -> para param_finder: {"params":[{"name":"q"},...]} -> "q,id,search"
    """
    preview = step_result.get("stdout_preview") or ""
    obj = _try_parse_json(preview)
    if not obj:
        return None
    if path == "params":
        params_list = obj.get("params") or []
        names = []
        for p in params_list:
            if isinstance(p, dict) and "name" in p:
                names.append(str(p["name"]))
            elif isinstance(p, str):
                names.append(p)
        return ",".join(names) if names else None
    return None


def _substitute_step_placeholders(
    parameters: Dict[str, Any],
    steps_results: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Sustituye {step_N.field} por valores extraídos del JSON de pasos anteriores."""
    if not parameters:
        return {}
    out = {}
    for k, v in parameters.items():
        if not isinstance(v, str):
            out[k] = v
            continue
        m = re.search(r"\{step_(\d+)\.(\w+)\}", v)
        if not m:
            out[k] = v
            continue
        step_num = int(m.group(1))
        field = m.group(2)
        replacement = None
        for sr in steps_results:
            if sr.get("index") == step_num:
                replacement = _extract_from_step_json(sr, field)
                break
        if replacement is not None:
            out[k] = re.sub(r"\{step_\d+\.\w+\}", replacement, v)
        elif field == "params" and k == "params":
            out[k] = "q"
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
        params = _substitute_step_placeholders(params, steps_results)

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

    # Guardar report_json en disco para post-proceso
    json_filename = f"flow_{flow_id}_{timestamp}.json"
    json_path = out_dir / json_filename
    try:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report_json, f, indent=2, ensure_ascii=False)
    except OSError:
        json_path = None

    # Post-proceso opcional (ej. flow_report_aggregator)
    post_process = flow.get("post_process") or {}
    post_script = post_process.get("script")
    post_params = post_process.get("params") or {}
    if post_script and json_path:
        try:
            mod_script = post_script.split("/")
            if len(mod_script) == 2:
                pp_mod, pp_scr = mod_script[0], mod_script[1]
                pp_params = dict(post_params)
                target_safe = (target or "").replace("://", "_").replace("/", "_").replace(":", "_")[:80]
                for k, v in list(pp_params.items()):
                    if not isinstance(v, str):
                        continue
                    s = v.replace("{flow_report_json}", str(json_path))
                    s = s.replace("{target}", target or "")
                    s = s.replace("{target_safe}", target_safe)
                    # Rutas relativas (output) se resuelven desde la raíz del proyecto
                    if k == "output" and s and not Path(s).is_absolute():
                        s = str(_ROOT / s)
                    pp_params[k] = s
                engine.execute_script(
                    module_name=pp_mod,
                    script_name=pp_scr,
                    parameters=pp_params,
                    timeout=config.execution_timeout or 60,
                )
        except Exception:
            pass

    return {
        "flow_id": flow_id,
        "target": target,
        "status": status,
        "steps": steps_results,
        "report_path": str(report_path),
        "report_json_path": str(json_path) if json_path else None,
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
