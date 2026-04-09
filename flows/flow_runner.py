"""
BOFA flow runner.
Executes YAML-defined flows and can optionally persist them via RunManager.
"""

from datetime import datetime
import json
import mimetypes
from pathlib import Path
import re
import sys
from typing import Any, Callable, Dict, List, Optional

import yaml

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.config import get_config
from core.engine import get_engine


def _flows_dir() -> Path:
    config = get_config()
    return config.config_path / "flows"


def list_flows() -> List[Dict[str, Any]]:
    flows_path = _flows_dir()
    if not flows_path.exists():
        return []
    result = []
    for flow_file in flows_path.glob("*.yaml"):
        try:
            data = yaml.safe_load(flow_file.read_text(encoding="utf-8")) or {}
            result.append(
                {
                    "id": flow_file.stem,
                    "name": data.get("name", flow_file.stem),
                    "description": data.get("description", ""),
                    "steps_count": len(data.get("steps", [])),
                }
            )
        except Exception:
            continue
    return result


def load_flow(flow_id: str) -> Dict[str, Any]:
    path = _flows_dir() / f"{flow_id}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"Flujo no encontrado: {flow_id}")
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _substitute_target(parameters: Dict[str, Any], target: str) -> Dict[str, Any]:
    if not parameters:
        return {}
    result = {}
    for key, value in parameters.items():
        result[key] = value.replace("{target}", target) if isinstance(value, str) else value
    return result


def _try_parse_json(text: str) -> Optional[Dict[str, Any]]:
    if not text or not isinstance(text, str):
        return None
    text = text.strip()
    start = text.find("{")
    if start < 0:
        return None
    depth = 0
    end = -1
    for index, char in enumerate(text[start:], start):
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                end = index
                break
    if end < 0:
        return None
    try:
        return json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None


def _extract_from_step_json(step_result: Dict[str, Any], path: str) -> Optional[str]:
    obj = _try_parse_json(step_result.get("stdout_preview", ""))
    if not obj:
        return None
    if path == "params":
        params_list = obj.get("params") or []
        names = []
        for item in params_list:
            if isinstance(item, dict) and "name" in item:
                names.append(str(item["name"]))
            elif isinstance(item, str):
                names.append(item)
        return ",".join(names) if names else None
    return None


def _flow_artifact_content_type(path_str: str, artifact_type: str) -> str:
    if artifact_type in {"flow_summary_json", "report_json"}:
        return "application/json"
    if artifact_type in {"flow_summary_markdown", "report_markdown"}:
        return "text/markdown"
    guessed, _ = mimetypes.guess_type(path_str)
    return guessed or "text/plain"


def _flow_artifact_metadata(
    path_str: str,
    artifact_type: str,
    run_status: str,
    partial: bool,
    step_id: Optional[str] = None,
) -> Dict[str, Any]:
    content_type = _flow_artifact_content_type(path_str, artifact_type)
    return {
        "step_id": step_id,
        "run_status": run_status,
        "step_status": None,
        "artifact_role": "post_process" if artifact_type == "post_process_output" else "summary",
        "previewable": content_type.startswith("text/") or content_type == "application/json",
        "preview_mode": "head",
        "content_type": content_type,
        "size_bytes": Path(path_str).stat().st_size if Path(path_str).exists() else None,
        "partial": partial,
    }
    

def _build_flow_summary(
    flow_id: str,
    flow: Dict[str, Any],
    target: str,
    status: str,
    steps_results: List[Dict[str, Any]],
    cancelled_at_step: Optional[int] = None,
    cause: Optional[str] = None,
    artifact_count: int = 0,
) -> Dict[str, Any]:
    return {
        "flow_id": flow_id,
        "flow_name": flow.get("name", flow_id),
        "target": target,
        "status": status,
        "timestamp": datetime.utcnow().isoformat(),
        "completed_steps": len([step for step in steps_results if step.get("status") == "success"]),
        "failed_steps": len([step for step in steps_results if step.get("status") in {"failed", "error"}]),
        "cancelled_steps": len([step for step in steps_results if step.get("status") == "cancelled"]),
        "cancelled_at_step": cancelled_at_step,
        "artifact_count": artifact_count,
        "cause": cause,
        "steps": steps_results,
    }


def _build_flow_markdown(summary: Dict[str, Any]) -> str:
    markdown = [
        f"# BOFA Flow Report: {summary['flow_name']}",
        "",
        f"- **Target:** {summary['target']}",
        f"- **Status:** {summary['status']}",
        f"- **Timestamp:** {summary['timestamp']}",
        f"- **Completed steps:** {summary['completed_steps']}",
        f"- **Failed steps:** {summary['failed_steps']}",
        f"- **Cancelled steps:** {summary['cancelled_steps']}",
        f"- **Artifact count:** {summary['artifact_count']}",
    ]
    if summary.get("cancelled_at_step") is not None:
        markdown.append(f"- **Cancelled at step:** {summary['cancelled_at_step']}")
    if summary.get("cause"):
        markdown.append(f"- **Cause:** {summary['cause']}")
    markdown.extend(["", "## Steps", ""])

    for step in summary.get("steps", []):
        markdown.append(f"### {step['index']}. {step['module']}/{step['script']}")
        markdown.append("")
        markdown.append(f"- **Status:** {step['status']} | **Exit code:** {step['exit_code']} | **Duration:** {step['duration']}s")
        markdown.append("")
        if step.get("stdout_preview"):
            markdown.extend(["**Stdout (preview):**", "```", step["stdout_preview"].strip()[:1500], "```", ""])
        if step.get("stderr_preview"):
            markdown.extend(["**Stderr (preview):**", "```", step["stderr_preview"].strip()[:500], "```", ""])
        if step.get("error"):
            markdown.extend([f"**Error:** {step['error']}", ""])

    return "\n".join(markdown)


def _finalize_flow_result(
    flow_id: str,
    flow: Dict[str, Any],
    target: str,
    report_dir: Path,
    engine,
    config,
    steps_results: List[Dict[str, Any]],
    status: str,
    run_manager=None,
    run_id: Optional[str] = None,
    cancelled_at_step: Optional[int] = None,
    cause: Optional[str] = None,
):
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    existing_artifact_count = 0
    if run_manager and run_id:
        detail = run_manager.get_run(run_id) or {}
        existing_artifact_count = len(detail.get("artifacts", []))

    summary = _build_flow_summary(
        flow_id,
        flow,
        target,
        status,
        steps_results,
        cancelled_at_step=cancelled_at_step,
        cause=cause,
        artifact_count=existing_artifact_count,
    )

    report_path = report_dir / f"flow_{flow_id}_{timestamp}.md"
    json_path = report_dir / f"flow_{flow_id}_{timestamp}.json"
    report_path.write_text(_build_flow_markdown(summary), encoding="utf-8")
    json_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    post_process = flow.get("post_process") or {}
    post_script = post_process.get("script")
    post_params = post_process.get("params") or {}
    post_process_output_path = None

    if post_script and status != "cancelled":
        try:
            module_name, script_name = post_script.split("/")
            resolved = dict(post_params)
            target_safe = (target or "").replace("://", "_").replace("/", "_").replace(":", "_")[:80]
            for key, value in list(resolved.items()):
                if not isinstance(value, str):
                    continue
                transformed = value.replace("{flow_report_json}", str(json_path))
                transformed = transformed.replace("{target}", target or "")
                transformed = transformed.replace("{target_safe}", target_safe)
                if key == "output" and transformed and not Path(transformed).is_absolute():
                    transformed = str(_ROOT / transformed)
                resolved[key] = transformed
            result = engine.execute_script(
                module_name=module_name,
                script_name=script_name,
                parameters=resolved,
                timeout=config.execution_timeout or 60,
            )
            if resolved.get("output") and result.exit_code == 0:
                post_process_output_path = str(resolved["output"])
        except Exception:
            pass
    elif post_script and status == "cancelled" and run_manager and run_id:
        run_manager.add_event(
            run_id,
            "run",
            run_id,
            "post_process_skipped",
            "cancelled",
            "Post-process skipped because the flow was cancelled",
            {"flow_id": flow_id, "reason": "flow_cancelled"},
        )

    summary["artifact_count"] = existing_artifact_count + 2 + (1 if post_process_output_path else 0)
    report_path.write_text(_build_flow_markdown(summary), encoding="utf-8")
    json_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    if run_manager and run_id:
        partial_evidence = status in {"partial", "cancelled", "failed", "error"}
        run_manager.add_artifact(
            run_id,
            "flow_summary_markdown",
            str(report_path),
            label="Flow markdown summary",
            metadata=_flow_artifact_metadata(str(report_path), "flow_summary_markdown", status, partial_evidence),
        )
        run_manager.add_artifact(
            run_id,
            "flow_summary_json",
            str(json_path),
            label="Flow json summary",
            metadata=_flow_artifact_metadata(str(json_path), "flow_summary_json", status, partial_evidence),
        )
        if post_process_output_path:
            run_manager.add_artifact(
                run_id,
                "post_process_output",
                post_process_output_path,
                label="Flow post-process output",
                metadata=_flow_artifact_metadata(post_process_output_path, "post_process_output", status, partial_evidence),
            )

    return {
        "flow_id": flow_id,
        "target": target,
        "status": status,
        "steps": steps_results,
        "report_path": str(report_path),
        "report_json_path": str(json_path),
        "report_json": summary,
        "completed_steps": summary["completed_steps"],
        "failed_steps": summary["failed_steps"],
        "cancelled_at_step": summary.get("cancelled_at_step"),
        "cause": summary.get("cause"),
        "artifact_count": summary["artifact_count"],
    }


def _substitute_step_placeholders(parameters: Dict[str, Any], steps_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not parameters:
        return {}
    output = {}
    for key, value in parameters.items():
        if not isinstance(value, str):
            output[key] = value
            continue
        match = re.search(r"\{step_(\d+)\.(\w+)\}", value)
        if not match:
            output[key] = value
            continue
        step_num = int(match.group(1))
        field = match.group(2)
        replacement = None
        for step_result in steps_results:
            if step_result.get("index") == step_num:
                replacement = _extract_from_step_json(step_result, field)
                break
        output[key] = re.sub(r"\{step_\d+\.\w+\}", replacement, value) if replacement is not None else value
    return output


def run_flow(
    flow_id: str,
    target: str,
    timeout_per_script: Optional[int] = None,
    output_dir: Optional[Path] = None,
    run_manager=None,
    run_id: Optional[str] = None,
    cancel_file: Optional[str] = None,
    cancel_check_interval: float = 0.5,
    cancellation_hooks: Optional[Dict[str, Callable[..., Any]]] = None,
):
    flow = load_flow(flow_id)
    steps_spec = flow.get("steps", [])
    if not steps_spec:
        return {
            "flow_id": flow_id,
            "target": target,
            "status": "error",
            "error": "Flujo sin pasos",
            "steps": [],
            "report_path": None,
            "report_json_path": None,
            "report_json": None,
        }

    engine = get_engine()
    engine.initialize()
    config = get_config()
    report_dir = Path(output_dir or (_ROOT / "reports"))
    report_dir.mkdir(parents=True, exist_ok=True)

    steps_results = []
    any_error = False
    for index, step in enumerate(steps_spec, start=1):
        should_cancel = cancellation_hooks.get("should_cancel") if cancellation_hooks else None
        if (should_cancel and should_cancel()) or (cancel_file and Path(cancel_file).exists()):
            return _finalize_flow_result(
                flow_id,
                flow,
                target,
                report_dir,
                engine,
                config,
                steps_results,
                "cancelled",
                run_manager=run_manager,
                run_id=run_id,
                cancelled_at_step=index,
                cause="Flow cancelled before next step started",
            )

        module = step.get("module")
        script = step.get("script")
        parameters = _substitute_target(step.get("parameters") or {}, target)
        parameters = _substitute_step_placeholders(parameters, steps_results)
        step_id = None
        step_cancel_file = cancel_file
        if run_manager and run_id:
            step_id = run_manager.create_step(
                run_id=run_id,
                step_type="flow_step",
                step_index=index,
                step_key=f"step_{index}",
                module=module,
                script_name=script,
                parameters=parameters,
                metadata={"flow_id": flow_id},
            )
            run_manager.update_step(step_id, run_id, status="running", started_at=datetime.utcnow().isoformat(), message=f"Flow step {index} started")
            if cancellation_hooks and cancellation_hooks.get("set_active_step"):
                step_cancel_file = str(Path(cancel_file).with_name(f"{run_id}_{step_id}.cancel")) if cancel_file else None
                cancellation_hooks["set_active_step"](step_id, step_cancel_file, {"index": index, "module": module, "script": script})

        step_result = {
            "index": index,
            "module": module,
            "script": script,
            "status": "pending",
            "exit_code": None,
            "duration": None,
            "stdout_preview": "",
            "stderr_preview": "",
            "error": None,
            "step_id": step_id,
        }

        try:
            result = engine.execute_script(
                module_name=module,
                script_name=script,
                parameters=parameters,
                timeout=timeout_per_script or config.execution_timeout,
                execution_id=step_id or None,
                extra_env={
                    "BOFA_RUN_ID": run_id or "",
                    "BOFA_STEP_ID": step_id or "",
                },
                cancel_file=step_cancel_file,
                cancel_check_interval=cancel_check_interval,
            )
            step_result["status"] = result.status
            step_result["exit_code"] = result.exit_code
            step_result["duration"] = result.duration
            step_result["stdout_preview"] = (result.stdout or "")[:2000]
            step_result["stderr_preview"] = (result.stderr or "")[:1000]
            if result.error:
                step_result["error"] = result.error
            if run_manager and run_id and step_id:
                run_manager.update_step(
                    step_id,
                    run_id,
                    status="cancelled" if result.status == "cancelled" else "success" if result.exit_code == 0 else "failed",
                    completed_at=datetime.utcnow().isoformat(),
                    exit_code=result.exit_code,
                    duration=result.duration,
                    stdout_preview=step_result["stdout_preview"],
                    stderr_preview=step_result["stderr_preview"],
                    error_message=result.error,
                    message=f"Flow step {index} completed",
                )
            if result.status == "cancelled":
                if cancellation_hooks and cancellation_hooks.get("clear_active_step"):
                    cancellation_hooks["clear_active_step"](step_id)
                return _finalize_flow_result(
                    flow_id,
                    flow,
                    target,
                    report_dir,
                    engine,
                    config,
                    steps_results + [step_result],
                    "cancelled",
                    run_manager=run_manager,
                    run_id=run_id,
                    cancelled_at_step=index,
                    cause=step_result.get("error") or "Flow cancelled during step execution",
                )
            if result.exit_code != 0:
                any_error = True
        except Exception as exc:
            step_result["status"] = "error"
            step_result["error"] = str(exc)
            any_error = True
            if run_manager and run_id and step_id:
                run_manager.update_step(
                    step_id,
                    run_id,
                    status="failed",
                    completed_at=datetime.utcnow().isoformat(),
                    error_message=str(exc),
                    message=f"Flow step {index} failed",
                )
        finally:
            if cancellation_hooks and cancellation_hooks.get("clear_active_step"):
                cancellation_hooks["clear_active_step"](step_id)
        steps_results.append(step_result)

    if cancel_file and Path(cancel_file).exists():
        return _finalize_flow_result(
            flow_id,
            flow,
            target,
            report_dir,
            engine,
            config,
            steps_results,
            "cancelled",
            run_manager=run_manager,
            run_id=run_id,
            cancelled_at_step=steps_results[-1]["index"] if steps_results else 1,
            cause="Flow cancelled after step execution",
        )

    status = "error" if any_error else "success"
    if any_error and any(step["status"] == "success" for step in steps_results):
        status = "partial"
    cause = None
    if status in {"partial", "error"}:
        first_problem = next((step for step in steps_results if step.get("status") in {"failed", "error", "cancelled"}), None)
        cause = first_problem.get("error") if first_problem else None

    return _finalize_flow_result(
        flow_id,
        flow,
        target,
        report_dir,
        engine,
        config,
        steps_results,
        status,
        run_manager=run_manager,
        run_id=run_id,
        cause=cause,
    )


class FlowRunner:
    @staticmethod
    def list_flows() -> List[Dict[str, Any]]:
        return list_flows()

    @staticmethod
    def run(flow_id: str, target: str, **kwargs) -> Dict[str, Any]:
        return run_flow(flow_id, target, **kwargs)
