"""BOFA security copilot with policy-gated optional execution."""

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

TOOLS_DESC = """
BOFA TOOLS (respond with JSON only):

1. execute_script: Execute a BOFA script.
   {"action": "execute_script", "module": "web", "script": "param_finder", "parameters": {"url": "URL", "json": true}}

2. run_flow: Execute a BOFA flow.
   {"action": "run_flow", "flow_id": "bug_bounty_full_chain", "target": "URL"}

3. run_skill: Execute a bounty skill for an existing workspace.
   {"action": "run_skill", "workspace_id": "workspace_xxx", "skill_key": "delta_recon"}

4. correlate: Correlate previous findings after recon/fuzzing.
   {"action": "correlate"}

5. done: Finish when you have enough signal or no promising steps remain.
   {"action": "done", "reason": "short reason", "success": true/false}
"""


SYSTEM_PROMPT = """You are a BOFA security planning copilot.

Goal:
- propose the next evidence-rich step for an authorized target,
- explain what the step is expected to prove,
- never assume you have permission to execute,
- prefer evidence-rich steps,
- avoid blind loops.

Use run_skill when a workspace_id is available and you need duplicate-aware prioritization.
The host application, not you, decides whether an action may execute.
Respond with valid JSON only.
"""


def _extract_json(text: str) -> Optional[Dict[str, Any]]:
    text = text.strip()
    start = text.find("{")
    if start < 0:
        return None
    depth = 0
    for idx, char in enumerate(text[start:], start):
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start : idx + 1])
                except json.JSONDecodeError:
                    return None
    return None


def _detect_success(stdout: str, script: str) -> List[str]:
    successes: List[str] = []
    try:
        obj = _extract_json(stdout)
        if not obj:
            return successes
        if script == "param_finder" and obj.get("params"):
            successes.append(f"Params found: {[p.get('name', p) for p in obj['params'][:10]]}")
        if script == "path_scanner" and obj.get("findings"):
            successes.append(f"Routes found: {len(obj['findings'])}")
        if script == "security_headers_analyzer" and obj.get("issues"):
            successes.append(f"Header issues: {len(obj['issues'])}")
        if script == "http_param_fuzzer" and obj.get("anomalies"):
            successes.append(f"Fuzzer anomalies: {len(obj['anomalies'])}")
        if script == "findings_correlator" and obj.get("hotspots"):
            successes.append(f"Hotspots: {len(obj['hotspots'])}")
    except Exception:
        pass
    return successes


def _execute_action(
    action: str,
    params: Dict[str, Any],
    target: str,
    context: Optional[List[Dict[str, Any]]] = None,
    workspace_id: Optional[str] = None,
    user_id: Optional[int] = None,
) -> Tuple[str, bool]:
    context = context or []

    if action == "run_flow":
        from core.engine import get_engine
        from flows.flow_runner import run_flow

        engine = get_engine()
        engine.initialize()
        flow_id = params.get("flow_id", "bug_bounty_full_chain")
        selected_target = params.get("target", target)
        try:
            result = run_flow(flow_id, selected_target)
            status = result.get("status", "unknown")
            steps = result.get("steps", [])
            summary: List[str] = []
            successes: List[str] = []
            for step in steps:
                step_status = step.get("status", "")
                module = step.get("module", "")
                script = step.get("script", "")
                summary.append(f"{module}/{script}: {step_status}")
                if step_status == "success" and step.get("stdout_preview"):
                    found = _detect_success(step["stdout_preview"], script)
                    if found:
                        summary.append(f"  -> {found}")
                        successes.extend(found)
            payload = {"status": status, "steps_summary": summary}
            if successes:
                payload["_successes"] = successes
            return json.dumps(payload, indent=2), False
        except Exception as exc:
            return json.dumps({"error": str(exc)}), True

    if action == "correlate" and context:
        steps_data = []
        for item in context:
            result = item.get("result", "")
            try:
                obj = json.loads(result)
            except json.JSONDecodeError:
                continue
            stdout = obj.get("stdout", "")
            if stdout:
                steps_data.append({"stdout_preview": stdout})
        if not steps_data:
            return json.dumps({"error": "No prior data to correlate"}), True

        import subprocess

        script_path = _ROOT / "scripts" / "reporting" / "findings_correlator.py"
        inp = json.dumps({"steps": steps_data})
        try:
            process = subprocess.run(
                [sys.executable, str(script_path), "--target", target, "--stdin", "--json"],
                input=inp,
                capture_output=True,
                text=True,
                timeout=30,
                cwd=str(_ROOT),
            )
            output = process.stdout or process.stderr or ""
            obj = _extract_json(output) or {}
            successes: List[str] = []
            if obj.get("hotspots"):
                successes.append(f"Hotspots: {len(obj['hotspots'])}")
            return json.dumps({"stdout": output, "_successes": successes, **obj}, indent=2), process.returncode != 0
        except Exception as exc:
            return json.dumps({"error": str(exc)}), True

    if action == "execute_script":
        from core.engine import get_engine

        engine = get_engine()
        engine.initialize()
        module = params.get("module", "")
        script = params.get("script", "")
        script_params = params.get("parameters", params)
        if not isinstance(script_params, dict):
            script_params = {}
        if "url" not in script_params and "target" not in script_params:
            script_params["url"] = target
        if not module or not script:
            return json.dumps({"error": "module and script are required"}), True
        try:
            result = engine.execute_script(module_name=module, script_name=script, parameters=script_params)
            payload = {
                "status": result.status,
                "exit_code": result.exit_code,
                "stdout": (result.stdout or "")[:3000],
                "stderr": (result.stderr or "")[:500],
                "error": result.error,
            }
            successes = _detect_success(result.stdout or "", script)
            if successes:
                payload["_successes"] = successes
            return json.dumps(payload, indent=2), result.exit_code != 0
        except Exception as exc:
            return json.dumps({"error": str(exc)}), True

    if action == "run_skill":
        selected_workspace_id = params.get("workspace_id") or workspace_id
        skill_key = params.get("skill_key")
        if not selected_workspace_id or not skill_key:
            return json.dumps({"error": "workspace_id and skill_key are required"}), True
        if user_id is None:
            return json.dumps({"error": "A concrete BOFA user id is required for workspace skills"}), True
        try:
            from api.database import db as api_db
            from api.run_manager import RunManager as ApiRunManager
            from core.bounty_service import BountyWorkspaceService

            service = BountyWorkspaceService(api_db, ApiRunManager(api_db), _ROOT)
            result = service.run_skill(
                workspace_id=selected_workspace_id,
                skill_key=skill_key,
                user_id=user_id,
                source="agent",
            )
            return json.dumps(result, indent=2, ensure_ascii=False), False
        except Exception as exc:
            return json.dumps({"error": str(exc)}), True

    return json.dumps({"error": f"Unknown action: {action}"}), True


def _required_capabilities(action: str) -> List[str]:
    if action in {"run_skill", "correlate"}:
        return ["evidence_read"]
    if action in {"execute_script", "run_flow"}:
        return ["network_active"]
    return []


def _policy_preflight(
    action: str,
    target: str,
    grant_payload: Mapping[str, Any],
    profile_payload: Mapping[str, Any],
    subject_id: str,
) -> Dict[str, Any]:
    from core.execution import AuthorizationGrant, ExecutionPolicyEngine, ExecutionProfile, ExecutionRequest

    grant = AuthorizationGrant.from_dict(grant_payload)
    profile = ExecutionProfile.from_dict(profile_payload)
    capabilities = _required_capabilities(action)
    request = ExecutionRequest.from_dict(
        {
            "subject_id": subject_id,
            "action": f"ai:{action}",
            "profile_id": profile.id,
            "required_capabilities": capabilities,
            "project_id": grant.project_id,
            "environment_id": grant.environment_id,
            "target": None if capabilities == ["evidence_read"] else target,
            "approval_id": grant.approval_id,
            "requested_steps": 1,
            "metadata": {"initiator": "llm_copilot"},
        }
    )
    decision = ExecutionPolicyEngine().evaluate(request, grant, profile)
    return {"decision": decision.to_dict(), "request": request.to_dict()}


def run_security_agent(
    target: str,
    provider: str = "auto",
    max_iterations: int = 15,
    verbose: bool = True,
    workspace_id: Optional[str] = None,
    execute: bool = False,
    grant_payload: Optional[Mapping[str, Any]] = None,
    profile_payload: Optional[Mapping[str, Any]] = None,
    subject_id: Optional[str] = None,
    llm_provider=None,
) -> Dict[str, Any]:
    from .llm_providers import get_provider

    target = target.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    llm = llm_provider or get_provider(provider)
    provider_id = getattr(llm, "provider_id", provider)
    provider_locality = getattr(llm, "locality", "unknown")
    if execute and (not grant_payload or not profile_payload or not subject_id):
        return {
            "status": "policy_required",
            "success": False,
            "reason": "Execution requires subject_id, authorization grant and execution profile",
            "provider": provider_id,
            "executed": False,
            "findings": [],
            "iterations": 0,
        }
    context: List[Dict[str, Any]] = []
    all_findings: List[str] = []
    iteration = 0

    if verbose:
        print(f"[Agent] Target: {target}")
        print(f"[Agent] Provider: {provider_id} ({provider_locality})")
        print(f"[Agent] Mode: {'execute' if execute else 'plan'}")
        if workspace_id:
            print(f"[Agent] Workspace: {workspace_id}")
        print("[Agent] Starting Observe-Think-Act loop...")
        print()

    while iteration < max_iterations:
        iteration += 1
        if verbose:
            print(f"--- Iteration {iteration}/{max_iterations} ---")

        context_str = ""
        if context:
            context_str = "PREVIOUS FINDINGS:\n"
            for index, item in enumerate(context[-6:], 1):
                context_str += f"\n[{index}] Action: {item.get('action', '')}\n"
                context_str += f"Result: {str(item.get('result', ''))[:1500]}...\n"
                if item.get("successes"):
                    context_str += f"SIGNAL: {item['successes']}\n"

        workspace_context = f"\nWorkspace bounty: {workspace_id}\n" if workspace_id else "\nWorkspace bounty: none\n"
        prompt = f"""Target: {target}
{workspace_context}
{context_str}

What BOFA tool do you execute next? Respond with JSON only."""

        response = llm.complete(prompt, system=SYSTEM_PROMPT + "\n\n" + TOOLS_DESC, max_tokens=1024)
        if verbose:
            print(f"[Think] {response[:300]}...")

        action_data = _extract_json(response)
        if not action_data:
            if verbose:
                print("[Agent] Could not parse JSON, retrying...")
            context.append({"action": "parse_error", "result": response[:500], "successes": []})
            continue

        if action_data.get("error"):
            if verbose:
                print(f"[Agent] LLM error: {action_data.get('error', '')[:120]}")
            return {
                "status": "provider_error",
                "success": False,
                "reason": action_data.get("error", "LLM provider failed"),
                "provider": provider_id,
                "executed": False,
                "findings": all_findings,
                "iterations": iteration,
            }

        action = action_data.get("action", "")
        if action == "done":
            reason = action_data.get("reason", "Finished by agent")
            success = action_data.get("success", False)
            if verbose:
                print(f"[Done] {reason} (success={success})")
            return {
                "status": "done",
                "success": success,
                "reason": reason,
                "findings": all_findings,
                "iterations": iteration,
                "provider": provider_id,
                "executed": False,
            }

        params = {key: value for key, value in action_data.items() if key != "action"}
        if action == "execute_script":
            if "parameters" not in params:
                params["parameters"] = {
                    key: value
                    for key, value in params.items()
                    if key in ("url", "json", "params", "payload_set", "payload-set", "timeout", "limit", "method", "paths")
                }
            else:
                script_params = params["parameters"]
                if isinstance(script_params, dict) and "url" not in script_params:
                    script_params["url"] = target
                    script_params.setdefault("json", True)

        if not execute:
            return {
                "status": "plan_ready",
                "success": True,
                "reason": "A proposed action is ready for human and policy review",
                "provider": provider_id,
                "provider_locality": provider_locality,
                "executed": False,
                "proposed_action": {"action": action, **params},
                "required_capabilities": _required_capabilities(action),
                "findings": all_findings,
                "iterations": iteration,
            }

        preflight = _policy_preflight(
            action,
            target,
            grant_payload or {},
            profile_payload or {},
            subject_id or "",
        )
        if not preflight["decision"]["allowed"]:
            return {
                "status": "policy_denied",
                "success": False,
                "reason": "BOFA policy denied the LLM-proposed action",
                "provider": provider_id,
                "executed": False,
                "proposed_action": {"action": action, **params},
                "preflight": preflight,
                "findings": all_findings,
                "iterations": iteration,
            }

        resolved_user_id = int(subject_id) if subject_id and subject_id.isdigit() else None
        result_str, _had_error = _execute_action(
            action,
            params,
            target,
            context,
            workspace_id=workspace_id,
            user_id=resolved_user_id,
        )
        result_obj = json.loads(result_str) if result_str.startswith("{") else {}
        successes = result_obj.pop("_successes", [])
        all_findings.extend(successes)

        context.append({"action": action, "params": params, "result": result_str, "successes": successes})

        if verbose:
            print(f"[Act] {action} -> status={result_obj.get('status', '?')}")
            if successes:
                print(f"[Signal] {successes}")

    return {
        "status": "max_iterations",
        "success": len(all_findings) > 0,
        "reason": f"Iteration limit {max_iterations}",
        "findings": all_findings,
        "iterations": iteration,
        "provider": provider_id,
        "executed": execute,
    }


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="BOFA policy-gated security copilot")
    parser.add_argument("target", help="Target URL")
    parser.add_argument(
        "--provider",
        default="auto",
        choices=["auto", "ollama", "openai_compatible", "openai", "anthropic"],
    )
    parser.add_argument("--max-iterations", type=int, default=15)
    parser.add_argument("--workspace-id", default=None)
    parser.add_argument("--execute", action="store_true", help="Allow policy-gated execution instead of plan-only mode")
    parser.add_argument("--grant-file", default=None, help="Authorization grant JSON required with --execute")
    parser.add_argument("--profile-file", default=None, help="Execution profile JSON required with --execute")
    parser.add_argument("--subject-id", default=None, help="BOFA user id required with --execute")
    parser.add_argument("-q", "--quiet", action="store_true")
    args = parser.parse_args()

    if args.execute and (not args.grant_file or not args.profile_file or not args.subject_id):
        parser.error("--execute requires --grant-file, --profile-file and --subject-id")
    grant_payload = json.loads(Path(args.grant_file).read_text(encoding="utf-8")) if args.grant_file else None
    profile_payload = json.loads(Path(args.profile_file).read_text(encoding="utf-8")) if args.profile_file else None
    result = run_security_agent(
        target=args.target,
        provider=args.provider,
        max_iterations=args.max_iterations,
        verbose=not args.quiet,
        workspace_id=args.workspace_id,
        execute=args.execute,
        grant_payload=grant_payload,
        profile_payload=profile_payload,
        subject_id=args.subject_id,
    )

    print()
    print("=" * 50)
    print("FINAL RESULT")
    print("=" * 50)
    print(f"Status: {result['status']}")
    print(f"Success: {result['success']}")
    print(f"Reason: {result['reason']}")
    print(f"Iterations: {result['iterations']}")
    print(f"Executed: {result.get('executed', False)}")
    if result.get("proposed_action"):
        print(f"Proposed action: {json.dumps(result['proposed_action'], ensure_ascii=False)}")
    print(f"Findings: {len(result['findings'])}")
    for finding in result["findings"]:
        print(f"  - {finding}")

    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
