"""
Security Agent - Agente autónomo que razona y vulnera
======================================================

Loop Observe-Think-Act: observa hallazgos, razona con LLM, ejecuta herramientas BOFA,
hasta encontrar vulnerabilidades o agotar opciones.

Soporta: Ollama (local), OpenAI, Anthropic.
"""

import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.engine import get_engine
from flows.flow_runner import run_flow

# Herramientas disponibles para el agente
TOOLS_DESC = """
HERRAMIENTAS BOFA (responde con JSON):

1. execute_script: Ejecuta un script BOFA.
   {"action": "execute_script", "module": "web", "script": "param_finder", "parameters": {"url": "URL", "json": true, "insecure": true}}

2. run_flow: Ejecuta un flujo completo.
   {"action": "run_flow", "flow_id": "bug_bounty_full_chain", "target": "URL"}

3. correlate: Correlaciona hallazgos previos (ejecutar tras param_finder, path_scanner, fuzzer).
   {"action": "correlate"}

4. done: Termina cuando hayas encontrado vulnerabilidades o agotado opciones.
   {"action": "done", "reason": "Explicación breve", "success": true/false}

Scripts clave para vulnerar:
- recon/web_discover, recon/http_headers (recon)
- web/param_finder (extrae params de formularios/enlaces) -> USA insecure: true si SSL falla
- web/path_scanner (busca admin, login, .git, etc.)
- web/security_headers_analyzer (HSTS, CSP faltantes)
- web/robots_txt
- exploit/http_param_fuzzer (fuzzing con params) -> params desde param_finder, payload-set: sqli o xss
- reporting/findings_correlator (correla param_finder+path_scanner+fuzzer para hotspots)

IMPORTANTE: Si el target tiene SSL autofirmado, añade "insecure": true a todos los scripts web/recon.
Encadena: param_finder devuelve params -> usa esos params en http_param_fuzzer con payload-set sqli,xss.
Si path_scanner encuentra rutas -> prueba param_finder en esas URLs (url + path).
"""

SYSTEM_PROMPT = """Eres un pentester autónomo. Tu objetivo es encontrar vulnerabilidades en el target.

Tienes acceso a herramientas BOFA. Debes:
1. OBSERVAR los hallazgos previos
2. RAZONAR qué probar a continuación (basándote en lo encontrado)
3. ACTUAR ejecutando la herramienta más prometedora
4. REPETIR hasta encontrar vulnerabilidades o agotar opciones

Criterios de ÉXITO (vulnerabilidad encontrada):
- param_finder: params encontrados
- path_scanner: rutas con 200/301/302/401/403
- security_headers_analyzer: issues (HSTS, CSP, etc. faltantes)
- http_param_fuzzer: anomalies (respuestas con longitud anómala)
- findings_correlator: hotspots priorizados

Estrategia: Empieza con recon (web_discover, http_headers), luego param_finder y path_scanner.
Si encuentras params, fuzzéalos con payload-set sqli o xss. Si encuentras rutas sensibles, profundiza.
Correlaciona hallazgos con findings_correlator. Usa insecure: true si hay errores SSL.

Responde ÚNICAMENTE con un JSON válido (action + parámetros). Sin markdown, sin explicación extra."""


def _extract_json(text: str) -> Optional[Dict[str, Any]]:
    """Extrae el primer JSON del texto."""
    text = text.strip()
    start = text.find("{")
    if start < 0:
        return None
    depth = 0
    for i, c in enumerate(text[start:], start):
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start : i + 1])
                except json.JSONDecodeError:
                    pass
                return None
    return None


def _detect_success(stdout: str, script: str) -> List[str]:
    """Detecta si el output indica hallazgos/vulnerabilidades."""
    successes = []
    try:
        obj = _extract_json(stdout)
        if not obj:
            return successes
        if script == "param_finder" and obj.get("params"):
            successes.append(f"Params encontrados: {[p.get('name', p) for p in obj['params'][:10]]}")
        if script == "path_scanner" and obj.get("findings"):
            successes.append(f"Rutas encontradas: {len(obj['findings'])}")
        if script == "security_headers_analyzer" and obj.get("issues"):
            successes.append(f"Issues de cabeceras: {len(obj['issues'])}")
        if script == "http_param_fuzzer":
            if obj.get("anomalies"):
                successes.append(f"Anomalías en fuzzer: {len(obj['anomalies'])}")
            if obj.get("results") and not obj.get("errors"):
                successes.append("Fuzzer completó sin errores")
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
) -> Tuple[str, bool]:
    """Ejecuta la acción y retorna (resultado_texto, si_hay_error)."""
    context = context or []

    if action == "run_flow":
        engine = get_engine()
        engine.initialize()
        flow_id = params.get("flow_id", "bug_bounty_full_chain")
        t = params.get("target", target)
        try:
            result = run_flow(flow_id, t)
            status = result.get("status", "unknown")
            steps = result.get("steps", [])
            summary = []
            all_successes = []
            for s in steps:
                st = s.get("status", "")
                mod = s.get("module", "")
                scr = s.get("script", "")
                summary.append(f"{mod}/{scr}: {st}")
                if st == "success" and s.get("stdout_preview"):
                    succ = _detect_success(s["stdout_preview"], scr)
                    if succ:
                        summary.append(f"  -> {succ}")
                        all_successes.extend(succ)
            out = {"status": status, "steps_summary": summary}
            if all_successes:
                out["_successes"] = all_successes
            return json.dumps(out, indent=2), False
        except Exception as e:
            return json.dumps({"error": str(e)}), True

    if action == "correlate" and context:
        # Correlaciona hallazgos previos usando findings_correlator
        steps_data = []
        for c in context:
            res = c.get("result", "")
            try:
                obj = json.loads(res)
                stdout = obj.get("stdout", "")
                if stdout:
                    steps_data.append({"stdout_preview": stdout})
            except json.JSONDecodeError:
                pass
        if not steps_data:
            return json.dumps({"error": "No hay datos previos para correlacionar"}), True
        import subprocess
        from pathlib import Path
        script_path = Path(__file__).parent.parent / "scripts" / "reporting" / "findings_correlator.py"
        inp = json.dumps({"steps": steps_data})
        try:
            r = subprocess.run(
                ["python3", str(script_path), "--target", target, "--stdin", "--json"],
                input=inp.encode("utf-8"),
                capture_output=True,
                text=True,
                timeout=30,
                cwd=str(Path(__file__).parent.parent),
            )
            out = r.stdout or r.stderr or ""
            obj = _extract_json(out) or {}
            successes = []
            if obj.get("hotspots"):
                successes.append(f"Hotspots: {len(obj['hotspots'])}")
            return json.dumps({"stdout": out, "_successes": successes, **obj}, indent=2), r.returncode != 0
        except Exception as e:
            return json.dumps({"error": str(e)}), True

    if action == "execute_script":
        engine = get_engine()
        engine.initialize()
        module = params.get("module", "")
        script = params.get("script", "")
        pars = params.get("parameters", params)
        if isinstance(pars, dict) is False:
            pars = {}
        if "url" not in pars and "target" not in pars:
            pars["url"] = target
        if not module or not script:
            return json.dumps({"error": "module y script requeridos"}), True
        try:
            result = engine.execute_script(
                module_name=module,
                script_name=script,
                parameters=pars,
            )
            out = {
                "status": result.status,
                "exit_code": result.exit_code,
                "stdout": (result.stdout or "")[:3000],
                "stderr": (result.stderr or "")[:500],
                "error": result.error,
            }
            successes = _detect_success(result.stdout or "", script)
            if successes:
                out["_successes"] = successes
            return json.dumps(out, indent=2), result.exit_code != 0
        except Exception as e:
            return json.dumps({"error": str(e)}), True

    return json.dumps({"error": f"Acción desconocida: {action}"}), True


def run_security_agent(
    target: str,
    provider: str = "auto",
    max_iterations: int = 15,
    verbose: bool = True,
) -> Dict[str, Any]:
    """
    Ejecuta el agente de seguridad hasta encontrar vulnerabilidades o agotar.

    Args:
        target: URL objetivo (ej. https://yungkuoo.com)
        provider: ollama, openai, anthropic, auto
        max_iterations: Máximo de pasos
        verbose: Imprimir progreso

    Returns:
        Dict con status, findings, iterations, final_reason
    """
    from .llm_providers import get_provider

    target = target.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    llm = get_provider(provider)
    context: List[Dict[str, Any]] = []
    all_findings: List[str] = []
    iteration = 0

    if verbose:
        print(f"[Agent] Target: {target}")
        print(f"[Agent] Provider: {provider}")
        print("[Agent] Iniciando loop Observe-Think-Act...")
        print()

    while iteration < max_iterations:
        iteration += 1
        if verbose:
            print(f"--- Iteración {iteration}/{max_iterations} ---")

        # Construir prompt
        context_str = ""
        if context:
            context_str = "HALLAZGOS PREVIOS:\n"
            for i, c in enumerate(context[-6:], 1):  # últimas 6
                context_str += f"\n[{i}] Acción: {c.get('action', '')}\n"
                context_str += f"Resultado: {str(c.get('result', ''))[:1500]}...\n"
                if c.get("successes"):
                    context_str += f"ÉXITOS: {c['successes']}\n"

        prompt = f"""Target: {target}
{context_str}

¿Qué herramienta ejecutas ahora? Responde SOLO con JSON."""

        # Think
        response = llm.complete(prompt, system=SYSTEM_PROMPT + "\n\n" + TOOLS_DESC, max_tokens=1024)

        if verbose:
            print(f"[Think] {response[:300]}...")

        # Parse action
        action_data = _extract_json(response)
        if not action_data:
            if verbose:
                print("[Agent] No se pudo parsear JSON, reintentando...")
            context.append({"action": "parse_error", "result": response[:500], "successes": []})
            continue

        # Si el LLM devolvió un error (ej. Ollama no disponible)
        if action_data.get("error"):
            if verbose:
                print(f"[Agent] Error del LLM: {action_data.get('error', '')[:100]}")
            if iteration == 1:
                # Fallback: ejecutar run_flow como primera acción
                if verbose:
                    print("[Agent] Fallback: ejecutando run_flow bug_bounty_full_chain")
                action_data = {"action": "run_flow", "flow_id": "bug_bounty_full_chain", "target": target}
            else:
                context.append({"action": "llm_error", "result": response[:500], "successes": []})
                continue

        action = action_data.get("action", "")
        if action == "done":
            reason = action_data.get("reason", "Finalizado por el agente")
            success = action_data.get("success", False)
            if verbose:
                print(f"[Done] {reason} (success={success})")
            return {
                "status": "done",
                "success": success,
                "reason": reason,
                "findings": all_findings,
                "iterations": iteration,
            }

        params = {k: v for k, v in action_data.items() if k != "action"}
        if action == "execute_script":
            if "parameters" not in params:
                params["parameters"] = {k: v for k, v in params.items() if k in ("url", "json", "insecure", "params", "payload_set", "payload-set", "timeout", "limit", "method", "paths")}
            else:
                # Asegurar url en parameters
                p = params["parameters"]
                if isinstance(p, dict) and "url" not in p:
                    p["url"] = target
                    if "insecure" not in p:
                        p["insecure"] = True
                    if "json" not in p:
                        p["json"] = True

        # Act
        result_str, had_error = _execute_action(action, params, target, context)
        result_obj = json.loads(result_str) if result_str.startswith("{") else {}
        successes = result_obj.pop("_successes", [])
        all_findings.extend(successes)

        context.append({
            "action": action,
            "params": params,
            "result": result_str,
            "successes": successes,
        })

        if verbose:
            print(f"[Act] {action} -> status={result_obj.get('status', '?')}")
            if successes:
                print(f"[Éxito] {successes}")

        # Si encontramos vulnerabilidades y el agente no dijo done, podemos sugerirle
        if successes and iteration >= 3:
            # Dar opción de terminar con éxito
            pass

    return {
        "status": "max_iterations",
        "success": len(all_findings) > 0,
        "reason": f"Límite de {max_iterations} iteraciones",
        "findings": all_findings,
        "iterations": iteration,
    }


def main() -> int:
    """CLI para el agente."""
    import argparse
    parser = argparse.ArgumentParser(description="Agente de seguridad autónomo BOFA")
    parser.add_argument("target", help="URL objetivo")
    parser.add_argument("--provider", default="auto", choices=["auto", "ollama", "openai", "anthropic"])
    parser.add_argument("--max-iterations", type=int, default=15)
    parser.add_argument("-q", "--quiet", action="store_true")
    args = parser.parse_args()

    result = run_security_agent(
        target=args.target,
        provider=args.provider,
        max_iterations=args.max_iterations,
        verbose=not args.quiet,
    )

    print()
    print("=" * 50)
    print("RESULTADO FINAL")
    print("=" * 50)
    print(f"Status: {result['status']}")
    print(f"Success: {result['success']}")
    print(f"Reason: {result['reason']}")
    print(f"Iterations: {result['iterations']}")
    print(f"Findings: {len(result['findings'])}")
    for f in result["findings"]:
        print(f"  - {f}")

    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
