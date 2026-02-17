#!/usr/bin/env python3
"""
Flow Report Aggregator - BOFA Reporting
========================================

Genera informe ejecutivo a partir del JSON de salida de run_flow.
Parsea stdout de cada paso, extrae hallazgos estructurados y produce
un Markdown con resumen, hotspots y score de riesgo.

Uso:
    python3 flow_report_aggregator.py --input reports/flow_bug_bounty_full_chain_xxx.json --output reports/executive.md
    python3 flow_report_aggregator.py --stdin < flow_output.json --output reports/executive.md --json
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def _try_parse_json(text: str) -> Optional[Dict[str, Any]]:
    """Intenta extraer y parsear JSON de un texto (puede tener prefijo/sufijo)."""
    if not text or not isinstance(text, str):
        return None
    text = text.strip()
    # Buscar bloque JSON
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


def _extract_findings(steps: List[Dict], target: str) -> Dict[str, Any]:
    """Extrae hallazgos por tipo de script desde steps."""
    findings: Dict[str, Any] = {
        "params": [],
        "paths": [],
        "anomalies": [],
        "header_issues": [],
        "chain_steps": [],
        "raw": {},
    }

    script_map = {
        "param_finder": "params",
        "path_scanner": "paths",
        "http_param_fuzzer": "anomalies",
        "security_headers_analyzer": "header_issues",
        "exploit_chain_suggester": "chain_steps",
    }

    for step in steps or []:
        module = step.get("module") or ""
        script = step.get("script") or ""
        preview = step.get("stdout_preview") or ""
        key = f"{module}/{script}"

        obj = _try_parse_json(preview)
        if not obj:
            continue

        findings["raw"][key] = obj

        if script == "param_finder" and "params" in obj:
            for p in obj.get("params") or []:
                name = p.get("name") if isinstance(p, dict) else str(p)
                if name:
                    findings["params"].append(name)

        elif script == "path_scanner" and "findings" in obj:
            findings["paths"].extend(obj.get("findings") or [])

        elif script == "http_param_fuzzer":
            findings["anomalies"].extend(obj.get("anomalies") or [])

        elif script == "security_headers_analyzer" and "issues" in obj:
            findings["header_issues"].extend(obj.get("issues") or [])

        elif script == "exploit_chain_suggester" and "chain" in obj:
            findings["chain_steps"].extend(obj.get("chain") or [])

    return findings


def _compute_risk_score(findings: Dict[str, Any]) -> Tuple[float, str]:
    """Calcula score 0-10 y nivel."""
    score = 0.0
    if findings.get("anomalies"):
        score += min(4.0, len(findings["anomalies"]) * 1.0)
    if findings.get("header_issues"):
        high = sum(1 for i in findings["header_issues"] if (i.get("severity") or "").upper() == "HIGH")
        score += min(3.0, high * 1.0)
    if findings.get("paths"):
        sens = ["admin", "login", "config", "api", "debug"]
        for p in findings["paths"]:
            path = (p.get("path") or "").lower()
            if any(s in path for s in sens):
                score += 1.5
                break
    if findings.get("params"):
        score += min(2.0, len(findings["params"]) * 0.3)

    score = min(10.0, score)
    if score >= 7:
        level = "critical"
    elif score >= 5:
        level = "high"
    elif score >= 3:
        level = "medium"
    elif score >= 1:
        level = "low"
    else:
        level = "info"
    return round(score, 1), level


def _generate_markdown(
    flow_name: str,
    target: str,
    status: str,
    timestamp: str,
    findings: Dict[str, Any],
    score: float,
    level: str,
) -> str:
    """Genera informe Markdown ejecutivo."""
    lines = [
        f"# Informe Ejecutivo: {flow_name}",
        "",
        f"- **Target:** {target}",
        f"- **Status:** {status}",
        f"- **Timestamp:** {timestamp}",
        f"- **Risk Score:** {score}/10 ({level})",
        "",
        "## Resumen de hallazgos",
        "",
    ]

    if findings.get("params"):
        lines.append("### Parámetros encontrados")
        lines.append("")
        for p in findings["params"][:15]:
            lines.append(f"- `{p}`")
        lines.append("")

    if findings.get("paths"):
        lines.append("### Rutas accesibles")
        lines.append("")
        for pf in findings["paths"][:15]:
            url = pf.get("url", "")
            status_code = pf.get("status", "")
            lines.append(f"- {status_code} {url}")
        lines.append("")

    if findings.get("anomalies"):
        lines.append("### Anomalías (fuzzer)")
        lines.append("")
        for a in findings["anomalies"][:10]:
            url = a.get("url", "")
            payload = a.get("payload", "")
            reason = a.get("reason", "")
            lines.append(f"- `{payload[:50]}...` en {url} ({reason})")
        lines.append("")

    if findings.get("header_issues"):
        lines.append("### Cabeceras de seguridad")
        lines.append("")
        for i in findings["header_issues"][:10]:
            h = i.get("header", "")
            sev = i.get("severity", "")
            detail = i.get("detail", "")
            lines.append(f"- **{h}** ({sev}): {detail}")
        lines.append("")

    if findings.get("chain_steps"):
        lines.append("### Cadena sugerida (exploit_chain_suggester)")
        lines.append("")
        for i, step in enumerate(findings["chain_steps"][:8], 1):
            mod = step.get("module", "")
            scr = step.get("script", "")
            reason = step.get("reason", "")
            lines.append(f"{i}. {mod}/{scr}: {reason}")
        lines.append("")

    lines.append("## Recomendaciones")
    lines.append("")
    recs = []
    if findings.get("anomalies"):
        recs.append("Investigar anomalías de longitud en respuestas del fuzzer.")
    if findings.get("header_issues"):
        recs.append("Implementar cabeceras de seguridad faltantes (HSTS, CSP, etc.).")
    if findings.get("params"):
        recs.append(f"Priorizar fuzzing de params: {', '.join(findings['params'][:5])}.")
    if not recs:
        recs.append("Revisar manualmente los hallazgos del flujo.")
    for r in recs:
        lines.append(f"- {r}")
    lines.append("")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generar informe ejecutivo desde JSON de run_flow"
    )
    parser.add_argument(
        "--input",
        type=str,
        default=None,
        help="Ruta al JSON de salida del flow",
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="Leer JSON desde stdin",
    )
    parser.add_argument(
        "--output",
        type=str,
        required=True,
        help="Ruta de salida del informe Markdown",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Escribir también JSON con estructura completa",
    )
    args = parser.parse_args()

    data: Optional[Dict] = None
    if args.stdin and not sys.stdin.isatty():
        try:
            data = json.load(sys.stdin)
        except json.JSONDecodeError:
            print("Error: JSON inválido en stdin", file=sys.stderr)
            return 1
    elif args.input:
        p = Path(args.input)
        if not p.exists():
            print(f"Error: archivo no encontrado: {args.input}", file=sys.stderr)
            return 1
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            print(f"Error leyendo {args.input}: {e}", file=sys.stderr)
            return 1
    else:
        print("Error: usar --input o --stdin", file=sys.stderr)
        return 1

    if not data:
        print("Error: sin datos", file=sys.stderr)
        return 1

    steps = data.get("steps") or []
    target = data.get("target") or "unknown"
    flow_name = data.get("flow_name") or data.get("flow_id") or "Flow"
    status = data.get("status") or "unknown"
    timestamp = data.get("timestamp") or ""

    findings = _extract_findings(steps, target)
    score, level = _compute_risk_score(findings)

    md_content = _generate_markdown(
        flow_name=flow_name,
        target=target,
        status=status,
        timestamp=timestamp,
        findings=findings,
        score=score,
        level=level,
    )

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(md_content)

    print(f"Informe guardado: {out_path}", file=sys.stderr)

    if args.json:
        json_path = out_path.with_suffix(out_path.suffix + ".json")
        report_json = {
            "flow_name": flow_name,
            "target": target,
            "status": status,
            "timestamp": timestamp,
            "risk_score": score,
            "risk_level": level,
            "findings": findings,
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report_json, f, indent=2, ensure_ascii=False)
        print(f"JSON guardado: {json_path}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
