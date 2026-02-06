#!/usr/bin/env python3
"""
Report Finding - Informe de hallazgo para disclosure
=====================================================

Genera un informe de hallazgo (vulnerabilidad / zero-day) en Markdown y/o JSON
listo para disclosure a vendor o CERT. No descubre vulnerabilidades; solo formatea.

Uso:
  python3 report_finding.py --title "Título" --description "..." --severity high --steps "1. Paso 1\n2. Paso 2" --output reports/finding_001.md
"""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime, timezone


def main():
    parser = argparse.ArgumentParser(description="Generar informe de hallazgo para disclosure")
    parser.add_argument("--title", type=str, required=True, help="Título del hallazgo")
    parser.add_argument("--description", type=str, required=True, help="Descripción de la vulnerabilidad")
    parser.add_argument("--severity", type=str, required=True, choices=["critical", "high", "medium", "low", "info"], help="Severidad")
    parser.add_argument("--steps", type=str, required=True, help="Pasos para reproducir (texto o numerado)")
    parser.add_argument("--impact", type=str, default="", help="Impacto potencial (opcional)")
    parser.add_argument("--mitigation", type=str, default="", help="Mitigación recomendada (opcional)")
    parser.add_argument("--references", type=str, default="", help="Referencias (opcional)")
    parser.add_argument("--output", type=str, required=True, help="Ruta de salida (.md o .json)")
    parser.add_argument("--json", action="store_true", help="Escribir también un .json junto al .md")
    args = parser.parse_args()

    data = {
        "title": args.title,
        "description": args.description,
        "severity": args.severity.upper(),
        "steps_to_reproduce": args.steps,
        "impact": args.impact or None,
        "mitigation": args.mitigation or None,
        "references": args.references or None,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if out_path.suffix.lower() == ".json":
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    else:
        md_lines = [
            f"# {data['title']}",
            "",
            f"**Severidad:** {data['severity']}",
            f"**Fecha:** {data['timestamp']}",
            "",
            "## Descripción",
            "",
            data["description"],
            "",
            "## Pasos para reproducir",
            "",
            data["steps_to_reproduce"].replace("\\n", "\n"),
            "",
        ]
        if data.get("impact"):
            md_lines.extend(["## Impacto", "", data["impact"], ""])
        if data.get("mitigation"):
            md_lines.extend(["## Mitigación recomendada", "", data["mitigation"], ""])
        if data.get("references"):
            md_lines.extend(["## Referencias", "", data["references"], ""])
        with open(out_path, "w", encoding="utf-8") as f:
            f.write("\n".join(md_lines))

    if args.json and out_path.suffix.lower() != ".json":
        json_path = out_path.with_suffix(out_path.suffix + ".json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"Informe guardado: {out_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
