#!/usr/bin/env python3
"""
Zero-Day Disclosure Kit - BOFA
===============================

Genera plantillas y workflow para divulgación responsable de zero-days
y vulnerabilidades críticas. Incluye: timeline sugerido, plantilla CERT,
plantilla vendor, checklist de divulgación. No ejecuta nada; solo genera documentos.

Uso:
    python3 zero_day_disclosure_kit.py --cve CVE-2024-XXXX --vendor "Vendor Inc" --output reports/
    python3 zero_day_disclosure_kit.py --title "RCE en X" --severity critical --json
"""

import argparse
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional, List


def _timeline_template(days_until_disclosure: int = 90) -> Dict[str, str]:
    """Timeline sugerido para divulgación coordinada."""
    base = datetime.utcnow()
    return {
        "D0": base.strftime("%Y-%m-%d"),
        "D+7": "Contacto inicial con vendor (canal seguro)",
        "D+14": "Vendor confirma recepción",
        "D+30": "Vendor desarrolla parche (seguimiento)",
        "D+60": "Preparar advisory público",
        f"D+{days_until_disclosure}": "Divulgación pública coordinada",
    }


def _cert_template(cve_id: str, description: str, severity: str, vendor: str) -> str:
    """Plantilla para reporte a CERT/CSIRT."""
    return f"""# Reporte a CERT/CSIRT - Vulnerabilidad

**Fecha:** {datetime.utcnow().strftime("%Y-%m-%d")}
**CVE (si asignado):** {cve_id}
**Severidad:** {severity.upper()}
**Vendor afectado:** {vendor}

## Resumen
{description}

## Impacto
[Describir impacto: RCE, LPE, bypass auth, etc.]

## Versiones afectadas
[Ej: Producto X < 2.3.1]

## Pasos para reproducir
1. [Paso 1]
2. [Paso 2]
3. [Paso 3]

## Mitigación temporal
[Workaround si existe]

## Contacto del investigador
[Email seguro para coordinación]

---
Generado por BOFA zero_day_disclosure_kit
"""


def _vendor_template(cve_id: str, description: str, severity: str) -> str:
    """Plantilla para contacto con vendor."""
    return f"""# Divulgación responsable - Vulnerabilidad

Estimado equipo de seguridad,

Les informo de una vulnerabilidad de seguridad identificada en [PRODUCTO].

**Identificador:** {cve_id or "Pendiente de asignación"}
**Severidad:** {severity.upper()}
**Descripción:** {description}

Solicito:
1. Confirmación de recepción en 7 días
2. Canal seguro para intercambio técnico (PGP preferido)
3. Coordinación para timeline de parche y divulgación

Adjunto detalles técnicos en documento separado (bajo NDA si aplica).

Atentamente,
[Investigador]
"""


def _checklist() -> List[Dict[str, Any]]:
    """Checklist de divulgación responsable."""
    return [
        {"id": 1, "item": "Documentar hallazgo (pasos, impacto, versión)", "done": False},
        {"id": 2, "item": "Verificar que es 0-day (no duplicado de CVE conocido)", "done": False},
        {"id": 3, "item": "Identificar vendor y canal de contacto seguro", "done": False},
        {"id": 4, "item": "Enviar reporte inicial con timeline sugerido", "done": False},
        {"id": 5, "item": "Firmar NDA si vendor lo requiere para detalles", "done": False},
        {"id": 6, "item": "Coordinar fecha de divulgación pública", "done": False},
        {"id": 7, "item": "Preparar advisory público (CERT, vendor, investigador)", "done": False},
        {"id": 8, "item": "Registrar CVE si aplica (MITRE, vendor)", "done": False},
    ]


def generate(cve_id: str = "", title: str = "", description: str = "", severity: str = "high", vendor: str = "", output_dir: str = "") -> Dict[str, Any]:
    """Genera kit de divulgación."""
    cve_id = cve_id or "CVE-PENDING"
    desc = description or title or "Vulnerabilidad identificada"
    out_path = Path(output_dir) if output_dir else Path("reports")
    out_path.mkdir(parents=True, exist_ok=True)

    timeline = _timeline_template()
    cert_doc = _cert_template(cve_id, desc, severity, vendor or "[VENDOR]")
    vendor_doc = _vendor_template(cve_id, desc, severity)
    checklist = _checklist()

    files_created = []
    if output_dir:
        (out_path / f"cert_report_{cve_id.replace('-', '_')}.md").write_text(cert_doc, encoding="utf-8")
        files_created.append(str(out_path / f"cert_report_{cve_id.replace('-', '_')}.md"))
        (out_path / f"vendor_contact_{cve_id.replace('-', '_')}.md").write_text(vendor_doc, encoding="utf-8")
        files_created.append(str(out_path / f"vendor_contact_{cve_id.replace('-', '_')}.md"))
        (out_path / f"timeline_{cve_id.replace('-', '_')}.json").write_text(json.dumps(timeline, indent=2), encoding="utf-8")
        files_created.append(str(out_path / f"timeline_{cve_id.replace('-', '_')}.json"))

    return {
        "cve_id": cve_id,
        "severity": severity.upper(),
        "timestamp": datetime.utcnow().isoformat(),
        "timeline": timeline,
        "checklist": checklist,
        "cert_template_preview": cert_doc[:500] + "...",
        "vendor_template_preview": vendor_doc[:300] + "...",
        "files_created": files_created,
    }


def main():
    parser = argparse.ArgumentParser(description="Kit de divulgación responsable para zero-days")
    parser.add_argument("--cve", type=str, default="", help="CVE ID (o CVE-PENDING)")
    parser.add_argument("--title", type=str, default="", help="Título del hallazgo")
    parser.add_argument("--description", type=str, default="", help="Descripción breve")
    parser.add_argument("--severity", type=str, default="high", choices=["critical", "high", "medium", "low"])
    parser.add_argument("--vendor", type=str, default="", help="Nombre del vendor")
    parser.add_argument("--output", type=str, default="reports", help="Directorio de salida")
    parser.add_argument("--json", action="store_true", help="Salida JSON")
    args = parser.parse_args()

    result = generate(
        cve_id=args.cve,
        title=args.title,
        description=args.description,
        severity=args.severity,
        vendor=args.vendor,
        output_dir=args.output,
    )

    if args.json:
        # No incluir previews largos en JSON
        out = {k: v for k, v in result.items() if "preview" not in k}
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print(f"CVE: {result['cve_id']} | Severidad: {result['severity']}")
        print("Timeline:", result["timeline"])
        print("Checklist:", len(result["checklist"]), "items")
        if result["files_created"]:
            print("Ficheros creados:", result["files_created"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
