# Zero-day y reporte con BOFA

Por descambiado. Como encaja BOFA en la busqueda y reporte de vulnerabilidades (incluyendo zero-days) y que soporte hay para reportar y divulgar hallazgos.

---

## ¿BOFA encuentra zero-days?

**No de forma automática.** Un zero-day es una vulnerabilidad desconocida; descubrirlo es **investigación** (fuzzing, análisis de código, monitoreo de parches, etc.). Ningún framework “encuentra” zero-days por sí solo.

**Sí da soporte al flujo** en el que podrías encontrar uno:

- **Recon y descubrimiento**: flujos y scripts (web_recon, full_recon, recon/web_discover, recon/http_headers, etc.) para mapear objetivos y superficie de ataque.
- **Inteligencia de vulnerabilidades**: módulo `vulnerability` (cve_lookup, cve_export) para consultar CVE conocidos y priorizar; sirve para comparar con hallazgos propios y evitar duplicados.
- **Exploit y payloads**: scripts en `exploit` (payload_encoder, post_exploit_enum, etc.) y en `red` para pruebas y desarrollo de PoC.
- **Forense y análisis**: scripts en `forensics` (hash_calculator, etc.) para analizar muestras o artefactos.
- **Reporte de hallazgos**: módulo `reporting` con script `report_finding` para generar un **informe de hallazgo** listo para disclosure (vendor/CERT). Ver más abajo.

Con BOFA puedes **orquestar** recon, vuln intel, pruebas y explotación; el “hallazgo” del zero-day sigue siendo humano/investigación. BOFA te ayuda a **sistematizar** y **reportar** ese hallazgo.

---

## Reportar hallazgos (disclosure)

Para **reportar** vulnerabilidades (zero-day o no) de forma estándar:

1. **Script `reporting/report_finding`**  
   Genera un informe de hallazgo en Markdown y/o JSON con: título, descripción, severidad, pasos para reproducir, impacto, mitigación, referencias. Sirve como borrador para enviar a vendor o CERT.

2. **Uso típico**  
   Tras reproducir la vulnerabilidad con BOFA (o con otras herramientas), ejecutas:
   ```bash
   python3 scripts/reporting/report_finding.py --title "Título del hallazgo" --description "..." --severity high --steps "1. ... 2. ..." --output reports/finding_001.md
   ```
   O desde el engine/MCP: `execute_script("reporting", "report_finding", parameters={...})`.

3. **Responsabilidad**  
   El contenido del reporte es del investigador. BOFA solo formatea y guarda; la divulgación (coordinated disclosure, CVE, etc.) la haces tú según tu política y la del vendor.

---

## Resumen

| Pregunta | Respuesta |
|----------|-----------|
| ¿BOFA encuentra zero-days? | No automáticamente; sí da recon, vuln intel, exploit tools y flujos para apoyar la investigación. |
| ¿Podemos reportarlos con BOFA? | Sí: con el script `report_finding` generas un informe de hallazgo listo para disclosure. |
| ¿Cómo estamos? | Framework listo para orquestar pruebas y para documentar/reportar hallazgos de forma estándar. |

Para generar un reporte de hallazgo: usar el módulo `reporting` y el script `report_finding`:
```bash
python3 scripts/reporting/report_finding.py --title "Título" --description "Descripción" --severity high --steps "1. Paso 1\n2. Paso 2" --output reports/finding_001.md
```
O desde la CLI/engine/MCP: `execute_script("reporting", "report_finding", parameters={...})`. Ver [REPORTS_CONVENTION.md](REPORTS_CONVENTION.md).
