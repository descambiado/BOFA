# Seguridad y reporte de vulnerabilidades en BOFA

BOFA es un framework de ciberseguridad orientado a uso **educativo y profesional autorizado**.
No debe utilizarse para actividades ilegales ni pruebas sin permiso explícito.

## Alcance

Este repositorio contiene:

- Core y CLI de BOFA.
- Scripts de recon, web, cloud, malware, blue, forense, etc.
- Flujos BOFA Flow y servidor MCP.

Si encuentras una vulnerabilidad en el propio BOFA (código, scripts, docs, labs):

## Cómo reportar vulnerabilidades

1. **No abras un issue público con detalles técnicos sensibles.**
2. Envía un correo a: `david@descambiado.com` con:
   - Descripción breve.
   - Impacto estimado.
   - Versión/commit afectado.
   - Pasos mínimos para reproducir (si es seguro compartirlos).
3. Opcional: adjunta un informe generado con `reporting/report_finding` de BOFA.

Intentaremos:

- Confirmar recepción en ~7 días.
- Evaluar el impacto y plan de corrección.
- Coordinar divulgación responsable si procede.

## Zero-days y divulgación responsable

BOFA incluye utilidades para ayudarte a **documentar** vulnerabilidades (incluyendo zero-days) de forma responsable:

- `reporting/report_finding`: genera un informe de hallazgo (Markdown/JSON).
- `reporting/zero_day_disclosure_kit`: genera plantillas para CERT/vendor, timeline sugerido y checklist.

Estas herramientas son para ayudarte a seguir buenas prácticas de disclosure, pero la responsabilidad final
de cómo y dónde divulgar recae siempre en el investigador.

## Uso responsable

- Usa BOFA solo en sistemas propios o donde tengas autorización explícita.
- Respeta leyes y regulaciones locales.
- No envíes tráfico agresivo o destructivo a servicios de terceros.

Si tienes dudas sobre el uso responsable de BOFA, abre un issue general (sin detalles técnicos sensibles)
o contacta por correo para aclararlo.

