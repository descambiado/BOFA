# BOFA Bug Bounty Workspaces

BOFA v2.9.0 introduce una capa nueva para bug bounty orientada a reducir ruido y duplicates.

La idea no es "escanear mas", sino trabajar mejor:

- separar cada programa en un workspace propio
- importar scope, disclosed reports y listas de URLs/endpoints
- construir memoria operativa del target
- persistir snapshots y deltas de superficie
- detectar que cambio y que es raro
- priorizar hallazgos con mas novedad y menos riesgo de duplicado
- generar una review queue con siguiente paso manual

## Flujo recomendado

1. Crea un workspace para el programa.
2. Importa el scope.
3. Importa disclosed reports publicos o notas relevantes.
4. Importa URL lists, Burp sitemap o endpoints JS/API.
5. Lanza el analisis del workspace.
6. Revisa:
   - `What Changed`
   - `What Is Weird`
   - `Worth Manual Time`
   - `Likely Duplicate`
   - `Review Queue`
7. Ejecuta skills tacticas como `delta_recon`, `authz_matrix`, `surface_regression`, `manual_handoff` o `report_novelty_gate`.
8. Exporta la review queue si quieres una sesion corta y accionable.
9. Solo despues invierte tiempo manual profundo en la cola mas prometedora.

## Endpoints principales

- `POST /bounty/workspaces`
- `GET /bounty/workspaces`
- `GET /bounty/workspaces/{workspace_id}`
- `POST /bounty/workspaces/{workspace_id}/imports`
- `POST /bounty/workspaces/{workspace_id}/analyze`
- `GET /bounty/workspaces/{workspace_id}/graph`
- `GET /bounty/workspaces/{workspace_id}/snapshots`
- `GET /bounty/workspaces/{workspace_id}/diffs/latest`
- `GET /bounty/workspaces/{workspace_id}/findings`
- `GET /bounty/workspaces/{workspace_id}/review-queue`
- `POST /bounty/workspaces/{workspace_id}/review-queue/export`
- `GET /bounty/skills`
- `POST /bounty/workspaces/{workspace_id}/skills/{skill_key}/run`

## Skills iniciales

- `program_intel`
- `disclosed_report_graph`
- `delta_recon`
- `js_api_diff`
- `authz_matrix`
- `duplicate_risk`
- `report_novelty_gate`
- `surface_regression`
- `manual_handoff`

## Qué intenta responder BOFA

- Que cambio desde el ultimo snapshot
- Que superficie parece rara o menos trillada
- Que cosas huelen a duplicate antes de perder tiempo
- Donde conviene invertir testing manual de mayor calidad
- Cual es el siguiente paso manual mas razonable por hipotesis

## Limites de esta version

- Sin API autenticada de HackerOne
- Sin crawling autenticado de navegador
- Sin envio automatico de reportes
- Web/API first; otros verticales quedan para fases posteriores
