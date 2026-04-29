# BOFA Status

Autor: descambiado. Esta pagina intenta dejar claro que parte del proyecto es hoy operativa, que parte es educativa y donde esta la apuesta flagship.

---

## Resumen ejecutivo

BOFA ya no es solo una coleccion de scripts. Hoy tiene tres capas distintas:

| Area | Estado | Lo importante |
|------|--------|---------------|
| **Core / Runtime / Evidence** | Operativo | Runs unificados, timeline, artifacts, export firmado, verificacion offline y smoke suites. |
| **Labs y UI educativa** | Util / educativa | Sirven para aprender, practicar y explorar, pero no son el argumento principal del proyecto. |
| **Duplicate-aware bounty** | Flagship activo | Workspaces, imports, snapshots, deltas, novelty findings, review queue y skills para priorizar tiempo manual y reducir duplicates. |

La propuesta de valor que hoy queremos reforzar es esta:

**BOFA ayuda a hunters web/API a ver que cambio, que es raro y que tiene menos riesgo de ser duplicate.**

---

## Lo que esta realmente fuerte

### 1. Control plane y runtime

- Runs, steps, labs, events y artifacts estan persistidos.
- Scripts, flows y labs comparten trazabilidad por `run_id`.
- Hay cancelacion operativa, retry con linaje y evidencia por run.
- Los exports de evidencia se firman y se pueden verificar offline.

### 2. Bounty workspaces

- Workspaces por programa o campana.
- Imports manuales de scope, disclosed reports, URL lists, Burp sitemaps, JS endpoints y notas.
- Target graph local-first.
- Findings con `novelty_score` y `duplicate_risk_score`.
- Skills orientadas a inteligencia de programa, delta recon, duplicate risk y handoff manual.

### 3. Calidad operativa

- Smoke suites para runtime hardening, control plane y bounty system.
- `tsc` y `build` pasan en frontend.
- Hay CI visible en GitHub Actions.

---

## Lo que NO estamos vendiendo como si ya estuviera cerrado

### 1. Browser automation autenticada

No esta en el nucleo actual del sistema bounty.

### 2. Integracion autenticada con HackerOne

Todavia no se usa la API autenticada de HackerOne. En esta fase el modelo es `public + import first`.

### 3. Auto-reporting

BOFA no envia reportes automaticamente. El modo correcto sigue siendo copilot: sugerir, priorizar y dejar el juicio final al hunter.

---

## Posicionamiento recomendado

Si alguien pregunta "que es BOFA hoy", la respuesta mas honesta y mas fuerte es:

> BOFA es una plataforma local-first para hunting web/API con memoria operativa, evidencia defendible y una capa duplicate-aware para decidir mejor donde gastar tiempo manual.

Todo lo educativo sigue siendo valioso, pero no deberia eclipsar la historia principal.

---

## Donde vamos

Los siguientes hitos deben seguir esta regla:

1. Priorizar edge real para bug bounty web/API individual.
2. Reducir duplicates y mejorar el tiempo manual antes que ampliar catalogo por catalogo.
3. Mantener evidencia, reproducibilidad y verificacion como parte del producto, no como detalle secundario.

Las lineas de trabajo mas valiosas ahora mismo son:

- snapshots y deltas mas finos
- clustering por hipotesis
- review queue mejor
- skills honestas y utiles
- mejor importacion de intelligence publica

---

## Enlaces rapidos

- [Bounty Workspaces](BUG_BOUNTY_WORKSPACES.md)
- [Agent](AGENT.md)
- [Tools README](../tools/README.md)
- [Changelog](../CHANGELOG.md)
