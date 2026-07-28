# BOFA Status

Autor: descambiado. Esta pagina intenta dejar claro que parte del proyecto es hoy operativa, que parte es educativa y donde esta la apuesta flagship.

---

## Resumen ejecutivo

BOFA ya no es solo una coleccion de scripts. Hoy tiene cuatro capas distintas:

| Area | Estado | Lo importante |
|------|--------|---------------|
| **Core / Runtime / Evidence** | Operativo | Runs unificados, timeline, artifacts, export firmado, verificacion offline y smoke suites. |
| **Execution Fabric v3** | Alpha ejecutable | Grants, scope, policy, JobSpecs firmados y primer worker OCI reproducible. |
| **Labs y UI educativa** | Util / educativa | Sirven para aprender, practicar y explorar, pero no son el argumento principal del proyecto. |
| **Duplicate-aware bounty** | Flagship activo | Workspaces, imports, snapshots, deltas, novelty findings, review queue y skills para priorizar tiempo manual y reducir duplicates. |

La propuesta de valor que hoy queremos reforzar es esta:

**BOFA hace que la autorizacion, los limites y la evidencia viajen con cada run, sin dar autoridad operativa a la IA.**

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

### 4. Execution fabric e IA

- Grants persistidos por sujeto, proyecto, entorno, scope, capacidades y TTL.
- JobSpecs canonicos firmados con Ed25519.
- Workers con clave fijada, imagen por digest, replay protection y recibos con hashes.
- Imagen OCI minima no-root, sin red y con catalogo inmutable de adaptadores.
- CI de imagen con ejecucion real, SBOM, provenance, escaneo y firma Cosign.
- Ollama y OpenAI-compatible locales; proveedores remotos explicitos.
- La IA planifica por defecto y cada accion ejecutable vuelve a pasar por policy.

---

## Lo que NO estamos vendiendo como si ya estuviera cerrado

### 1. Browser automation autenticada

No esta en el nucleo actual del sistema bounty.

### 2. Integracion autenticada con HackerOne

Todavia no se usa la API autenticada de HackerOne. En esta fase el modelo es `public + import first`.

### 3. Auto-reporting

BOFA no envia reportes automaticamente. El modo correcto sigue siendo copilot: sugerir, priorizar y dejar el juicio final al hunter.

### 4. Provisionador cloud

El primer contenedor OCI ya materializa el contrato y ejecuta un fixture offline,
pero esta alpha no crea infraestructura en una cuenta cloud. Los perfiles
remotos siguen desactivados hasta publicar el digest y configurar un dispatcher
con teardown real.

---

## Posicionamiento recomendado

Si alguien pregunta "que es BOFA hoy", la respuesta mas honesta y mas fuerte es:

> BOFA es un execution fabric abierto para trabajo de ciberseguridad autorizado, con memoria operativa, policy, evidencia defendible e IA sin autoridad autonoma.

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
- publicar y consumir la primera imagen OCI por digest desde GHCR
- dispatcher de un solo proveedor con teardown demostrado
- un workflow defensivo completo visible desde SotyHub

---

## Enlaces rapidos

- [Bounty Workspaces](BUG_BOUNTY_WORKSPACES.md)
- [Agent](AGENT.md)
- [Tools README](../tools/README.md)
- [Changelog](../CHANGELOG.md)
