# Release y versión

## Versión actual: **2.8.0**

La versión está unificada en:

- `pyproject.toml` -> `version = "2.8.0"`
- `cli/bofa_cli.py` -> `VERSION = "2.8.0"`
- `README.md` -> badge y titulo v2.8.0
- `CHANGELOG.md` -> entrada `## v2.8.0`

## Ramas y GitHub

- **main**: rama principal estable; cada tag (v2.8.0, etc.) marca una release.
- **Desarrollo**: opcionalmente usar ramas `feature/...` o `develop` y hacer merge a `main` cuando esté listo para release.
- **Releases en GitHub**: tras `git push origin v2.8.0`, en GitHub ir a **Releases** -> **Draft a new release**, elegir tag `v2.8.0`, título "BOFA v2.8.0 - Operational Control Plane", y pegar la descripción del CHANGELOG (v2.8.0) para que quede bien detallado.

### Crear issues para la release (opcional)

Ideas de issues para visibilidad y actividad: "Control plane: trazabilidad end-to-end", "Runtime: cancelación cooperativa", "UI: historial táctico de runs", "Release v2.8.0 checklist". Cerrar los que queden resueltos con el commit de la release.

## Topics recomendados (GitHub)

En el repositorio: Settings -> General -> Topics. Añadir:

`cybersecurity`, `penetration-testing`, `bug-bounty`, `security-tools`, `mcp`, `llm`, `ollama`, `openai`, `claude`, `cursor`, `vulnerability-scanner`, `red-team`, `blue-team`, `forensics`, `malware-analysis`

## Commit y push (recomendado)

```bash
# Desde la raíz del repositorio
git add -A
git status   # revisar qué se sube

git commit -m "Release v2.8.0: operational control plane

- Runs unificados con timeline, steps, labs y artifacts persistentes
- Cancelación cooperativa y retry con linaje
- UI operacional para scripts, flows, labs e historial táctico"

git tag -a v2.8.0 -m "v2.8.0 operational control plane"

git push origin main
git push origin v2.8.0
```

## Próxima versión

- **Patch** (2.8.1): solo correcciones o docs sin nuevas features.
- **Minor** (2.9.0): nuevas funcionalidades compatibles (más flujos, mejor verificación, etc.).
- **Major** (3.0.0): cambios incompatibles con el core o la CLI.

Actualizar siempre `pyproject.toml`, `cli/bofa_cli.py`, `README.md` y una nueva entrada en `CHANGELOG.md` antes del tag.
