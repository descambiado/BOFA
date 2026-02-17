# Release y versión

## Versión actual: **2.7.0**

La versión está unificada en:

- `pyproject.toml` -> `version = "2.7.0"`
- `cli/bofa_cli.py` -> `VERSION = "2.7.0"`
- `README.md` -> badge y titulo v2.7.0
- `CHANGELOG.md` -> entrada `## v2.7.0`

## Ramas y GitHub

- **main**: rama principal estable; cada tag (v2.7.0, etc.) marca una release.
- **Desarrollo**: opcionalmente usar ramas `feature/...` o `develop` y hacer merge a `main` cuando esté listo para release.
- **Releases en GitHub**: tras `git push origin v2.7.0`, en GitHub ir a **Releases** -> **Draft a new release**, elegir tag `v2.7.0`, título "BOFA v2.7.0 - CLI navegable, mensaje MCP unificado", y pegar la descripción del CHANGELOG (v2.7.0) para que quede bien detallado.

### Crear issues para la release (opcional)

Ideas de issues para visibilidad y actividad: "Docs: Unificar mensaje MCP", "CLI: Opción H (Ayuda)", "CLI: Opción L (todos los módulos)", "Release v2.7.0 checklist". Cerrar los que queden resueltos con el commit de la release.

## Topics recomendados (GitHub)

En el repositorio: Settings -> General -> Topics. Añadir:

`cybersecurity`, `penetration-testing`, `bug-bounty`, `security-tools`, `mcp`, `llm`, `ollama`, `openai`, `claude`, `cursor`, `vulnerability-scanner`, `red-team`, `blue-team`, `forensics`, `malware-analysis`

## Commit y push (recomendado)

```bash
# Desde la raíz del repositorio
git add -A
git status   # revisar qué se sube

git commit -m "Release v2.7.0: CLI navegable, mensaje MCP unificado

- Docs: MCP para cualquier cliente (Cursor como ejemplo), Cómo usar BOFA, frase impacto
- CLI: menú dinámico (engine.list_modules), opción L (todos módulos), H (ayuda), banner hint
- CONTRIBUTING: enlace Good first issues"

git tag -a v2.7.0 -m "v2.7.0 CLI navegable, mensaje MCP unificado"

git push origin main
git push origin v2.7.0
```

## Próxima versión

- **Patch** (2.7.1): solo correcciones o docs sin nuevas features.
- **Minor** (2.8.0): nuevas funcionalidades compatibles (más flujos, mejor verificación, etc.).
- **Major** (3.0.0): cambios incompatibles con el core o la CLI.

Actualizar siempre `pyproject.toml`, `cli/bofa_cli.py`, `README.md` y una nueva entrada en `CHANGELOG.md` antes del tag.
