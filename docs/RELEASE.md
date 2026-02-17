# Release y versión

## Versión actual: **2.6.0**

La versión está unificada en:

- `pyproject.toml` -> `version = "2.6.0"`
- `cli/bofa_cli.py` -> `VERSION = "2.6.0"`
- `README.md` -> badge y titulo v2.6.0
- `CHANGELOG.md` -> entrada `## v2.6.0`

## Ramas y GitHub

- **main**: rama principal estable; cada tag (v2.6.0, etc.) marca una release.
- **Desarrollo**: opcionalmente usar ramas `feature/...` o `develop` y hacer merge a `main` cuando esté listo para release.
- **Releases en GitHub**: tras `git push origin v2.6.0`, en GitHub ir a **Releases** -> **Draft a new release**, elegir tag `v2.6.0`, título "BOFA v2.6.0 - Agente autónomo con LLM", y pegar la descripción del CHANGELOG (resumen v2.6.0) para que quede bien detallado.

## Topics recomendados (GitHub)

En el repositorio: Settings -> General -> Topics. Añadir:

`cybersecurity`, `penetration-testing`, `bug-bounty`, `security-tools`, `mcp`, `llm`, `ollama`, `openai`, `claude`, `cursor`, `vulnerability-scanner`, `red-team`, `blue-team`, `forensics`, `malware-analysis`

## Commit y push (recomendado)

```bash
# Desde la raíz del repositorio
git add -A
git status   # revisar qué se sube

git commit -m "Release v2.6.0: Agente autónomo, SSL insecure, docs unificados

- agents/: security_agent (Observe-Think-Act), llm_providers (Ollama/OpenAI/Anthropic)
- tools/run_agent.py, tools/self_hack_runner.py
- --insecure en scripts web/recon para SSL autofirmado
- bug_bounty_full_chain: insecure, limit 10, flow_report_aggregator en reports/
- docs/AGENT.md, DOCUMENTATION_INDEX, STATUS, README actualizados
- Números: 96 scripts, 20 módulos, 25 flujos"

git tag -a v2.6.0 -m "v2.6.0 Agente autónomo con LLM, bug bounty full chain"

git push origin main
git push origin v2.6.0
```

## Próxima versión

- **Patch** (2.6.1): solo correcciones o docs sin nuevas features.
- **Minor** (2.7.0): nuevas funcionalidades compatibles (más flujos, mejor verificación, etc.).
- **Major** (3.0.0): cambios incompatibles con el core o la CLI.

Actualizar siempre `pyproject.toml`, `cli/bofa_cli.py`, `README.md` y una nueva entrada en `CHANGELOG.md` antes del tag.
