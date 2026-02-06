# Release y versión

## Versión actual: **2.6.0**

La versión está unificada en:

- `pyproject.toml` -> `version = "2.6.0"`
- `cli/bofa_cli.py` -> `VERSION = "2.6.0"`
- `README.md` -> badge y titulo v2.6.0
- `CHANGELOG.md` -> entrada `## v2.6.0`

## Commit y push (recomendado)

```bash
# Desde la raíz del repositorio
git add -A
git status   # revisar qué se sube

git commit -m "Release v2.6.0: Core finalization, BOFA Flow, verification

- Core: script validator YAML types, module loader parameters list/dict
- Script migration: exploit, red, osint, blue, recon to --key; cross-platform fixes
- BOFA Flow: config/flows (demo, recon, blue), flow_runner, CLI option F
- Verification: tools/verify_bofa.py (quick + --full), 0 failures
- Docs: NEXT_STEPS_AND_ROADMAP, flows/README, tools/README, MODULE_CONTRACT
- Version: 2.6.0 (pyproject, CLI, README, CHANGELOG)"

git tag -a v2.6.0 -m "v2.6.0 Core finalization, BOFA Flow, verification"

git push origin main
git push origin v2.6.0
```

## Próxima versión

- **Patch** (2.6.1): solo correcciones o docs sin nuevas features.
- **Minor** (2.7.0): nuevas funcionalidades compatibles (más flujos, mejor verificación, etc.).
- **Major** (3.0.0): cambios incompatibles con el core o la CLI.

Actualizar siempre `pyproject.toml`, `cli/bofa_cli.py`, `README.md` y una nueva entrada en `CHANGELOG.md` antes del tag.
