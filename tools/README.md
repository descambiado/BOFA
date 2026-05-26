# Herramientas BOFA

## Demo: sentir BOFA rapido

Para generar un workspace bounty real sin depender de servicios externos:

```bash
python3 tools/demo_bounty_workspace.py --fresh
```

Esto crea un workspace offline con scope, URLs, disclosed reports, notas, findings,
review queue y artifacts exportados bajo `data/demo_bounty_workspace/`.

## Verificacion: saber que todo funciona

Para comprobar que el core, la CLI y las capas operativas funcionan correctamente:

```bash
python3 tools/verify_bofa.py
```

- **Modo rapido (por defecto)**: ejecuta el flujo demo y los modulos de ejemplo. Si termina con "Resultado: TODO OK", lo esencial funciona.
- **Modo completo**: `python3 tools/verify_bofa.py --full` lista modulos/scripts, valida contratos y ejecuta solo lo que sea seguro sin parametros externos.
- **Comprobar MCP (opcional)**: `python3 tools/verify_bofa.py --mcp`
- **Comprobar agente (opcional)**: `python3 tools/verify_bofa.py --agent`
- **Comprobar hardening del runtime**: `python3 tools/verify_runtime_hardening.py`
- **Comprobar el catalogo runtime y su coherencia con la UI**: `python3 tools/verify_runtime_catalog.py`
- **Comprobar el control plane**: `python3 tools/verify_control_plane.py`
- **Comprobar el sistema bounty anti-duplicados**: `python3 tools/verify_bounty_system.py`
- **Verificar un bundle offline**: `python3 tools/verify_evidence_bundle.py reports/runs/<run_id>/exports/bofa_evidence_<run_id>_<timestamp>.zip --json`

Codigo de salida: `0` = todo OK, `1` = hay fallos.

### Flujo recomendado para releases

```bash
python3 tools/verify_bofa.py
python3 tools/verify_runtime_hardening.py
python3 tools/verify_runtime_catalog.py
python3 tools/verify_control_plane.py
python3 tools/verify_bounty_system.py
python3 tools/demo_bounty_workspace.py --fresh
python3 tools/verify_evidence_bundle.py <bundle.zip> --json
```

Si estas verificaciones pasan, BOFA queda validado a nivel basico antes de mergear o taggear una release.

## Agente autonomo

```bash
python3 tools/run_agent.py https://target.com --provider ollama
python3 tools/run_agent.py https://target.com --provider openai
python3 tools/run_agent.py https://target.com --provider auto
python3 tools/run_agent.py https://target.com --provider auto --workspace-id workspace_xxx
```

Ver [docs/AGENT.md](../docs/AGENT.md).

## Self-hack runner

```bash
python3 tools/self_hack_runner.py https://yungkuoo.com --suggest
```

Si el target tiene SSL autofirmado, el flujo usa `--insecure` automaticamente.
