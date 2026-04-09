# Herramientas BOFA

## Verificación: saber que todo funciona

Para comprobar que el core, la CLI y los scripts funcionan correctamente:

```bash
# Desde la raíz del proyecto
python3 tools/verify_bofa.py
```

- **Modo rápido (por defecto)**: Ejecuta el flujo demo y los módulos de ejemplo. Si termina con "Resultado: TODO OK", lo esencial funciona.
- **Modo completo**: `python3 tools/verify_bofa.py --full` — lista todos los módulos/scripts, valida y ejecuta los que aceptan parámetros vacíos o tienen parámetros seguros. Los que necesitan parámetros no se ejecutan (se marcan como "Necesitan parámetros"). Algunos se omiten por ser de larga duración o con dependencias de entorno (no cuentan como fallo).
- **Comprobar MCP (opcional)**: `python3 tools/verify_bofa.py --mcp` — además del modo rápido, comprueba que las herramientas MCP responden si tienes instalado `pip install .[mcp]`. Si no tienes MCP instalado, se marca como "SKIP" y no cuenta como fallo.
- **Comprobar agente (opcional)**: `python3 tools/verify_bofa.py --agent` — verifica que el módulo del agente autónomo se importa correctamente (sin ejecutar LLM).
- **Comprobar hardening del runtime**: `python3 tools/verify_runtime_hardening.py` — valida cancelación de cola, compatibilidad legacy de estados/historial, drenaje seguro de flows y preservación del timeout real en el engine.
- **Comprobar el control plane**: `python3 tools/verify_control_plane.py` — valida persistencia de runs, steps, labs, timeline, artifacts, filtros de listado, retry lineage y mezcla de historial legacy.

Código de salida: 0 = todo OK, 1 = hay fallos (revisar la salida).

### Flujo recomendado para releases del runtime

```bash
python3 tools/verify_bofa.py
python3 tools/verify_runtime_hardening.py
python3 tools/verify_control_plane.py
```

Si los tres terminan en OK, BOFA queda validado a nivel básico antes de mergear o taggear una release.

## Agente autónomo

Ejecuta el agente que razona con un LLM y continúa hasta encontrar vulnerabilidades:

```bash
python3 tools/run_agent.py https://target.com --provider ollama   # Local (Ollama)
python3 tools/run_agent.py https://target.com --provider openai  # OpenAI API
python3 tools/run_agent.py https://target.com --provider auto    # Auto-detecta
```

Ver [docs/AGENT.md](../docs/AGENT.md).

## Self-hack runner

Ejecuta el flujo bug bounty contra tu propia infraestructura (sin LLM; flujo fijo):

```bash
python3 tools/self_hack_runner.py https://yungkuoo.com --suggest
```

Si el target tiene SSL autofirmado, el flujo usa `--insecure` automáticamente.
