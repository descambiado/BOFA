# Agente de Seguridad Autónomo BOFA

El agente razona, explora opciones y continúa hasta encontrar vulnerabilidades. Usa un loop **Observe-Think-Act** con un LLM (local o por API).

## Requisitos

- **Ollama** (local): `ollama serve` + `ollama pull llama3.2`
- **OpenAI**: `export OPENAI_API_KEY=sk-...`
- **Anthropic**: `export ANTHROPIC_API_KEY=sk-ant-...`

## Uso

```bash
# Con Ollama (local)
ollama pull llama3.2
ollama serve &
python3 tools/run_agent.py https://yungkuoo.com --provider ollama

# Con OpenAI
export OPENAI_API_KEY=sk-...
python3 tools/run_agent.py https://yungkuoo.com --provider openai

# Con Anthropic Claude
export ANTHROPIC_API_KEY=sk-ant-...
python3 tools/run_agent.py https://yungkuoo.com --provider anthropic

# Auto (usa la primera disponible: OpenAI > Anthropic > Ollama)
python3 tools/run_agent.py https://yungkuoo.com
```

## Cómo funciona

1. **Observe**: El agente recibe el contexto (hallazgos previos de param_finder, path_scanner, fuzzer, etc.).
2. **Think**: El LLM razona qué herramienta ejecutar a continuación.
3. **Act**: Ejecuta la herramienta BOFA (execute_script, run_flow, correlate).
4. **Repeat**: Hasta encontrar vulnerabilidades o alcanzar el límite de iteraciones.

## Acciones disponibles

| Acción | Descripción |
|--------|-------------|
| `execute_script` | Ejecuta un script BOFA (param_finder, path_scanner, http_param_fuzzer, etc.) |
| `run_flow` | Ejecuta un flujo completo (bug_bounty_full_chain) |
| `correlate` | Correlaciona hallazgos previos con findings_correlator |
| `done` | Termina (con success=true si encontró vulnerabilidades) |

## Criterios de éxito

- **param_finder**: Parámetros encontrados en formularios/enlaces
- **path_scanner**: Rutas sensibles (admin, login, .git) con 200/301/302
- **security_headers_analyzer**: Cabeceras faltantes (HSTS, CSP, etc.)
- **http_param_fuzzer**: Anomalías en respuestas (longitud distinta)
- **findings_correlator**: Hotspots priorizados

## Opciones

```
python3 tools/run_agent.py TARGET [--provider auto|ollama|openai|anthropic] [--max-iterations 15] [-q]
```
