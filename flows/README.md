# BOFA Flows

Ejecución de secuencias predefinidas de scripts con un target común e informe unificado.

## Uso

- **Desde la CLI**: Opción `F` (Flujos) en el menú principal. Elige flujo, introduce target y se ejecuta la secuencia; el informe se guarda en `reports/`.
- **Desde código**:
  ```python
  from flows.flow_runner import list_flows, run_flow

  flows = list_flows()
  result = run_flow("demo", "test.com")
  print(result["report_path"])
  ```

## Definición de flujos

Los flujos se definen en YAML en `config/flows/`. Disponibles: `demo`, `recon`, `blue`, `web_recon`, `pentest_basic`, `vulnerability_scan`, `full_recon`. Orquestables por un LLM vía MCP. Ejemplo:

```yaml
name: recon
description: "Reconocimiento web sobre un target"
steps:
  - module: recon
    script: web_discover
    parameters:
      url: "{target}"
  - module: examples
    script: example_params
    parameters:
      target: "{target}"
      timeout: 10
      verbose: true
```

El placeholder `{target}` se sustituye por el valor proporcionado al ejecutar el flujo.

## Dependencias

Usa exclusivamente el core (`get_engine()`). No modifica el core.
