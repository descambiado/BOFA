# BOFA MCP Server

Servidor **Model Context Protocol (MCP)** que expone las capacidades del core de BOFA a **cualquier cliente MCP**: Cursor, Claude Desktop, o cualquier herramienta que hable el protocolo MCP. No añade IA ni LLM al framework; solo actúa como puente para que un agente de IA pueda listar y ejecutar scripts y flujos BOFA. **BOFA se puede usar por completo en local sin MCP** (CLI `./bofa.sh`, agente `tools/run_agent.py`, flujos); MCP es opcional para integrar con asistentes de IA.

## Instalación

```bash
# Desde la raíz del proyecto
pip install .[mcp]
# o
pip install mcp
```

## Ejecución

Desde la raíz del proyecto (para que los imports `core` y `flows` funcionen):

```bash
python3 mcp/bofa_mcp.py
```

El servidor usa transporte **stdio** por defecto (espera que un cliente MCP lo invoque como subproceso).

## Herramientas expuestas (Tools)

| Tool | Descripción |
|------|--------------|
| `bofa_list_modules` | Lista los módulos disponibles (categorías de scripts). |
| `bofa_list_scripts` | Lista scripts; opcionalmente filtrado por `module_name`. |
| `bofa_script_info` | Devuelve descripción y parámetros de un script. |
| `bofa_execute_script` | Ejecuta un script con parámetros opcionales (JSON). |
| `bofa_list_flows` | Lista los flujos predefinidos. |
| `bofa_run_flow` | Ejecuta un flujo con un target dado. |

## Integración con clientes MCP

- **Cursor**: Ver [docs/MCP_CURSOR_INTEGRATION.md](../docs/MCP_CURSOR_INTEGRATION.md) para configurar `.cursor/mcp.json`.
- **Claude Desktop**: Añadir el servidor BOFA en la config MCP de Claude (stdio, command `python3`, args `ruta/a/BOFA/mcp/bofa_mcp.py`, cwd la raíz de BOFA).
- **Otros clientes**: Cualquier cliente que soporte MCP sobre stdio puede invocar `python3 mcp/bofa_mcp.py` con cwd en la raíz del proyecto.

## Consideraciones de seguridad

- El servidor MCP permite ejecutar scripts BOFA desde el agente de IA. Úsalo solo en entornos controlados y con autorización.
- No expone autenticación; el control de acceso depende del cliente y del entorno donde se ejecute BOFA.
