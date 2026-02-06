# BOFA MCP Server

Servidor **Model Context Protocol (MCP)** que expone las capacidades del core de BOFA a clientes compatibles (Cursor, Claude Desktop, etc.). No añade IA ni LLM al framework; solo actúa como puente para que un agente de IA pueda listar y ejecutar scripts y flujos BOFA.

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

## Integración con Cursor

Ver [docs/MCP_CURSOR_INTEGRATION.md](../docs/MCP_CURSOR_INTEGRATION.md) para configurar `.cursor/mcp.json` y usar BOFA desde Cursor.

## Consideraciones de seguridad

- El servidor MCP permite ejecutar scripts BOFA desde el agente de IA. Úsalo solo en entornos controlados y con autorización.
- No expone autenticación; el control de acceso depende del cliente y del entorno donde se ejecute BOFA.
