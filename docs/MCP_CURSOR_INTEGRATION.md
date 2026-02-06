# Integración BOFA MCP con Cursor

BOFA puede usarse como backend de herramientas desde **Cursor** (y otros clientes MCP) mediante un servidor MCP que expone listar módulos/scripts, ejecutar scripts y flujos. **Para usar un LLM con BOFA en ciberseguridad** (decisión autónoma, flujos orquestables), ver [LLM_CYBERSECURITY.md](LLM_CYBERSECURITY.md).

## Requisitos

- Python 3.8+ con el proyecto BOFA clonado.
- Dependencia opcional MCP instalada: `pip install .[mcp]` o `pip install mcp`.

## Configuración en Cursor

1. **Crear o editar** el archivo de configuración MCP de Cursor:
   - En el proyecto: **`.cursor/mcp.json`**
   - Puedes copiar `.cursor/mcp.json.example` y sustituir `ABSOLUTE_PATH_TO_BOFA` por la ruta real.
   - O configurar globalmente según tu instalación de Cursor (consulta la documentación de Cursor para MCP).

2. **Añadir el servidor BOFA.** Sustituye `ABSOLUTE_PATH_TO_BOFA` por la ruta absoluta a la raíz del repositorio BOFA (donde está `pyproject.toml`, `core/`, `mcp/`, etc.):

```json
{
  "mcpServers": {
    "bofa": {
      "command": "python3",
      "args": [
        "ABSOLUTE_PATH_TO_BOFA/mcp/bofa_mcp.py"
      ],
      "cwd": "ABSOLUTE_PATH_TO_BOFA",
      "env": {},
      "disabled": false
    }
  }
}
```

Ejemplo en Linux/macOS si BOFA está en `/home/user/BOFA`:

```json
{
  "mcpServers": {
    "bofa": {
      "command": "python3",
      "args": [
        "/home/user/BOFA/mcp/bofa_mcp.py"
      ],
      "cwd": "/home/user/BOFA",
      "disabled": false
    }
  }
}
```

3. **Reiniciar Cursor** o recargar la configuración MCP para que detecte el servidor.

4. En un chat, puedes pedir al asistente que use las herramientas BOFA, por ejemplo:
   - "Lista los módulos de BOFA con bofa_list_modules."
   - "Ejecuta el script X del módulo Y con bofa_execute_script y parámetros Z."
   - "Lista los flujos con bofa_list_flows y ejecuta el flujo recon con target example.com."

## Herramientas disponibles

| Herramienta | Uso típico |
|-------------|------------|
| `bofa_list_modules` | Ver categorías de scripts (red, exploit, recon, etc.). |
| `bofa_list_scripts` | Ver scripts; opcionalmente por módulo. |
| `bofa_script_info` | Ver descripción y parámetros de un script antes de ejecutarlo. |
| `bofa_execute_script` | Ejecutar un script (parámetros en JSON, opcional). |
| `bofa_list_flows` | Ver flujos predefinidos (demo, recon, blue, etc.). |
| `bofa_run_flow` | Ejecutar un flujo con un target (ej. recon sobre un dominio). |

## Parámetros de `bofa_execute_script`

- `module_name` (requerido): nombre del módulo (ej. `recon`, `red`).
- `script_name` (requerido): nombre del script (sin `.py`).
- `parameters_json` (opcional): objeto JSON como string, ej. `'{"target": "example.com", "port": 80}'`.
- `timeout_seconds` (opcional): timeout en segundos.

## Solución de problemas

- **"ModuleNotFoundError: No module named 'core'"**: El servidor debe ejecutarse con `cwd` en la raíz de BOFA y la raíz debe estar en `sys.path`; `bofa_mcp.py` ya añade la raíz. Asegúrate de que `cwd` en la config apunte a la raíz del proyecto.
- **"No module named 'mcp'"**: Instala la dependencia con `pip install mcp` o `pip install .[mcp]` en el mismo entorno que use Cursor para ejecutar el script.
- **Herramientas no aparecen**: Comprueba que el path en `args` sea absoluto y que `python3` sea el intérprete correcto (o usa `uv run` si tu proyecto lo usa).

## Referencias

- [Model Context Protocol](https://modelcontextprotocol.io/)
- [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)
- [BOFA MCP README](../mcp/README.md)
