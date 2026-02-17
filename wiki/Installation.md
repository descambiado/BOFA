# Instalación

Cómo instalar y ejecutar BOFA en local (sin Cursor ni MCP).

---

## Requisitos

- **Python 3.8+**
- Git

---

## Opción 1: Local (recomendado para CLI y agente)

```bash
git clone https://github.com/descambiado/BOFA
cd BOFA
pip install -r requirements.txt
./bofa.sh
```

Con esto puedes:

- Usar el **menú CLI** (módulos, scripts, flujos).
- Ejecutar el **agente autónomo**: `python3 tools/run_agent.py https://target.com --provider ollama`
- Ejecutar flujos desde la opción **F** del menú o con el flow runner.

---

## Opción 2: Con MCP (opcional)

Para usar BOFA desde **Cursor**, **Claude Desktop** o cualquier cliente MCP:

```bash
pip install .[mcp]
python3 mcp/bofa_mcp.py   # el cliente MCP lo invoca como subproceso
```

Configura el cliente MCP con: comando `python3`, argumentos `ruta/a/BOFA/mcp/bofa_mcp.py`, cwd = raíz de BOFA. Ver [README del servidor MCP](https://github.com/descambiado/BOFA/blob/main/mcp/README.md) y [Integración MCP con Cursor](https://github.com/descambiado/BOFA/blob/main/docs/MCP_CURSOR_INTEGRATION.md).

---

## Opción 3: Docker (web UI y API)

```bash
git clone https://github.com/descambiado/BOFA
cd BOFA
docker-compose up --build
```

- Interfaz web: http://localhost:3000  
- API: http://localhost:8000/docs  

---

## Verificar que todo funciona

```bash
python3 tools/verify_bofa.py        # comprobación rápida
python3 tools/verify_bofa.py --full # todos los scripts
python3 tools/verify_bofa.py --mcp  # servidor MCP
python3 tools/verify_bofa.py --agent # agente autónomo
```

Resultado esperado: **TODO OK**.

---

[← Home](Home)
