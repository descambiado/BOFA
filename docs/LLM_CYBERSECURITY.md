# BOFA + LLM para Ciberseguridad

Por descambiado. Como usar un LLM (Cursor, Claude u otro cliente MCP) con BOFA para ciberseguridad: arsenal de herramientas, flujos orquestables y decision autonoma.

---

## Cómo funciona

1. **Cliente MCP** (Cursor, Claude Desktop, etc.) se conecta al **servidor MCP de BOFA** por stdio.
2. El **LLM** ve las herramientas BOFA: listar módulos/scripts, ver info de un script, ejecutar script, listar flujos, ejecutar flujo.
3. El **usuario** escribe en lenguaje natural (ej. "haz un reconocimiento web de example.com" o "busca vulnerabilidades CVE en web_framework").
4. El **LLM** decide qué herramientas usar, con qué parámetros, y ejecuta (bofa_list_flows → bofa_run_flow, o bofa_list_scripts → bofa_script_info → bofa_execute_script).
5. **Resultado**: pruebas de seguridad orquestadas por la IA sin escribir comandos a mano.

BOFA no incluye el LLM; el LLM es el cliente. BOFA aporta el **arsenal** y los **flujos**; el LLM aporta la **decisión** y el **lenguaje natural**.

---

## Capacidades para el LLM

| Capacidad | Cómo la da BOFA |
|-----------|------------------|
| **Automatización guiada por IA** | El LLM elige scripts y flujos según el objetivo del usuario; ejecuta y resume resultados. |
| **Arsenal de herramientas** | 65+ scripts en 18 módulos (recon, exploit, red, blue, purple, vulnerability, osint, forensics, etc.). |
| **Arquitectura multi-dominio** | Módulos = dominios (recon, vulnerability, exploit, blue…). El LLM puede actuar como “agente de recon”, “agente de vulnerabilidades”, etc. usando solo esos módulos. |
| **Inteligencia de vulnerabilidades** | Módulo `vulnerability`: `cve_lookup`, `cve_export` (base local CVE). El LLM puede consultar y filtrar por producto/severidad. |
| **Testing web** | Scripts recon/web_discover, recon/http_headers, web/robots_txt, web/security_headers_analyzer, web/path_scanner; flujos web_recon, full_recon, web_security_review, bug_bounty_web_light, bug_bounty_web_full, pentest_basic. |
| **Combinar y encadenar** | bofa_capabilities(), bofa_suggest_tools(goal); flujos que inyectan mismo target; scripts con salida JSON para parsear y pasar a report_finding. Ver ORCHESTRATION_AND_CHAINING.md. |
| **Análisis y explotación** | Scripts en `exploit`, `red`, `forensics`; flujos `pentest_basic`, `recon`. |

---

## Herramientas MCP (que puede hacer el LLM)

| Herramienta | Uso tipico para el LLM |
|-------------|-------------------------|
| `bofa_capabilities` | Ver que se puede combinar: flows (when/combine_with), scripts_with_json, chain_examples. Llamar primero para descubrir y encadenar. |
| `bofa_suggest_tools(goal)` | Dado un objetivo en texto (ej. "recon web example.com", "vulnerabilidades web_framework"), obtener suggested_flows y suggested_scripts con razon. |
| `bofa_list_modules` | Ver categorias (recon, web, exploit, vulnerability, blue...) para elegir dominio. |
| `bofa_list_scripts` | Ver scripts de un modulo o de todos; elegir script para una tarea. |
| `bofa_script_info` | Ver descripcion y parametros de un script antes de ejecutarlo. |
| `bofa_execute_script` | Ejecutar script con parameters_json. Incluir "json": true donde aplique para stdout parseable y encadenar. |
| `bofa_list_flows` | Ver flujos (demo, recon, web_recon, full_recon, web_security_review, bug_bounty_web_light, bug_bounty_web_full, pentest_basic, vulnerability_scan, vuln_triage, blue). |
| `bofa_run_flow` | Ejecutar flujo con target; resultado incluye steps[].stdout_preview (puede ser JSON para extraer y usar). |

El LLM debe: 1) opcionalmente bofa_capabilities() o bofa_suggest_tools(goal) para saber que combinar, 2) listar modulos o flujos segun la peticion, 3) leer script_info si hace falta, 4) ejecutar script o flujo con parametros correctos, 5) parsear stdout cuando sea JSON y usarlo en el siguiente paso o en report_finding, 6) devolver al usuario un resumen. Ver [ORCHESTRATION_AND_CHAINING.md](ORCHESTRATION_AND_CHAINING.md) para ejemplos de encadenamiento.

---

## Dominios / “Agentes” sugeridos

El LLM puede especializarse por dominio usando solo ciertos módulos y flujos:

| Dominio | Modulos | Flujos | Ejemplo de peticion |
|---------|---------|--------|----------------------|
| **Recon** | recon | recon, web_recon, full_recon | "Reconocimiento web de example.com" -> bofa_run_flow("web_recon", "https://example.com"); "Recon completo (web + CVE)" -> bofa_run_flow("full_recon", "https://example.com") |
| **Vulnerabilidades** | vulnerability | vulnerability_scan, vuln_triage | "Lista CVE de web_framework" -> bofa_run_flow("vuln_triage", "web_framework"); o cve_lookup con product |
| **Pentest basico** | recon, exploit | pentest_basic | "Pentest basico de https://example.com" -> bofa_run_flow("pentest_basic", "https://example.com") |
| **Bug bounty web** | recon, web, vulnerability, reporting | web_recon, full_recon, web_security_review, bug_bounty_web_light, bug_bounty_web_full, vuln_triage, bug_bounty_web_params, bug_bounty_web_diff | "Mapea superficie de ataque de https://example.com" -> bofa_run_flow("web_security_review", "https://example.com"); "Triaje de CVE para web_framework" -> bofa_run_flow("vuln_triage", "web_framework") |
| **Blue team** | blue | blue, blue_daily, blue_risk_assessment | "Simula alertas SIEM" -> bofa_run_flow("blue", "dummy"); "Evalua el riesgo de /var/log/auth.log" -> bofa_run_flow("blue_risk_assessment", "/var/log/auth.log") |
| **Exploit / payloads** | exploit | - | "Codifica este payload en base64" -> bofa_execute_script("exploit", "payload_encoder", parameters_json='{"payload":"...", "encoding":"base64"}') |

No hay agentes separados en el código; el LLM decide qué herramientas usar en función del dominio que el usuario pida.

---

## Configuración rápida (Cursor)

1. `pip install .[mcp]`
2. Copiar `.cursor/mcp.json.example` a `.cursor/mcp.json` y poner la ruta absoluta a BOFA en `args` y `cwd`.
3. Reiniciar Cursor; en el chat, pedir por ejemplo:  
   "Usa las herramientas BOFA: lista los flujos y ejecuta el flujo web_recon con target https://example.com."

Ver [MCP_CURSOR_INTEGRATION.md](MCP_CURSOR_INTEGRATION.md) para más detalle.

---

## Ejemplo de flujo completo (usuario → LLM → BOFA)

- **Usuario**: "Quiero un reconocimiento web de mi sitio https://misitio.com y que me digas si hay CVE conocidos para componentes web."
- **LLM** (internamente):  
  1. `bofa_run_flow("web_recon", "https://misitio.com")` → obtiene informe de descubrimiento web.  
  2. `bofa_execute_script("vulnerability", "cve_lookup", parameters_json='{"product":"web_framework","limit":10}')` → obtiene CVE de ejemplo.  
  3. Responde al usuario con un resumen del informe y de los CVE, y recomendaciones en lenguaje natural.

Así la **IA funciona para ciberseguridad**: el LLM orquesta BOFA y devuelve análisis y pasos siguientes.
