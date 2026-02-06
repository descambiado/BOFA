# Orquestacion y encadenamiento

Por descambiado. Como combinar flujos y scripts para que la IA (o un usuario) pueda extraer resultados y usarlos en pasos siguientes. Todo accesible y encadenable.

---

## Objetivo

Que un mismo target (URL, producto, dominio) recorra varias herramientas en secuencia y que la salida de una pueda alimentar la siguiente o el informe final. La IA (cliente MCP) puede:

1. Descubrir que puede combinar: bofa_capabilities(), bofa_suggest_tools(goal).
2. Ejecutar flujos que ya encadenan pasos: full_recon(URL), vuln_triage(product).
3. Ejecutar scripts sueltos y parsear stdout (JSON) para pasarlo al siguiente o a report_finding.

---

## Herramientas MCP para orquestar

| Herramienta | Uso para combinar |
|-------------|-------------------|
| bofa_capabilities() | Ver flows con when/combine_with, scripts_with_json, chain_examples. Llamar primero para saber que encadenar. |
| bofa_suggest_tools(goal) | Dado un objetivo en texto (ej. "recon web example.com", "vulnerabilidades web_framework"), devuelve suggested_flows y suggested_scripts con razon. |
| bofa_list_flows() | Lista flujos; luego bofa_run_flow(flow_id, target). |
| bofa_list_scripts(module) | Lista scripts de un modulo; luego bofa_script_info y bofa_execute_script. |
| bofa_execute_script(module, script, parameters_json) | Ejecutar script. Incluir "json": true donde aplique para stdout parseable. |
| bofa_run_flow(flow_id, target) | Ejecutar flujo; resultado incluye steps[].stdout_preview que puede ser JSON. |

---

## Flujos que ya encadenan

| Flujo | Target | Pasos (mismo target inyectado) |
|-------|--------|--------------------------------|
| full_recon | URL | web_discover(url), http_headers(url, json), robots_txt(url, json), cve_lookup(limit 5) |
| web_security_review | URL | http_headers(url, json), security_headers_analyzer(url, json), robots_txt(url, json) |
| web_recon | URL | web_discover(url) |
| vuln_triage | producto | cve_lookup(product=target, limit 15), cve_export(output=reports/vuln_triage_{target}.json, product=target) |
| vulnerability_scan | (no usa target) | cve_lookup(limit 10), cve_export(output cve_export.json) |
| pentest_basic | URL | pasos de pentest basico |
| recon | dominio | pasos de recon |
| blue | dummy | simulacion blue team |

Combinar: ejecutar full_recon(URL) y luego vuln_triage(producto) si quieres CVE filtrados por producto. La IA puede extraer "producto" del contexto (ej. web_framework) o del usuario.

---

## Scripts con salida JSON (encadenables)

Estos scripts aceptan parametro json o devuelven JSON por defecto; la IA puede parsear stdout y usar campos en el siguiente paso:

| Modulo/script | Parametro JSON | Uso en cadena |
|---------------|----------------|----------------|
| recon/http_headers | json: true | Cabeceras de una URL; pasar misma URL a security_headers_analyzer, robots_txt o report_finding. |
| web/security_headers_analyzer | json: true | Analisis de HSTS, CSP, X-Frame-Options, Referrer-Policy y cookies; ideal para resumen de seguridad web o alimentar report_finding. |
| web/robots_txt | json: true | Contenido robots.txt; combinar con http_headers y security_headers_analyzer para mismo dominio. |
| blue/log_guardian | json: true | Resumen de detecciones en un log (detections, threat_summary, suspicious_ips); se puede pasar a report_finding o a un flujo blue. |
| vulnerability/cve_lookup | (salida JSON por defecto) | Entradas CVE; filtrar por product/severidad; pasar IDs o resumen a report_finding. |
| vulnerability/cve_export | output: path | Exporta a fichero; path puede ser reports/ para agrupar. |
| reporting/report_finding | title, description, severity, steps, output | Genera informe de hallazgo; recibir titulo/descripcion de cve_lookup o de analisis previo. |
| forensics/hash_calculator | (salida texto/hex) | Hash de cadena o fichero; usar en reporte o comparacion. |

Ejemplo de cadena (IA): 1) bofa_run_flow("full_recon", "https://example.com") -> 2) parsear steps[].stdout_preview del paso cve_lookup -> 3) bofa_execute_script("reporting", "report_finding", parameters_json='{"title":"CVE summary", "description": "...", "severity":"info", "steps":"...", "output":"reports/finding.md"}').

---

## Ejemplos de combinacion para la IA

1. **Recon web + CVE por producto**  
   bofa_run_flow("full_recon", "https://example.com"); bofa_run_flow("vuln_triage", "web_framework"). Resumir report_path y contenido de reports/vuln_triage_web_framework.json.

2. **Solo headers y robots de una URL**  
   bofa_execute_script("recon", "http_headers", parameters_json='{"url":"https://example.com","json":true}'); bofa_execute_script("web", "robots_txt", parameters_json='{"url":"https://example.com","json":true}').

3. **CVE y reporte de hallazgo**  
   bofa_execute_script("vulnerability", "cve_lookup", parameters_json='{"product":"web_framework","limit":5}'); parsear stdout; bofa_execute_script("reporting", "report_finding", parameters_json='{"title":"CVE web_framework", "description": "<resumen>", "severity":"high", "steps":"1. cve_lookup 2. revisar", "output":"reports/cve_finding.md"}').

4. **Sugerencia por objetivo**  
   bofa_suggest_tools("recon web y vulnerabilidades para api_gateway") -> suggested_flows: full_recon, vuln_triage; suggested_scripts: recon/http_headers, web/robots_txt, vulnerability/cve_lookup, reporting/report_finding.

---

## Convenciones

- Mismo target: en flujos, {target} se inyecta en todos los pasos; usar la misma URL o producto en scripts sueltos para mantener coherencia.
- Salida parseable: pedir json: true o usar scripts que devuelven JSON para poder extraer campos y pasarlos al siguiente script o a report_finding.
- Informes: los flujos escriben en reports/ (flow_*.md); report_finding escribe donde indique output. La IA puede leer report_path y resumir al usuario.

Todo esto esta disponible via MCP; la IA que tenga conectado BOFA puede listar, sugerir, ejecutar y encadenar sin pasos manuales.
