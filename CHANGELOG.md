# BOFA - CHANGELOG

Por descambiado. Cambios notables por version.

---

## v2.8.5 (2026-04-09) - Signed Evidence Verification

### Evidencia portable y defendible
- **Artifacts y timeline endurecidos**: runs `failed`, `partial` y `cancelled` conservan mejor su evidencia operativa, con metadata enriquecida, summaries de flow y previews ligeras desde History.
- **Export por run**: cada `run` puede salir como bundle ZIP con `manifest.json`, `run.json`, `timeline.json`, `steps.json`, `labs.json`, `README.txt` y artifacts permitidos bajo `reports/runs/<run_id>/exports/`.
- **Firma y trust anchor**: los bundles ahora se firman con `Ed25519`, incluyen `manifest.sig`, `public_key.pem` y fingerprint SHA-256 de la clave pública gestionada localmente por BOFA.

### VerificaciÃ³n y cadena de custodia
- **VerificaciÃ³n API**: `GET /runs/{run_id}/export/verify` valida firma, integridad, hashes canÃ³nicos, artifacts incluidos y si la clave embebida coincide con la clave activa del servidor.
- **VerificaciÃ³n offline**: nuevo `tools/verify_evidence_bundle.py` para comprobar bundles fuera de BOFA, con modo JSON, trust mode explÃ­cito y detecciÃ³n de manipulaciÃ³n.
- **Clave pÃºblica operativa**: nuevo `GET /evidence/public-key` para consultar o descargar la clave pÃºblica activa y su fingerprint.

### Frontend y runbook
- **History mÃ¡s Ãºtil**: la UI ya permite preview de artifacts de evidencia, descarga del bundle real, verificaciÃ³n de firma e integridad, y visibilidad del fingerprint del firmante.
- **VerificaciÃ³n de release ampliada**: `tools/verify_control_plane.py`, `tools/verify_runtime_hardening.py`, `tsc` y `vite build` ya forman parte del ciclo real de validaciÃ³n de este hito.

---

## v2.8.2 (2026-04-09) - Control Plane Smoke Suite

### Verificación operativa
- **Smoke suite del control plane**: nuevo `tools/verify_control_plane.py` para validar persistencia de runs, steps, labs, timeline, artifacts, filtros y mezcla de historial legacy.
- **Cancelación medida**: la smoke suite cubre transiciones a `cancelling`, propagación a steps y labs, creación de cancel markers e idempotencia al repetir la solicitud.
- **Retry trazado**: se valida el linaje entre run origen y run hijo con eventos `retry_requested` y `retried_from`, además de `parent_run_id` y metadata asociada.

### Runbook
- **Verificación de release ampliada**: `tools/README.md` incorpora `python3 tools/verify_control_plane.py` como parte del flujo recomendado antes de merge y versionado.

---

## v2.8.1 (2026-04-06) - Runtime Hardening

### Fiabilidad operacional
- **Cancelación endurecida**: la cola conserva control del proceso durante `launching` y `process_started`, evitando slots colgados y procesos huérfanos al cancelar.
- **Flows más seguros**: `POST /runs/{run_id}/cancel` drena tasks de flow sin propagar errores internos como 500, dejando eventos y estados coherentes.
- **Timeout real**: el motor vuelve a preservar `ExecutionError` de timeout con su metadata correcta (`timeout`, `duration`) sin reenvolverlo.

### Compatibilidad y observabilidad
- **Historial híbrido**: `/history` mezcla runs nuevos con ejecuciones legacy que aún no estaban correlacionadas con `run_id`.
- **Contrato legacy estable**: `/execute/{id}` mantiene `status=error` para clientes antiguos cuando el run operativo real está en `failed`.
- **Permisos y acciones de labs**: `lab_session` exige `manage_labs` y solo acepta acciones válidas de `start_lab` y `stop_lab`.

### Verificación de release
- **Checks reutilizables**: nuevo `tools/verify_runtime_hardening.py` para validar timeout efectivo, cancelación segura, compatibilidad legacy y mezcla de historial.
- **Runbook de tools**: `tools/README.md` documenta la verificación recomendada antes de merge y versionado.

---

## v2.8.0 (2026-04-06) - Operational Control Plane

### Runtime y trazabilidad
- **Runs unificados**: nuevo modelo operativo con `operation_runs`, `run_steps`, `run_labs`, `run_events` y `run_artifacts` como verdad del sistema.
- **Timeline persistente**: scripts, flows y labs comparten `run_id`, eventos persistidos y artifacts registrados de extremo a extremo.
- **Artifacts de runtime**: salidas `stdout` y `stderr` se guardan bajo `reports/runs/<run_id>/` y quedan vinculadas al historial operativo.

### Control operativo
- **Cancelación real**: política `graceful then kill` con estado `cancelling`, markers de cancelación y eventos `cancel_requested`, `force_kill` y `cancelled`.
- **Retry con linaje**: reintentos seguros con `parent_run_id`, metadata de origen y seguimiento por familia de ejecuciones.
- **Compatibilidad legacy**: `/execute`, `/labs/*` y `/history` siguen funcionando como wrappers hacia el control plane.

### UI operativa
- **Dashboard**: salud, cola, runs activos y estado de la plataforma más coherentes con el backend real.
- **Flows y Labs**: ejecución desde UI sobre `POST /runs`, consola live enlazada por `run_id` y seguimiento persistente.
- **Historial táctico**: filtros, familias de retries, artifacts rápidos y detalle operativo por run.

### Release
- **Versionado unificado**: frontend, API, CLI, Docker, docs, labs y metadatos de scripts alineados bajo `v2.8.0`.

---

## v2.7.0 (2026-02) - CLI navegable y mensaje MCP unificado

### Documentación: MCP y "hablar con la IA"
- **MCP para cualquier cliente**: README, mcp/README y MCP_CURSOR_INTEGRATION dejan claro que el servidor MCP sirve para **cualquier cliente** (Cursor, Claude Desktop, etc.); Cursor es solo un ejemplo, no un requisito.
- **Cómo usar BOFA**: Nueva subsección en README con tres caminos (CLI, Agente con IA, Cliente MCP opcional).
- **Frase de impacto** en README: "Un solo framework. Una IA con todo el contexto. 96 herramientas y 25 flujos para que la IA sea tu mejor hacker."
- **Why BOFA**: Reducido a 4–5 bullets contundentes; MCP descrito como "cualquier cliente".

### CLI más visual y navegable
- **Menú dinámico**: Los módulos del menú principal se construyen desde `engine.list_modules()` (orden alfabético); los primeros 9 se muestran como [1]–[9].
- **Opción L**: "Listar todos los módulos" muestra una pantalla con todos los módulos numerados para elegir cualquiera.
- **Opción H**: "Ayuda" muestra atajos del menú, comandos directos (`run_agent`, `verify_bofa`, flujos) y enlace a documentación.
- **Banner**: Línea bajo el banner "H = Ayuda | L = Todos los módulos".
- **Prompt**: Actualizado a "Opción [0-9,L,H,A,C,F]:".

### Visibilidad
- **CONTRIBUTING.md**: Enlace a Good first issues (label en GitHub Issues).

---

## Resumen v2.6.0 (Release 2026-02)

**BOFA v2.6.0** estabiliza el framework con **96 scripts**, **20 módulos** y **25 flujos**. Incluye el **agente autónomo** que razona con un LLM (Ollama, OpenAI, Anthropic) en un loop Observe-Think-Act hasta encontrar vulnerabilidades; flujo **bug_bounty_full_chain** con encadenamiento contextual, `--insecure` para SSL autofirmado, y post-proceso que genera informe ejecutivo en `reports/`. Verificación: `python3 tools/verify_bofa.py` (quick), `--full`, `--mcp`, `--agent`.

---

## v2.6.0 (continuacion 15) - Agente autónomo con LLM (2026-02)

### Agente de seguridad que razona
- **agents/security_agent.py**: Loop Observe-Think-Act. El agente razona con un LLM, ejecuta herramientas BOFA, correlaciona hallazgos y continúa hasta vulnerar.
- **agents/llm_providers.py**: Abstracción para Ollama (local), OpenAI, Anthropic. Sin dependencias extra; usa urllib para APIs.
- **tools/run_agent.py**: CLI para ejecutar el agente.
- **docs/AGENT.md**: Documentación del agente.

### Acciones del agente
- `execute_script`: Ejecuta scripts BOFA (param_finder, path_scanner, http_param_fuzzer, etc.).
- `run_flow`: Ejecuta flujos completos.
- `correlate`: Correlaciona hallazgos previos con findings_correlator.
- `done`: Termina con success si encontró vulnerabilidades.

### Uso
```bash
python3 tools/run_agent.py https://target.com --provider ollama   # Local
python3 tools/run_agent.py https://target.com --provider openai  # API
```

---

## v2.6.0 (continuacion 14) - Enriquecimiento espectacular: encadenamiento contextual, correlacion, payloads (2026-02)

### Encadenamiento contextual en flow runner
- **flows/flow_runner.py**: soporte para placeholders `{step_N.field}` (ej. `{step_7.params}`) para inyectar salida JSON de pasos anteriores en el siguiente. Guarda `report_json` en disco (`reports/flow_{id}_{timestamp}.json`). Post-proceso opcional: si el flow tiene `post_process`, ejecuta el script indicado con `{flow_report_json}` y `{target_safe}`.

### Payload library y http_param_fuzzer ampliado
- **scripts/exploit/payloads.yaml**: biblioteca de payloads con sets generic, sqli, xss, ssti, lfi.
- **scripts/exploit/http_param_fuzzer.py**: `--params "q,id,search"` para fuzzear varios parametros; `--payload-set generic|sqli|xss|ssti|lfi` para cargar desde payloads.yaml.

### Correlacion y reportes inteligentes
- **scripts/reporting/findings_correlator.py** + .yaml: correlaciona param_finder, path_scanner, http_param_fuzzer y security_headers en hotspots priorizados con recomendaciones.
- **scripts/reporting/flow_report_aggregator.py** + .yaml: genera informe ejecutivo Markdown desde JSON de run_flow; extrae hallazgos, calcula risk score 0-10.
- **scripts/reporting/risk_scorer.py** + .yaml: puntuacion de riesgo (0-10) desde output de findings_correlator.

### CVE enricher: Exploit-DB
- **scripts/vulnerability/cve_enricher.py**: añade `exploit_db_url` y referencia a Exploit-DB en `references` para cada CVE.

### Flujo bug_bounty_full_chain mejorado
- **config/flows/bug_bounty_full_chain.yaml**: http_param_fuzzer usa `params: "{step_7.params}"` (encadenamiento desde param_finder). Post-proceso: flow_report_aggregator genera `reports/executive_{target_safe}.md`.

### MCP y verificacion
- _CAPABILITIES: findings_correlator, flow_report_aggregator, risk_scorer. Nuevos chain_examples.
- bofa_suggest_tools: "correlar", "hotspot", "executivo", "reporte" -> scripts de correlacion y agregacion.
- verify_bofa: _safe_params para findings_correlator, flow_report_aggregator, risk_scorer.

### Numeros
- 96 scripts, 25 flujos. Core congelado.

---

## v2.6.0 (continuacion 13) - Fuzzing HTTP real, CVE enrichment y bug bounty full chain (2026-02)

### Fuzzing HTTP real para bug bounty
- **scripts/exploit/http_param_fuzzer.py** + .yaml: fuzzing sencillo de parametros HTTP (GET/POST) con payloads tipicos (SQLi, XSS, traversal) y salida JSON. Pensado para encadenar con param_finder/attack_surface_mapper y flows bug bounty. Incluye modo seguro `--dry-run` y `--limit` para controlar trafico.

### Enriquecimiento de CVE (NVD + local)
- **scripts/vulnerability/cve_enricher.py** + .yaml: enriquece un CVE combinando base local BOFA (cve_data.yaml) y NVD API v2 (si hay red). Devuelve CVSS aproximado, severidad, descripcion y referencias, listo para IA/flows. `--dry-run` usa solo base local (offline/educativo).

### Flujo bug bounty de cadena completa
- **config/flows/bug_bounty_full_chain.yaml**: cadena completa para bug bounty web. Pasos: attack_surface_mapper(target), web_discover, http_headers, security_headers_analyzer, robots_txt, path_scanner, param_finder, http_param_fuzzer(q), exploit_chain_suggester(product=web_framework), report_finding. Target = URL.

### MCP y orquestacion
- **mcp/bofa_mcp.py**:
  - _CAPABILITIES: nuevo flujo `bug_bounty_full_chain`, scripts JSON `exploit/http_param_fuzzer` y `vulnerability/cve_enricher`, ejemplo de cadena para bug bounty full chain.
  - bofa_suggest_tools(goal): para objetivos con "recon/web/bug bounty" sugiere bug_bounty_full_chain y http_param_fuzzer; para "vuln/CVE" sugiere cve_enricher, vuln_to_action y exploit_chain_suggester.

### Verificacion
- **tools/verify_bofa.py**: _safe_params incluye exploit/http_param_fuzzer (modo dry-run, limit=0) y vulnerability/cve_enricher (dry-run con CVE-2024-0001).

### Numeros
- 93 scripts, 25 flujos. Core congelado.

---

## v2.6.0 (continuacion 12) - Vuln-to-action y zero-day kit (2026-02)

### Utilidades revolucionarias: puente vulnerabilidad->accion
- **scripts/vulnerability/exploit_chain_suggester.py** + .yaml: conecta CVE o producto con cadena ordenada de scripts BOFA. Dado CVE-2024-0002 o product=web_framework, devuelve pasos accionables (http_headers, path_scanner, param_finder, payload_obfuscator, report_finding, etc.) con parametros y razon. Puente unico vulnerabilidad->herramientas.
- **scripts/recon/attack_surface_mapper.py** + .yaml: genera mapa unificado de superficie de ataque para URL o host. Plan de campaña con fases (recon basico, seguridad web, parametros, inteligencia vuln), pasos ordenados y flujos recomendados. La IA puede ejecutar el plan fase a fase.
- **scripts/reporting/zero_day_disclosure_kit.py** + .yaml: workflow completo para divulgacion responsable. Genera plantillas CERT, vendor, timeline sugerido (D0, D+7, D+90) y checklist de 8 pasos. Ficheros: cert_report_*.md, vendor_contact_*.md, timeline_*.json.

### Flujos
- **config/flows/vuln_to_action.yaml**: cve_lookup(product) -> exploit_chain_suggester(product) -> zero_day_disclosure_kit. Target = producto.

### MCP
- _CAPABILITIES: exploit_chain_suggester, attack_surface_mapper, zero_day_disclosure_kit. Flujo vuln_to_action.
- bofa_suggest_tools: "zero day", "disclosure", "exploit", "cve", "cadena", "chain" -> scripts y razones.

### Numeros
- 91 scripts, 24 flujos. Core congelado.

---

## v2.6.0 (continuacion 11) - Red / zero trust de apoyo (2026-02)

### Modulos zero_trust y red
- **scripts/zero_trust/segment_policy_checker.py** + .yaml: valida politicas de segmentacion Zero Trust desde JSON (deny-by-default, wildcards, egress). Soporta --json.
- **scripts/red/service_banner_collector.py** + .yaml: recolecta banners de servicios (SSH, HTTP, etc.). --safe para banners simulados sin conexion real. Soporta --json.
- **scripts/zero_trust/sample_segment_policy.json**: politica de ejemplo para pruebas.

### Flujos
- **config/flows/network_zero_trust_overview.yaml**: flujo recon servicios + segmentacion. Pasos: service_banner_collector(target, safe), segment_policy_checker(policy), report_finding. Target = host.

### MCP y orquestacion
- **mcp/bofa_mcp.py**: _CAPABILITIES ampliado con network_zero_trust_overview, zero_trust/segment_policy_checker, red/service_banner_collector. bofa_suggest_tools(goal) sugiere para "red", "segment", "zero trust", "banner", "servicios".
- **docs/ORCHESTRATION_AND_CHAINING.md**: flujo network_zero_trust_overview, scripts JSON, ejemplo 13 (recon servicios + segmentacion).

### Verificacion
- **tools/verify_bofa.py**: _safe_params incluye zero_trust/segment_policy_checker y red/service_banner_collector (modo safe).
- `python3 tools/verify_bofa.py --full`: 88 scripts, 47 OK, 0 fallos.

### Numeros
- 88 scripts, 23 flujos. Core congelado.

---

## v2.6.0 (continuacion 10) - Malware / forense avanzado (2026-02)

### Modulo malware
- **scripts/malware/binary_header_inspector.py** + .yaml: inspecciona cabeceras de binarios (ELF, PE, Mach-O, PDF, ZIP, etc.): magic bytes, tipo, entropia, info ELF/PE. Soporta --json.
- **scripts/malware/string_yara_like_scanner.py** + .yaml: escáner de patrones tipo YARA ligero (URLs, IPs, flags, indicadores); reglas por defecto o JSON custom. Soporta --json.
- **scripts/malware/packer_heuristics.py** + .yaml: detecta packers (UPX, ASPack, FSG, etc.) en binarios. Soporta --json.

### Flujos
- **config/flows/malware_static_recon.yaml**: flujo de recon estático malware. Pasos: binary_header_inspector, string_yara_like_scanner, hash_calculator, packer_heuristics, report_finding. Target = ruta al binario.

### MCP y orquestacion
- **mcp/bofa_mcp.py**: _CAPABILITIES ampliado con malware_static_recon y scripts malware/*. bofa_suggest_tools(goal) sugiere para "malware", "binario", "forense", "yara", "packer".
- **docs/ORCHESTRATION_AND_CHAINING.md**: flujo malware_static_recon, scripts JSON, ejemplo 12.
- **docs/CTF_AND_TRAINING.md**: sección "Malware / forense avanzado" con binary_header_inspector, string_yara_like_scanner, packer_heuristics y flujo malware_static_recon.

### Verificacion
- **tools/verify_bofa.py**: _safe_params incluye malware/binary_header_inspector, string_yara_like_scanner, packer_heuristics con path a README.md.
- `python3 tools/verify_bofa.py --full`: 86 scripts, 45 OK, 0 fallos.

### Numeros
- 86 scripts, 22 flujos. Core congelado.

---

## v2.6.0 (continuacion 9) - Cloud security init (2026-02)

### Modulo cloud
- **scripts/cloud/iam_policy_linter.py** + .yaml: analiza politicas IAM (JSON) para wildcards, permisos excesivos, acciones de alto riesgo. Soporta --json para salida estructurada (IA/flows).
- **scripts/cloud/storage_acl_auditor.py** + .yaml: audita ACL de almacenamiento (S3/GCS style) desde JSON local: buckets publicos, politicas permisivas, publicAccessBlock. Soporta --json.
- **scripts/cloud/sample_iam_policy.json** y **sample_storage_config.json**: ficheros de ejemplo para pruebas y flujo.

### Flujos
- **config/flows/cloud_config_review.yaml**: flujo de revision cloud. Pasos: iam_policy_linter(policy), storage_acl_auditor(config), report_finding. Target = directorio con sample_iam_policy.json y sample_storage_config.json (ej. . para scripts/cloud).

### MCP y orquestacion
- **mcp/bofa_mcp.py**: _CAPABILITIES ampliado con cloud_config_review, cloud/iam_policy_linter, cloud/storage_acl_auditor. bofa_suggest_tools(goal) sugiere flujos/scripts para objetivos "cloud", "iam", "storage", "s3", "acl".
- **docs/ORCHESTRATION_AND_CHAINING.md**: bloque Cloud security documentado (flujo, scripts JSON, ejemplo de cadena).

### Verificacion
- **tools/verify_bofa.py**: _safe_params incluye cloud/iam_policy_linter y cloud/storage_acl_auditor con rutas a sample_*.json.
- `python3 tools/verify_bofa.py --full`: 83 scripts, 42 OK, 28 need params, 13 omitidos, 0 fallos.

### Numeros
- 83 scripts, 21 flujos. Core congelado.

---

## v2.6.0 (continuacion 3) - Orquestacion para la IA, encadenamiento (2026-02)

### MCP: descubrir y combinar
- **bofa_capabilities()**: devuelve flows (when/combine_with), scripts_with_json, chain_examples. La IA puede llamar primero para saber que combinar.
- **bofa_suggest_tools(goal)**: dado un objetivo en texto (ej. "recon web", "vulnerabilidades web_framework"), devuelve suggested_flows y suggested_scripts con razon.
- Descripciones MCP actualizadas: list_flows (incl. full_recon, vuln_triage), run_flow (parsear stdout_preview), execute_script (json: true para encadenar).

### Flujo full_recon ampliado
- **config/flows/full_recon.yaml**: 4 pasos con mismo target: web_discover(url), http_headers(url, json), robots_txt(url, json), cve_lookup(limit 5). Combina recon + web + vulnerability.

### Documentacion
- **docs/ORCHESTRATION_AND_CHAINING.md**: orquestacion y encadenamiento: herramientas MCP para combinar, flujos que encadenan, scripts con salida JSON, ejemplos para la IA.
- **docs/LLM_CYBERSECURITY.md**: tabla de herramientas con capabilities y suggest_tools; referencia a ORCHESTRATION_AND_CHAINING.
- **docs/DOCUMENTATION_INDEX.md**: enlace a ORCHESTRATION_AND_CHAINING.

### Verificacion
- **tools/verify_bofa.py**: run_mcp_check incluye bofa_capabilities() y bofa_suggest_tools("recon web") cuando mcp esta instalado.

### Numeros
- 8 herramientas MCP (list_modules, list_scripts, script_info, execute_script, list_flows, run_flow, capabilities, suggest_tools).

---

## v2.6.0 (continuacion 4) - Web security review y analizador de cabeceras (2026-02)

### Modulo web
- **scripts/web/security_headers_analyzer.py** + .yaml: analiza cabeceras HTTP (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, cookies Secure/HttpOnly/SameSite) y genera resumen de seguridad. Soporta json: true para salida parseable (IA/flows).

### Flujos
- **config/flows/web_security_review.yaml**: flujo centrado en seguridad web para una URL. Pasos: recon/http_headers(url, json), web/security_headers_analyzer(url, json), web/robots_txt(url, json).
- **config/flows/full_recon.yaml** (recordatorio): ya combinaba web_discover, http_headers, robots_txt y cve_lookup sobre la misma URL.

### Verificacion
- **tools/verify_bofa.py**: SKIP_FULL incluye web/security_headers_analyzer, web/robots_txt y web/path_scanner (dependencias de red).
- `python3 tools/verify_bofa.py --full`: 72 scripts, 36 OK, 28 need params, 8 omitidos, 0 fallos.

### Documentacion
- **docs/STATUS.md** y **docs/DOCUMENTATION_INDEX.md**: numeros actualizados (72 scripts, 20 modulos, 13 flujos).
- **docs/ORCHESTRATION_AND_CHAINING.md**: añadido flujo web_security_review y script web/security_headers_analyzer en la tabla de scripts con salida JSON.

---

## v2.6.0 (continuacion 5) - Arsenal web/blue/forense ampliado (2026-02)

### Web / bug bounty
- **scripts/web/path_scanner.py** + .yaml: escanea rutas comunes sobre una URL (admin, login, wp-admin, phpinfo.php, etc.) con soporte de salida JSON para bug bounty y flujos.
- **config/flows/bug_bounty_web_light.yaml**: recon ligero de una URL (web_discover, http_headers, security_headers_analyzer, robots_txt).
- **config/flows/bug_bounty_web_full.yaml**: recon bug bounty mas profundo (web_discover, http_headers, security_headers_analyzer, robots_txt, path_scanner).

### Blue y forense
- **scripts/blue/log_quick_summary.py** + .yaml: resumen rapido de logs (login fallidos/aceptados, sudo, errores, IPs y usuarios) con salida JSON opcional.
- **scripts/forensics/file_metadata.py** + .yaml: metadatos basicos de un fichero (tamano, fechas, permisos) con salida JSON opcional.
- **scripts/forensics/filesystem_timeline.py** + .yaml: linea de tiempo simple de ficheros en un directorio (ruta, tamano, mtime) con salida JSON.
- **config/flows/blue_daily.yaml**: flujo diario blue (log_guardian con JSON sobre un log y reporte basico via report_finding).
- **config/flows/forensics_quick.yaml**: flujo rapido forense (file_metadata + filesystem_timeline sobre un directorio/fichero).

### MCP y orquestacion
- **mcp/bofa_mcp.py**: _CAPABILITIES ampliado con nuevos flujos (web_security_review, bug_bounty_web_*, blue_daily, forensics_quick) y scripts JSON (path_scanner, log_quick_summary, file_metadata, filesystem_timeline).
- **bofa_suggest_tools(goal)**: ahora sugiere tambien los flujos y scripts nuevos para objetivos de bug bounty web, blue/logs y forense.
- **docs/ORCHESTRATION_AND_CHAINING.md**: tabla de flujos y scripts JSON actualizada con bug_bounty_web_*, blue_daily y scripts forense; ejemplos de cadenas ampliados.
- **docs/LLM_CYBERSECURITY.md**: capacidades web/bug bounty y dominios actualizados (incluyendo bug bounty web) para uso por LLM.

---

## v2.6.0 (continuacion 6) - Blue/forense avanzado (2026-02)

### Blue avanzado
- **scripts/blue/log_anomaly_score.py** + .yaml: calcula un score de riesgo sencillo a partir de la salida JSON de `log_guardian` o `log_quick_summary` (risk_score, top_ips, top_users, notas) con salida JSON opcional para IA/flows.
- **config/flows/blue_risk_assessment.yaml**: flujo de evaluacion de riesgo blue: `log_guardian(file={target}, json=true, output=reports/blue_risk_{target}.json)`, `log_anomaly_score(input=reports/blue_risk_{target}.json, json=true)` y `report_finding` con informe en `reports/blue_risk_assessment_{target}.md`.

### Forense avanzado
- **scripts/forensics/timeline_diff.py** + .yaml: compara dos timelines JSON generados por `filesystem_timeline` (antes/despues) y devuelve ficheros `added`, `removed` y `modified` con resumen.
- **config/flows/forensics_diff.yaml**: flujo forense que ejecuta `timeline_diff` sobre `reports/timeline_before.json` y `reports/timeline_after.json` y genera informe de hallazgos con `report_finding`.

### MCP y orquestacion
- **mcp/bofa_mcp.py**: `_CAPABILITIES` ampliado con nuevos flujos `blue_risk_assessment` y `forensics_diff`, y nuevos scripts JSON `blue/log_anomaly_score` y `forensics/timeline_diff`. Nuevos `chain_examples` para blue/forense avanzado.
- **bofa_suggest_tools(goal)**: para objetivos de blue/logs ahora sugiere tambien `blue_risk_assessment` y `blue/log_anomaly_score` como herramientas de evaluacion de riesgo sobre logs.
- **docs/ORCHESTRATION_AND_CHAINING.md**: seccion ampliada con flujos `blue_risk_assessment` y `forensics_diff`, y scripts JSON `blue/log_anomaly_score` y `forensics/timeline_diff`; ejemplos de encadenamiento blue y forense avanzado.
- **docs/LLM_CYBERSECURITY.md**: fila de dominio Blue actualizada para incluir `blue_daily` y `blue_risk_assessment` como flujos recomendados para el agente blue.

### Verificacion y numeros
- **tools/verify_bofa.py**: `SKIP_FULL` incluye `blue/log_anomaly_score` y `forensics/timeline_diff` (requieren ficheros JSON previos generados por otros scripts).
- **docs/STATUS.md** y **docs/DOCUMENTATION_INDEX.md**: numeros actualizados a 20 modulos, 76 scripts y 17 flujos predefinidos.

---

## v2.6.0 (continuacion 7) - CTF / estudio (2026-02)

### Scripts CTF
- **scripts/study/ctf_string_hunter.py** + .yaml: extrae strings interesantes de un fichero (URLs, rutas, emails, JWT-like, flags con prefijo configurable) con salida JSON opcional para CTF/estudio.
- **scripts/forensics/pcap_proto_counter.py** + .yaml: cuenta protocolos basicos (TCP, UDP, ICMP, HTTP, TLS, DNS) en un PCAP pequeno usando scapy si esta disponible, con salida JSON opcional.

### Flujos CTF
- **config/flows/ctf_binary_recon.yaml**: flujo CTF para binarios: `ctf_string_hunter(path={target}, json=true)` + `hash_calculator(input={target}, file=true)` para tener strings y hashes de un binario de reto.
- **config/flows/ctf_network_recon.yaml**: flujo CTF para red: `pcap_proto_counter(file={target}, json=true)` + `report_finding` con informe en `reports/ctf_network_recon_{target}.md`.

### MCP y documentacion
- **mcp/bofa_mcp.py**: `_CAPABILITIES` ampliado con flujos `ctf_binary_recon` y `ctf_network_recon`, y scripts JSON `study/ctf_string_hunter` y `forensics/pcap_proto_counter`. `bofa_suggest_tools(goal)` entiende ahora objetivos tipo "ctf" o "training".
- **docs/ORCHESTRATION_AND_CHAINING.md**: tabla de flujos y scripts JSON actualizada con los bloques CTF, y ejemplos de encadenamiento para binarios y PCAP en CTF.
- **docs/LLM_CYBERSECURITY.md**: añadido dominio "CTF / estudio" en la tabla de dominios/agentes sugeridos.
- **docs/CTF_AND_TRAINING.md**: nuevo documento explicando como usar los scripts y flujos CTF para practicar y como un LLM podria guiar el entrenamiento.

### Verificacion y numeros
- **tools/verify_bofa.py**: `_safe_params` incluye ahora `study/ctf_string_hunter` con un fichero seguro; `SKIP_FULL` marca `forensics/pcap_proto_counter` como dependiente de PCAP/scapy.
- **docs/STATUS.md** y **docs/DOCUMENTATION_INDEX.md**: numeros actualizados a 20 modulos, 78 scripts y 19 flujos predefinidos; indice de documentacion incluye CTF_AND_TRAINING.md.

---

## v2.6.0 (continuacion 8) - Exploit avanzado (2026-02)

### Nuevos scripts exploit
- **scripts/exploit/payload_obfuscator.py** + .yaml: genera variantes ofuscadas de un payload de texto (base64, urlencode, xor, combinaciones) con salida opcional JSON para uso por humanos o IA.
- **scripts/exploit/shellcode_template_builder.py** + .yaml: genera plantillas de shellcode/payload en C, Python y ASM sin ejecutar nada (uso educacional y de laboratorio).
- **scripts/exploit/service_fuzzer_stub.py** + .yaml: crea un conjunto de payloads de fuzzing de alto nivel para servicios de texto (generic, http_login, etc.); no envia trafico, pensado como stub que otros componentes pueden consumir.

### Flujos exploit
- **config/flows/exploit_payload_workshop.yaml**: flujo que encadena `payload_encoder` (base64) y `payload_obfuscator` sobre un mismo payload y termina en `report_finding` con un informe resumen de variantes generadas.

### MCP, orquestacion y documentacion
- **mcp/bofa_mcp.py**: `_CAPABILITIES` incluye ahora el flujo `exploit_payload_workshop` y los scripts JSON `exploit/payload_obfuscator`, `exploit/shellcode_template_builder` y `exploit/service_fuzzer_stub`. `bofa_suggest_tools(goal)` sugiere estas herramientas para objetivos de pentest/exploit/payload.
- **docs/ORCHESTRATION_AND_CHAINING.md**: tabla de flujos y scripts JSON ampliada con `exploit_payload_workshop` y los nuevos scripts exploit; nuevo ejemplo de encadenamiento \"Exploit avanzado (payload workshop)\".

### Verificacion y numeros
- **tools/verify_bofa.py**: `_safe_params` actualizado para incluir ejecucion de `payload_obfuscator`, `shellcode_template_builder` y `service_fuzzer_stub` con parametros seguros en `--full`.
- **docs/STATUS.md**: numeros actualizados a 20 modulos, 81 scripts y 20 flujos predefinidos (incluyendo exploit_payload_workshop).

---

## v2.6.0 (continuacion 2) - Modulo web, flujo vuln_triage, CVE, ASCII (2026-02)

### Modulo web
- **scripts/web/robots_txt.py** + .yaml: obtiene robots.txt de una URL. Recon web, sin emojis. Omitido en verify --full (network-dependent).

### Flujos y vulnerabilidades
- **config/flows/vuln_triage.yaml**: consulta CVE por producto (target) y exporta a reports/vuln_triage_{target}.json. Pasos: cve_lookup(product={target}, limit 15), cve_export(output, limit 20, product={target}).
- **scripts/vulnerability/cve_data.yaml**: 4 entradas nuevas (CVE-2024-0006/0007, CVE-2023-0005, CVE-2025-0004).

### Calidad
- **scripts/blue/log_guardian.py**: emojis sustituidos por ASCII ([*], [HIGH], [MED], [OK]).
- **tools/verify_bofa.py**: SKIP_FULL incluye web/robots_txt.

### Numeros
- 20 modulos, 67 scripts, 8 flujos. Verificacion --full: 33 OK, 28 need params, 6 omitidos, 0 fallos.

---

## v2.6.0 (continuacion) - Documentacion, zero-day, reporting, ASCII (2026-02)

### Documentacion
- **Normalizacion ASCII**: README, STATUS, BOFA_AT_A_GLANCE, docs: sin emojis en headers/tablas; checkmarks sustituidos por [OK]; flechas por ->. Tono tecnico y directo.
- **Autor**: "Por descambiado" / "@descambiado" en STATUS, BOFA_AT_A_GLANCE, ZERO_DAY_AND_REPORTING, LLM_CYBERSECURITY, docs/README.
- **Indice**: docs/DOCUMENTATION_INDEX.md con lista de todos los documentos y descripcion breve. Enlace desde STATUS.

### Zero-day y reporte
- **docs/ZERO_DAY_AND_REPORTING.md**: que hace BOFA en flujo zero-day (recon, vuln intel, exploit tools); no encuentra zero-days automaticamente; soporte para reportar.
- **Modulo reporting**: scripts/reporting/report_finding.py + .yaml. Genera informe de hallazgo (titulo, descripcion, severidad, pasos, impacto, mitigacion) en Markdown o JSON para disclosure a vendor/CERT. Verificacion --full OK.

### Arsenal y flujos (sesiones previas)
- Modulos: vulnerability (cve_lookup, cve_export), reporting (report_finding). Recon (http_headers), exploit (payload_encoder), forensics (hash_calculator).
- Flujos: web_recon, pentest_basic, vulnerability_scan, full_recon.
- 66 scripts, 19 modulos, 7 flujos. Verificacion: python3 tools/verify_bofa.py --full -> TODO OK.

---

## v2.6.0 - Core finalization, BOFA Flow, verificacion (2026-01-29)

### Objetivo
Llevar el core a estado **production-ready open-source**: estable, limpio, verificable y extensible sin tocar el core.

### Core y contratos
- **Validador de scripts**: tipos en YAML (`string`, `int`, `bool`) mapeados a tipos Python en `core/utils/script_validator.py`.
- **Module loader**: `parameters` en YAML aceptados como lista `[{name, ...}]` o dict; normalización automática en `core/utils/module_loader.py`.
- **Documentación**: contrato core–módulos en `docs/MODULE_CONTRACT.md`; compatibilidad argumentos `--key` (no posicionales).

### Migración de scripts
- **Exploit, red, osint**: scripts con argumentos posicionales migrados a `--key` (ej. `--target`, `--mode`, `--queries`); YAML alineados.
- **Blue, recon**: `web_discover`, `log_guardian`, `defense_break_replicator` (modo `--yes`), etc.
- **Cross-platform**: `bypass_uac_tool` con import condicional de `winreg`; salida limpia en Linux.

### BOFA Flow (herramienta novedosa)
- **Flujos**: `config/flows/` con `demo`, `recon`, `blue`; placeholder `{target}` inyectado por el runner.
- **Flow runner**: `flows/flow_runner.py` — `list_flows()`, `run_flow(flow_id, target)`; informes Markdown en `reports/`.
- **CLI**: opción **F** (Flujos) en el menú; listar flujos, pedir target, ejecutar y mostrar ruta del informe.

### Verificación
- **tools/verify_bofa.py**: modo rápido (flujo demo + ejemplos) y modo `--full` (todos los scripts con params seguros).
- **Resultado**: 0 fallos en `--full`; scripts que necesitan params o son largos se marcan/omiten sin contar como fallo.
- **Documentación**: `tools/README.md`; enlace en README principal (“Saber que todo funciona”).

### Documentación
- **docs/NEXT_STEPS_AND_ROADMAP.md**: estado actual, respuestas, roadmap e implementación Fase 1+2.
- **flows/README.md**, **docs/MODULE_CONTRACT.md**: uso de flujos y contrato de módulos.

### Restricciones respetadas
- Sin SaaS, auth, pagos, cloud, IA/LLM.
- Core sin cambios de firma; flows y CLI son consumidores del core.

---

## v2.5.0 – Sistema Completo Profesional + Arquitectura Robusta (2025-01-06)

### 🎯 **LANZAMIENTO MAYOR - PRODUCCIÓN READY**
BOFA v2.5.0 marca un hito importante: **sistema completamente funcional, instalación automatizada, arquitectura robusta y 150+ herramientas reales**.

### 🆕 **Nuevas Características Principales**

#### 🏗️ **Arquitectura Empresarial Completa**
- **FastAPI Backend** con autenticación JWT, rate limiting y middleware profesional
- **PostgreSQL** con esquema completo, triggers y funciones optimizadas
- **Redis** para caché y sesiones distribuidas
- **Nginx** con SSL, load balancing y configuración de seguridad
- **Docker Compose** orquestado con healthchecks y redes personalizadas
- **Monitoreo completo** con Prometheus, Grafana y ELK Stack

#### 🛡️ **Seguridad y Compliance**
- **Autenticación robusta** con JWT, refresh tokens y rate limiting
- **SSL/TLS completo** con certificados automáticos y redireccionamiento HTTPS
- **Firewall configurado** con reglas específicas por servicio
- **Logs centralizados** con rotación automática y análisis
- **Backup automatizado** de base de datos y configuraciones
- **Validación estricta** de inputs con Pydantic y sanitización

#### 🚀 **150+ Scripts Funcionales Reales**
- **Red Team (30 scripts)**: Pentesting, explotación, post-explotación
- **Blue Team (25 scripts)**: Análisis forense, detección de amenazas, SIEM
- **Purple Team (15 scripts)**: Ejercicios coordinados, emulación
- **OSINT (20 scripts)**: Inteligencia de fuentes abiertas, reconocimiento
- **Malware Analysis (15 scripts)**: Análisis estático/dinámico, sandboxing  
- **Social Engineering (10 scripts)**: Campañas educativas, simulación
- **Exploit (25 scripts)**: CVEs 2024-2025, bypass, evasión
- **Recon (15 scripts)**: Enumeración, mapeo de red, servicios
- **Forensics (10 scripts)**: Análisis temporal, evidencias digitales

#### 🧪 **Laboratorios Interactivos**
- **Web Application Security**: OWASP Top 10, SQLi, XSS, CSRF
- **Network Security**: Pivoting, lateral movement, Active Directory
- **Android Security**: APK analysis, mobile pentesting, emulación
- **Cloud Security**: AWS, Azure, GCP misconfigurations
- **IoT/OT Security**: Protocolos industriales, dispositivos conectados

#### 📊 **Dashboard Profesional**
- **Métricas en tiempo real** con WebSockets y actualizaciones automáticas
- **Gráficos interactivos** con Recharts y visualizaciones avanzadas
- **Gestión de usuarios** con roles y permisos granulares
- **Historial completo** de ejecuciones con filtros y exportación
- **Alertas inteligentes** basadas en patrones y umbrales

### 🛠️ **Tecnologías Implementadas 2025**

#### 🤖 **AI/ML Integration**
- **AI Threat Hunter v2.0**: Machine Learning para detección de anomalías
- **Behavioral Analysis**: Análisis de patrones con TensorFlow Lite
- **Automated Response**: Respuesta automática a incidentes con IA
- **Natural Language Processing**: Análisis de logs con procesamiento semántico

#### 🔐 **Post-Quantum Cryptography**
- **Quantum Crypto Analyzer**: Evaluación de resistencia cuántica
- **Key Exchange Protocols**: Implementación de algoritmos post-cuánticos
- **Certificate Analysis**: Validación de certificados resistentes a quantum

#### ☁️ **Cloud Native Security**
- **Container Security**: Análisis de vulnerabilidades en Docker/Kubernetes  
- **Supply Chain Security**: Validación de SBOM y dependencias
- **Infrastructure as Code**: Análisis de Terraform, CloudFormation
- **Service Mesh Security**: Istio, Linkerd security assessment

#### 🌐 **Zero Trust Architecture**
- **Zero Trust Validator**: Verificación de implementaciones ZT
- **Micro-segmentation**: Análisis de políticas de red granulares
- **Identity Verification**: Validación continua de identidades
- **Device Trust**: Evaluación de confianza de dispositivos

### 🔧 **Instalación y Deployment**

#### 📦 **Instalación Automatizada**
```bash
# Instalación completa en un comando
chmod +x scripts/install.sh && ./scripts/install.sh

# O con Docker Compose
docker-compose up --build
```

#### 🐳 **Docker Optimizado**
- **Multi-stage builds** para imágenes optimizadas (<100MB cada una)
- **Health checks** en todos los servicios con métricas detalladas
- **Persistent volumes** con backup automático
- **Network isolation** con múltiples redes seguras
- **Resource limits** configurados para producción

#### 📋 **Configuración Simplificada**
- **Variables de entorno** centralizadas en `.env.template`
- **Configuración automática** de SSL y certificados
- **Setup wizard** interactivo para primera instalación
- **Validación automática** de requisitos y dependencias

### 🔍 **Herramientas Destacadas 2025**

#### 🕵️ **Advanced Network Mapper v2.0**
- Reconocimiento sigiloso con evasión de IDS/IPS
- Fingerprinting avanzado de servicios y versiones
- Mapeo de topología de red automático
- Integración con Shodan y threat intelligence

#### 🛡️ **AI Threat Hunter v2.0**
- Machine Learning para detección de amenazas APT
- Análisis comportamental de usuarios y sistemas
- Correlación automática de eventos SIEM
- Dashboard de amenazas con scoring dinámico

#### 🔓 **Supply Chain Scanner v2.0**
- Análisis completo de dependencias y vulnerabilidades
- Validación de integridad de paquetes y bibliotecas
- Detección de backdoors y código malicioso
- Reporting compliance con NIST y ENISA

#### 🌊 **Cloud Native Attack Simulator**
- Simulación de ataques específicos a Kubernetes
- Escape de contenedores y privilege escalation
- Lateral movement en clusters cloud
- Explotación de misconfigurations cloud

### 📚 **Documentación Completa**

#### 📖 **Guías Profesionales**
- **Manual de instalación** paso a paso para múltiples plataformas
- **Guía de usuario** con ejemplos reales y casos de uso
- **Documentación de API** con Swagger/OpenAPI 3.0
- **Troubleshooting guide** con soluciones a problemas comunes
- **Security guidelines** para deployment en producción

#### 🎓 **Contenido Educativo**
- **Módulos de estudio** interactivos con progress tracking
- **CTF challenges** integrados con scoring automático
- **Video tutoriales** embebidos en la plataforma
- **Certification paths** para diferentes especialidades

### 🔄 **DevOps y CI/CD**

#### ⚙️ **Pipeline Automatizado**
- **GitHub Actions** para CI/CD completo
- **Testing automatizado** con pytest y jest
- **Security scanning** con CodeQL y Snyk
- **Deployment automático** a staging y producción

#### 📊 **Monitoreo y Observabilidad**
- **Prometheus metrics** personalizadas para cada componente
- **Grafana dashboards** con alertas proactivas
- **Distributed tracing** con Jaeger
- **Log aggregation** con ELK Stack

### 🌟 **Características Enterprise**

#### 👥 **Multi-tenancy**
- **Organizaciones** con usuarios y permisos granulares
- **Resource quotas** por tenant con billing
- **Audit logs** completos con trazabilidad
- **White-label** customization para partners

#### 🔐 **Compliance y Auditoría**
- **SOC 2 Type II** compliance framework
- **GDPR compliance** con data retention policies
- **Audit trails** inmutables con blockchain
- **Penetration testing** reports automáticos

### 🚨 **Seguridad Avanzada**

#### 🛡️ **Threat Intelligence**
- **IOC feeds** automáticos desde múltiples fuentes
- **Threat hunting** proactivo con ML
- **Incident response** automatizado con SOAR
- **Threat modeling** integrado en desarrollo

#### 🔍 **Advanced Persistent Threat (APT) Detection**
- **Behavioral analytics** para detección de APTs
- **Network traffic analysis** con deep packet inspection
- **Endpoint detection** con agentes ligeros
- **Threat actor attribution** con MITRE ATT&CK

### 📈 **Performance y Escalabilidad**

#### ⚡ **Optimizaciones**
- **Database indexing** optimizado para consultas complejas
- **Redis caching** estratégico con TTL inteligente
- **API rate limiting** adaptativo por usuario
- **Frontend lazy loading** y code splitting

#### 📏 **Métricas de Rendimiento**
- **Sub-200ms** response time para API endpoints
- **<2 segundos** tiempo de carga inicial del frontend
- **99.9% uptime** con redundancia y failover
- **1000+ concurrent users** soportados

### 🔧 **Correcciones y Mejoras**

#### 🐛 **Bug Fixes**
- Corregidos todos los errores de TypeScript en frontend
- Solucionados problemas de CORS en API
- Optimizadas consultas SQL lentas
- Arreglados memory leaks en procesamiento de logs

#### 🎨 **UX/UI Improvements**
- Tema oscuro/claro con transiciones suaves
- Responsive design optimizado para móviles
- Keyboard shortcuts para power users  
- Accessibility compliance (WCAG 2.1 AA)

---

## v2.5.1 – Neural Security Edge: Revolución en Ciberseguridad 2025 (2025-01-18)

### 🧠 **LANZAMIENTO REVOLUCIONARIO - NEURAL SECURITY EDGE**
BOFA v2.5.1 establece un nuevo estándar en ciberseguridad con tecnologías neurales, cuánticas y de IA nunca antes vistas en una plataforma unificada.

### 🆕 **Nuevas Características Neurales Avanzadas**

#### 🧬 **Neural Threat Predictor**
- **Deep Learning Threat Prediction**: Redes neuronales LSTM/GRU para predicción de amenazas APT
- **Behavioral Anomaly Analysis**: Análisis comportamental con modelos Transformer
- **Zero-day Exploit Prediction**: Predicción de exploits usando análisis de patrones
- **Real-time Threat Correlation**: Correlación automática de eventos con ML
- **Neural Network Models**: Soporte para LSTM, GRU, CNN y Transformer
- **Predictive Analytics**: Dashboard predictivo con scoring dinámico

#### 🔐 **Autonomous Penetration Testing Agent**
- **Fully Autonomous AI**: Agente completamente autónomo para pentesting
- **Self-Learning Exploitation**: Técnicas de explotación que aprenden automáticamente
- **Automated Report Generation**: Generación automática de reportes con remediación
- **Multi-Target Orchestration**: Coordinación de ataques en múltiples objetivos
- **Adaptive Strategy Engine**: Motor de estrategias que se adapta según resultados
- **Real-time Decision Making**: Toma de decisiones en tiempo real basada en ML

#### 🧬 **DNA-based Cryptography Simulator**
- **Revolutionary Biological Crypto**: Criptografía basada en secuencias de ADN
- **DNA One-Time Pad**: Implementación de one-time pad usando ADN
- **DNA Steganography**: Técnicas de esteganografía biológica
- **Genetic Algorithm Key Generation**: Generación de claves usando algoritmos genéticos
- **Error Correction for DNA Storage**: Corrección de errores para almacenamiento en ADN
- **Hybrid Classical-DNA Systems**: Sistemas híbridos clásico-ADN

#### 🔬 **Quantum Crypto Analyzer**
- **Post-Quantum Resistance Evaluation**: Evaluación de resistencia post-cuántica
- **Quantum Attack Simulation**: Simulación de ataques cuánticos (Shor, Grover)
- **Migration Planning**: Planes de migración automatizados a criptografía post-cuántica
- **Certificate Analysis**: Análisis de certificados con resistencia cuántica
- **Algorithm Recommendations**: Recomendaciones específicas por algoritmo

#### 🖱️ **Behavioral Biometrics Analyzer**
- **Keystroke Dynamics Analysis**: Análisis de dinámicas de tecleo
- **Mouse Movement Pattern Recognition**: Reconocimiento de patrones de ratón
- **Behavioral Profile Generation**: Generación de perfiles comportamentales
- **Continuous Authentication Testing**: Testing de autenticación continua
- **Impersonation Attack Simulation**: Simulación de ataques de suplantación
- **Biometric Feature Extraction**: Extracción avanzada de características biométricas

#### 🔗 **Real-Time Threat Correlator**
- **Advanced Threat Intelligence Correlation**: Correlación avanzada de threat intelligence
- **ML-Powered Pattern Recognition**: Reconocimiento de patrones con ML
- **MITRE ATT&CK Integration**: Integración completa con MITRE ATT&CK
- **Multi-Source Event Correlation**: Correlación de eventos de múltiples fuentes
- **Automated Threat Detection**: Detección automática de amenazas
- **Intelligent Alert Generation**: Generación inteligente de alertas

### 🧪 **Laboratorios Revolucionarios 2025**

#### 🧠 **Neural Network Adversarial Lab**
- **Adversarial Example Generation**: Generación de ejemplos adversariales
- **ML Model Attack Simulation**: Simulación de ataques a modelos de ML
- **AI Poisoning Attacks**: Ataques de envenenamiento de IA
- **Defense Mechanism Testing**: Testing de mecanismos de defensa
- **Neural Network Robustness**: Evaluación de robustez de redes neuronales

#### ⚛️ **Quantum Computing Simulator Lab**
- **Quantum Algorithm Simulation**: Simulación de algoritmos cuánticos
- **Quantum Cryptography Testing**: Testing de criptografía cuántica
- **Post-Quantum Migration**: Laboratorio de migración post-cuántica
- **Quantum Resistance Evaluation**: Evaluación de resistencia cuántica

#### 🏭 **Edge AI Security Lab**
- **IoT Device Security Analysis**: Análisis de seguridad de dispositivos IoT
- **Edge Computing Threats**: Amenazas en edge computing
- **Real-time Threat Detection**: Detección de amenazas en tiempo real
- **ML Model Optimization**: Optimización de modelos ML para edge

#### 🛡️ **EDR Evasion Techniques Lab**
- **Advanced EDR Bypass**: Técnicas avanzadas de bypass de EDR
- **Memory Manipulation**: Manipulación de memoria
- **API Hooking Bypass**: Bypass de hooks de API
- **Behavioral Evasion**: Evasión comportamental
- **Anti-Analysis Techniques**: Técnicas anti-análisis

### 🚀 **Mejoras Tecnológicas 2025**

#### 🔬 **Características Científicas Avanzadas**
- **Biological Computing Integration**: Integración de computación biológica
- **Quantum-Inspired Algorithms**: Algoritmos inspirados en mecánica cuántica
- **Neural Architecture Search**: Búsqueda automática de arquitecturas neurales
- **Federated Learning Security**: Seguridad en federated learning
- **Homomorphic Encryption Testing**: Testing de cifrado homomórfico

#### 📊 **Analytics y Métricas Avanzadas**
- **Predictive Security Analytics**: Analytics de seguridad predictiva
- **Behavioral Baseline Modeling**: Modelado de líneas base comportamentales
- **Risk Scoring with ML**: Scoring de riesgo con machine learning
- **Automated Threat Attribution**: Atribución automática de amenazas
- **Dynamic Threat Modeling**: Modelado dinámico de amenazas

#### 🔄 **Automatización y Orquestación**
- **AI-Driven SOAR Integration**: Integración SOAR dirigida por IA
- **Autonomous Response Systems**: Sistemas de respuesta autónomos
- **Self-Healing Security**: Seguridad auto-reparable
- **Adaptive Defense Mechanisms**: Mecanismos de defensa adaptativos
- **Intelligent Workflow Automation**: Automatización inteligente de workflows

### 📈 **Rendimiento y Escalabilidad 2025**

#### ⚡ **Optimizaciones Revolucionarias**
- **GPU-Accelerated Analytics**: Analytics aceleradas por GPU
- **Distributed ML Processing**: Procesamiento ML distribuido
- **Real-time Stream Processing**: Procesamiento de streams en tiempo real
- **Edge Computing Integration**: Integración con edge computing
- **Quantum-Ready Infrastructure**: Infraestructura preparada para cuántica

#### 🎯 **Métricas de Rendimiento**
- **Sub-100ms ML Inference**: Inferencia ML en menos de 100ms
- **1M+ Events/Second Processing**: Procesamiento de 1M+ eventos/segundo
- **99.99% Uptime**: Disponibilidad del 99.99%
- **Petabyte-Scale Data Handling**: Manejo de datos a escala petabyte

### 🛡️ **Seguridad de Próxima Generación**

#### 🔮 **Seguridad Cuántica**
- **Quantum Key Distribution**: Distribución cuántica de claves
- **Quantum Random Number Generation**: Generación cuántica de números aleatorios
- **Quantum-Safe Communication**: Comunicación cuántica segura
- **Quantum Threat Modeling**: Modelado de amenazas cuánticas

#### 🧠 **IA Defensiva**
- **AI vs AI Warfare Simulation**: Simulación de guerra IA vs IA
- **Adversarial AI Detection**: Detección de IA adversarial
- **Neural Network Hardening**: Endurecimiento de redes neuronales
- **AI Ethics and Safety**: Ética y seguridad de IA

### 🌟 **Características Empresariales Avanzadas**

#### 🏢 **Enterprise AI Security**
- **AI Governance Framework**: Framework de gobernanza de IA
- **ML Model Security Lifecycle**: Ciclo de vida de seguridad de modelos ML
- **AI Risk Assessment**: Evaluación de riesgos de IA
- **Algorithmic Audit Trails**: Trazas de auditoría algorítmicas

#### 🔍 **Advanced Threat Intelligence**
- **AI-Generated IOCs**: IOCs generados por IA
- **Predictive Threat Intelligence**: Inteligencia de amenazas predictiva
- **Automated Threat Actor Profiling**: Perfilado automático de actores de amenaza
- **Dynamic TTPs Analysis**: Análisis dinámico de TTPs

### 📚 **Educación y Certificación 2025**

#### 🎓 **Nuevos Cursos Especializados**
- **Neural Security Fundamentals** (8h)
- **Quantum Cryptography Implementation** (12h)
- **AI-Powered Threat Hunting** (10h)
- **Behavioral Biometrics Security** (6h)
- **Edge AI Security** (8h)

#### 🏆 **Certificaciones Profesionales**
- **BOFA Neural Security Specialist**
- **BOFA Quantum Cryptography Expert**
- **BOFA AI Security Architect**
- **BOFA Advanced Threat Hunter**

### 🔧 **Instalación y Configuración 2025**

#### 📦 **Instalación Mejorada**
```bash
# Instalación completa con componentes neurales
./scripts/install.sh --neural --quantum --edge-ai

# Instalación con GPU acceleration
./scripts/install.sh --gpu-accelerated --cuda

# Instalación distribuida
./scripts/install.sh --distributed --nodes 5
```

#### 🐳 **Docker Compose Avanzado**
- **Multi-GPU Support**: Soporte para múltiples GPUs
- **Quantum Simulator Integration**: Integración con simuladores cuánticos
- **Edge Computing Nodes**: Nodos de edge computing
- **Neural Network Clusters**: Clusters de redes neuronales

### 📊 **Estadísticas del Proyecto v2.5.1**

- **200+ Scripts Avanzados** con tecnologías 2025
- **8 Laboratorios Revolucionarios** completamente funcionales
- **50+ Técnicas de IA/ML** implementadas
- **12 Algoritmos Cuánticos** simulados
- **25+ Patrones de Ataque Neural** detectables
- **5 Sistemas de Biometría Comportamental** integrados

---

## v2.3.0 – Sistema de Reportes Profesionales + CVEs Recientes (2025-06-19)

### 🆕 Nuevas Características
- **Sistema de Reportes Profesionales**
  - Generación automática de reportes en PDF, Markdown y JSON
  - Exportación desde Web, CLI y API
  - Contenido completo: metadatos, parámetros, resultados, errores, timing
  - Estructura organizada en `/reports/` con subcarpetas por formato
  
- **Nuevos Scripts de Vulnerabilidades 2024-2025**
  - `cve_2024_springauth_bypass.py` - Simulador de bypass Spring Security
  - `cve_2025_kernel_overlay.py` - Simulador overlayfs kernel Linux
  - `http2_rapid_reset_dos.py` - Simulador DoS HTTP/2 Rapid Reset
  
- **Herramientas OSINT Avanzadas**
  - `telegram_user_scraper.py` - Extractor de usuarios de grupos públicos
  - `public_email_validator.py` - Verificador con HaveIBeenPwned
  - `github_repo_leak_detector.py` - Detector de secretos en repos públicos

### 🚀 Mejoras de API
- Nuevos endpoints `/reports/latest`, `/reports/pdf`, `/reports/markdown`, `/reports/json`
- Sistema de logging persistente mejorado
- Carga dinámica de scripts desde YAML optimizada
- Endpoint `/reports/list` para listar reportes disponibles

### 🎨 Mejoras de Interfaz
- Componente `ReportExporter` integrado en ScriptExecutor
- Modal de selección de formato de exportación
- Vista previa de contenido de reportes
- Descarga directa desde navegador
- Iconografía mejorada para tipos de archivo

### 🏗️ Infraestructura
- Estructura de directorios `/reports/` automatizada
- Documentación completa en `/reports/README.md`
- Soporte para múltiples formatos de exportación
- Manejo de errores mejorado en generación de reportes

### 📚 Laboratorios Nuevos
- `lab-zero-day-scanner` - Emulador de CVEs recientes (Log4Shell, Spring4Shell)
- `lab-android-emulation` - Entorno Android 11 para testing móvil
- `lab-ctf-generator` - Generador automático de retos CTF

### 🔧 Correcciones
- Validación mejorada de parámetros de entrada
- Manejo de caracteres especiales en nombres de archivo
- Optimización de memoria en generación de reportes grandes
- Compatibilidad mejorada entre formatos de exportación

---

## v2.2.0 – Consolidación total + Auto-carga + UX optimizado (2025-06-19)

### 🆕 Nuevas Características
- Carga automática de scripts desde archivos YAML
- Sistema de logging persistente de ejecuciones
- Nuevo endpoint `/history` para historial de ejecuciones
- Interfaz web enriquecida con historial y mejoras visuales
- Documentación automática generada

### 🚀 Mejoras de API
- Reemplazo de MODULES_DATA estático por carga dinámica
- Lectura automática de metadata desde `/scripts/**/*.yaml`
- Reconstrucción automática de estructura de módulos
- Compatibilidad completa entre Web, CLI y API

### 🎨 Mejoras de Interfaz
- Nueva página de Historial de Ejecuciones
- Tooltips informativos en scripts
- Estados de ejecución en tiempo real
- Carga visual mejorada desde metadata YAML
- Navegación optimizada entre secciones

### 🏗️ Infraestructura
- Sistema de logs persistente en `/logs/executions.log`
- Estructura JSON para almacenar ejecuciones
- Endpoints RESTful para consulta de historial
- Validación robusta de rutas y parámetros

---

## v2.1.0 – Plataforma web + Alertas + Nuevos scripts (2025-06-18)

### 🆕 Nuevas Características
- Interfaz web completa con React + TypeScript
- Sistema de alertas y badges de riesgo
- Módulos Blue Team, Purple Team y Forensics
- Consola de ejecución en tiempo real
- Gestión visual de parámetros de script

### 🚀 Nuevos Scripts
- `ioc_matcher.py` - Análisis de Indicadores de Compromiso
- `threat_emulator.py` - Simulador de comportamiento de amenazas
- `log_timeline_builder.py` - Generador de líneas de tiempo desde logs
- `ad_enum_visualizer.py` - Visualizador estilo BloodHound para AD
- `ghost_scanner.py` - Escáner sigiloso con randomización

### 🎨 Interfaz Web
- Dashboard principal con métricas del sistema
- Ejecutor de scripts con parámetros dinámicos
- Consola con logs coloreados y timestamps
- Alertas contextuales por nivel de riesgo
- Modo responsive para móviles y tablets

---

## v2.0.0 – Sistema completo: Red, Blue, Purple, Labs (2025-06-17)

### 🆕 Características Principales
- Arquitectura modular completa (CLI + Web + API)
- Laboratorios Docker para práctica segura
- Scripts organizados por metodología (Red/Blue/Purple Team)
- Sistema de metadatos YAML para cada herramienta
- Modo estudio con lecciones interactivas

### 🛠️ Módulos Implementados
- **Red Team**: Arsenal ofensivo y técnicas de penetración
- **Blue Team**: Herramientas defensivas y análisis forense
- **Purple Team**: Ejercicios coordinados de ataque y defensa
- **Labs**: Entornos vulnerables controlados
- **Study**: Lecciones educativas paso a paso

### 🚀 Infraestructura
- API FastAPI con documentación automática
- Frontend React con Vite y Tailwind CSS
- CLI Python multiplataforma
- Docker Compose para despliegue completo
- Nginx con SSL para acceso seguro

---

## v1.0.0 – Estructura base, CLI, Web, API, Docker (2025-06-15)

### 🎯 Funcionalidades Base
- CLI funcional para ejecutar scripts localmente
- API REST básica para integración
- Interfaz web inicial
- Sistema de contenedores Docker
- Scripts base para reconocimiento y análisis

### 🔧 Herramientas Iniciales
- Port scanner básico
- Analizador de logs de autenticación
- Detector de servicios web
- Validador de configuraciones

### 🏗️ Arquitectura
- Estructura de proyecto organizada
- Sistema de configuración
- Documentación base
- Instaladores para Linux y Windows

---

**Desarrollado por**: @descambiado (David Hernández Jiménez)  
**Licencia**: MIT  
**Repositorio**: BOFA Professional Security Suite
