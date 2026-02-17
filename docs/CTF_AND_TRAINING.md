# CTF y entrenamiento con BOFA

Por descambiado. Como usar el Bloque 3 (CTF/estudio) para practicar retos y entrenar, tanto de forma humana como asistida por IA.

---

## Objetivo

- Tener herramientas ligeras para hacer **recon rapido** de binarios y capturas de red en CTF.
- Mantenerlas **IA-ready**: salida JSON opcional y flujos encadenables.
- No tocar el core; solo añadir scripts y flujos sobre el arsenal existente.

---

## Scripts CTF

### study/ctf_string_hunter

- **Que hace**: dado un fichero (binario o texto), extrae strings imprimibles y las clasifica en:
  - URLs
  - rutas de fichero
  - emails
  - cadenas tipo JWT
  - flags con prefijo configurable (por defecto `BOFA{` y `CTF{`).
- **Uso basico**:

```bash
python3 scripts/study/ctf_string_hunter.py --path reto.bin --json
```

- **Salida JSON** (resumen):
  - `file`: ruta del fichero analizado.
  - `min_length`: longitud minima usada.
  - `total_strings`: numero total de strings detectadas.
  - `categories.urls`, `categories.paths`, `categories.emails`, `categories.jwt_like`, `categories.flags`, `categories.other_sample`.

Esto permite a un humano (o a la IA) ver rapidamente indicadores utiles en un binario CTF.

### forensics/pcap_proto_counter

- **Que hace**: cuenta protocolos basicos en un PCAP pequeno:
  - TCP, UDP, ICMP
  - HTTP (puertos 80/8080/8000)
  - TLS (puertos 443/8443)
  - DNS (puerto 53)
- **Uso basico**:

```bash
python3 scripts/forensics/pcap_proto_counter.py --file captura.pcap --json
```

- **Salida JSON**:
  - `file`: ruta del PCAP.
  - `limit`: maximo de paquetes leidos.
  - `counts`: objeto con contadores por protocolo.

Nota: si `scapy` no esta instalado, el script devuelve un error claro en JSON/STDERR.

---

## Flujos CTF

### ctf_binary_recon

- **Ubicacion**: `config/flows/ctf_binary_recon.yaml`
- **Target**: ruta a un binario o fichero CTF.
- **Pasos**:
  1. `study/ctf_string_hunter(path={target}, json=true)` -> JSON con strings interesantes.
  2. `forensics/hash_calculator(input={target}, file=true)` -> hash del binario (MD5/SHA256).

Uso tipico:

```bash
python3 -m flows.flow_runner run_flow ctf_binary_recon reto.bin
```

Sirve para tener, en un solo flujo, strings relevantes y hashes de referencia del binario.

### ctf_network_recon

- **Ubicacion**: `config/flows/ctf_network_recon.yaml`
- **Target**: ruta a un PCAP pequeno.
- **Pasos**:
  1. `forensics/pcap_proto_counter(file={target}, json=true)` -> JSON con contadores de protocolos.
  2. `reporting/report_finding` -> informe Markdown en `reports/ctf_network_recon_{target}.md`.

Uso tipico:

```bash
python3 -m flows.flow_runner run_flow ctf_network_recon captura.pcap
```

Permite ver de un vistazo si el PCAP es mas HTTP, DNS, TLS, etc., y usarlo como guia para el analisis.

---

## Uso por parte de la IA (MCP)

Un cliente MCP (Cursor, Claude, etc.) puede usar estos bloques CTF de forma autonoma:

- **Binario CTF**:
  1. `bofa_run_flow("ctf_binary_recon", "reto.bin")`.
  2. Parsear `steps[0].stdout_preview` (JSON de `ctf_string_hunter`) para listar flags candidatas, URLs y rutas interesantes.
  3. Usar el hash del segundo paso para documentar el binario en un informe o compararlo con otras muestras.

- **PCAP CTF**:
  1. `bofa_run_flow("ctf_network_recon", "captura.pcap")`.
  2. Parsear `steps[0].stdout_preview` (JSON de `pcap_proto_counter`) para ver que protocolos hay.
  3. Decidir siguientes pasos (por ejemplo, solo analizar HTTP o DNS segun los contadores).

Estos flujos no contienen logica de LLM; solo proporcionan datos estructurados que un LLM puede interpretar y explicar al alumno.

---

## Relacion con otros modulos

- Para binarios:
  - `ctf_string_hunter` + `hash_calculator` dan una primera vista.
  - Se puede combinar con `forensics/file_metadata` si se quiere mas contexto.
- Para red:
  - `pcap_proto_counter` da una vista de alto nivel.
  - Se puede combinar con `packet_storybuilder` o con reportes manuales usando `report_finding`.

Todo sigue la filosofia de BOFA: core congelado y profesional, arsenal en expansion y salidas JSON listas para ser orquestadas por humanos o IA.

