# Estado actual, respuestas y roadmap

Este documento responde a las preguntas sobre el estado del proyecto BOFA, qué queda por hacer, y cómo seguir desarrollando y diferenciándonos.

---

## ¿Te acuerdas qué queríamos hacer después del core?

Sí. Después de dejar el **core production-ready** (estable, limpio, documentado, sin tocar para añadir módulos), los siguientes pasos acordados eran:

1. **Auditar y migrar los scripts existentes** para que cumplan el contrato del core (parámetros como `--key value`, tipos en YAML compatibles con el validador, códigos de salida, etc.).
2. **Innovar y diferenciarnos** con ideas como:
   - Módulos BOFA “certificados” (estándar de calidad).
   - Framework de testing para módulos.
   - Documentación interactiva por módulo.
   - Gestión de dependencias por módulo.
   - Salida/reportes estandarizados (JSON, Markdown).

---

## ¿Funcionan las herramientas/scripts?

| Componente | Estado |
|------------|--------|
| **Core** (engine, config, logger, errors, utils) | ✅ Funciona y validado |
| **CLI** (`./bofa.sh`, `cli/bofa_cli.py`) | ✅ Funciona; usa solo el core |
| **Módulos de ejemplo** (`examples/`: example_info, example_params, example_fail) | ✅ Funcionan con el core |
| **Validador de parámetros** | ✅ Corregido: acepta tipos en YAML (`string`, `int`, `bool`) además de tipos Python |
| **Scripts “reales”** (exploit, red, blue, osint, etc.) | ✅ Migrados a `--key` los que tenían posicionales; core acepta `parameters` en YAML como lista o dict; verificación `tools/verify_bofa.py --full` pasa (0 fallos). |

**Nota**: El core pasa parámetros como `--key value`. Los scripts deben usar **argumentos opcionales** (`--target`, `--verbose`, etc.). Los ejemplos en `scripts/examples/` son la referencia.

---

## ¿Es funcional todo?

- **Sí** para: core, CLI, ejemplos, flujos (BOFA Flow), verificación (`python3 tools/verify_bofa.py` y `--full`). Los scripts migrados funcionan desde CLI/core; los que necesitan parámetros se ejecutan con params seguros en `--full` o desde la CLI introduciendo valores.

---

## ¿Cuánto nos queda por desarrollar?

Estimación por fases:

| Fase | Descripción | Esfuerzo aproximado |
|------|-------------|----------------------|
| **1. Compatibilidad de scripts** | Revisar cada script: argparse con `--key`, YAML con `parameters` y `type: string/int/bool`, códigos de salida. | Alto (60+ scripts) |
| **2. Tests automatizados** | Tests del core + script de smoke para “listar módulos y ejecutar ejemplo sin params”. | Medio |
| **3. Innovación 1** | Por ejemplo: estándar de “módulo certificado” o framework de tests para módulos. | Medio |
| **4. Innovación 2** | Por ejemplo: documentación interactiva por módulo o salida estandarizada (JSON/MD). | Medio |
| **5. API y frontend** | Verificar que la API y el frontend usen el mismo core y mismos contratos (si aplica). | Medio |

El **trabajo más grande** para tener “todo funcional” es la **fase 1** (auditoría y migración de scripts). El resto son mejoras e innovación sobre una base ya sólida.

---

## ¿Hay algo que nos diferencie de otras herramientas o proyectos?

Sí:

- **Core como framework**, no solo colección de scripts: arquitectura clara, responsabilidades definidas, documentación de contrato core–módulos.
- **Añadir módulos sin tocar el core**: descubrimiento automático por directorios en `scripts/<módulo>/`.
- **Contrato explícito** (docs, YAML, parámetros `--key`) para quien escribe o integra herramientas.
- **Enfoque educativo y operativo**: formación y uso real con la misma base.
- **Muchas herramientas en un solo marco**: decenas de scripts organizados por categoría (red, blue, purple, osint, etc.).
- **Local-first, extensible**: pensado para uso local y reutilizable por otras capas (CLI, API, frontend).

---

## ¿Podemos diferenciarnos más? ¿Ser más innovadores?

Sí. Algunas direcciones concretas (sin SaaS, auth, pagos, cloud, IA/LLM, bug bounty, OSINT externo):

1. **Módulos BOFA certificados**  
   Definir un checklist (tests, metadata, parámetros documentados, salida estable) y un proceso para “certificar” módulos. Da confianza y calidad sin cerrar el ecosistema.

2. **Framework de testing para módulos**  
   Herramientas y convenciones para que los autores de módulos escriban pruebas (p. ej. “ejecutar con estos params y comprobar exit code y salida”). El core ya permite ejecutar scripts desde código; falta estandarizar cómo se escriben y ejecutan esos tests.

3. **Documentación interactiva por módulo**  
   Estándar para que cada módulo pueda incluir un pequeño doc o tutorial (Markdown/HTML) que la CLI o el frontend muestren al elegir el módulo (p. ej. “E” en el menú ya abre ejemplos; se puede generalizar).

4. **Salida y reportes estandarizados**  
   Convención para que los scripts puedan emitir JSON o Markdown estructurado; el core (o una utilidad) podría agregar o formatear informes. Opcional y retrocompatible.

5. **Dependencias por módulo**  
   Que cada módulo declare sus dependencias (p. ej. en `metadata.yaml` o `requirements.txt` dentro del módulo) y el core o un script de setup compruebe/instale sin conflictos. Aumenta la robustez en entornos reales.

Prioridad sugerida para innovar: primero **certificación + framework de tests**, luego documentación interactiva y salida estandarizada.

---

## Próximo paso recomendado

Para acercarnos a “ya no se pueda desarrollar más” en el código libre (sin añadir SaaS/auth/pagos/cloud/IA):

1. **Inmediato**: Mantener el core y la CLI como están; usar los ejemplos como referencia.
2. **Corto plazo**:  
   - Auditar scripts por categoría (p. ej. empezar por `exploit`, luego `red`, `blue`, etc.).  
   - Por cada script: cambiar a `--key` en argparse, alinear YAML (`parameters`, `type: string|int|bool`) y códigos de salida.  
   - Opcional: script o doc que liste “scripts compatibles con el core” para ir tachando.
3. **Después**: Introducir una primera innovación (p. ej. “módulo certificado” o “framework de tests para módulos”) y documentarla en este roadmap.

Con esto se consigue que **todo** sea funcional desde el core/CLI y, a la vez, se abre la puerta a diferenciación e innovación de forma ordenada.

---

## Resumen de cambios recientes (esta sesión)

- **ScriptValidator** (`core/utils/script_validator.py`): se aceptan tipos en YAML (`string`, `int`, `bool`, `integer`, `boolean`) además de tipos Python; se mapean internamente a `str`, `int`, `bool` para la validación. Así los YAML con `type: "string"` no rompen la validación.
- **Documento**: creado `docs/NEXT_STEPS_AND_ROADMAP.md` (este archivo) con respuestas y plan.

### Implementación del plan (Fase 1 + Fase 2)

**Fase 1 – Migración de scripts**  
- **exploit**: `cve_2024_springauth_bypass`, `http2_rapid_reset_dos` — argumentos posicionales cambiados a `--target`; `mitre_attack_runner` — argparse con `--technique` y `--list`; YAML alineados.  
- **red**: `quantum_network_infiltrator` — `--target`; `c2_simulator` — `--mode`; YAML con `parameters` en formato dict y tipos string/int/bool.  
- **osint**: `telegram_user_scraper` — `--group`; `github_repo_leak_detector` — `--queries` (string, split en script); `public_email_validator` — `--emails` (string, split); YAML alineados.  
- **recon**: `web_discover.yaml` — añadido bloque `parameters` (url, output) para CLI.

**Fase 2 – BOFA Flow**  
- **Flujos**: `config/flows/recon.yaml` y `config/flows/demo.yaml` — definición de flujos con pasos y placeholder `{target}`.  
- **Flow runner**: `flows/flow_runner.py` — `list_flows()`, `run_flow(flow_id, target)`; usa solo `get_engine()`; genera informe Markdown en `reports/`.  
- **CLI**: opción `F` (Flujos) en el menú principal — listar flujos, pedir flujo + target, ejecutar y mostrar ruta del informe.  
- **Documentación**: `flows/README.md` con uso y formato de flujos.

**Verificación (saber que todo funciona)**  
- Script: `tools/verify_bofa.py`. Modo rápido: `python3 tools/verify_bofa.py`. Modo completo: `--full`. Ver [tools/README.md](../tools/README.md).

Si quieres, el siguiente paso concreto puede ser: (A) definir la plantilla de “migración de un script” y aplicarla a 2–3 scripts como ejemplo, o (B) esbozar el estándar de “módulo certificado” y el framework de tests para módulos.
