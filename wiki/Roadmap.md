# Roadmap

Próximos pasos y direcciones de desarrollo de BOFA.

---

## Objetivo: arsenal completo y de referencia

BOFA aspira a ser el framework de ciberseguridad más completo en un solo proyecto:

- **Más herramientas**: ampliar módulos y scripts (recon, web, binary, cloud, exploit, blue, purple, etc.).
- **Más flujos**: secuencias predefinidas con informes unificados.
- **Inteligencia de vulnerabilidades**: CVE, explotación, plantillas (módulo `vulnerability` ya existe).
- **Reportes estandarizados**: salida JSON/Markdown por script y por flujo.
- **MCP y automatización**: servidor MCP estable para Cursor, Claude, etc.
- **Calidad y extensibilidad**: core estable; certificación de módulos y tests por módulo cuando se definan.

---

## Próximos pasos (prioridad)

1. **Core cerrado**: asegurar que no falte nada en engine, config, logger, module_loader, script_validator.
2. **Ampliar arsenal**: más scripts por categoría (recon, web, exploit, cloud, binary).
3. **Más flujos**: nuevos YAML en `config/flows/` para casos de uso recurrentes.
4. **Inteligencia CVE/exploit**: ampliar módulo `vulnerability` (más entradas, scripts).
5. **Reportes**: seguir la convención REPORTS_CONVENTION; ampliar si hace falta.
6. **Innovación**: checklist de módulo certificado, framework de tests por módulo, documentación interactiva.

---

## Fases estimadas (opcional)

| Fase | Descripción | Esfuerzo |
|------|-------------|----------|
| Compatibilidad de scripts | Revisar cada script: `--key`, YAML, códigos de salida | Alto |
| Tests automatizados | Core + smoke (listar módulos, ejecutar ejemplo) | Medio |
| Innovación 1 | Módulo certificado o framework de tests por módulo | Medio |
| Innovación 2 | Documentación interactiva o salida JSON/MD estandarizada | Medio |
| API y frontend | Verificar que usen el mismo core y contratos | Medio |

---

## Diferenciación

- **Core como framework**, no solo colección de scripts.
- **Añadir módulos sin tocar el core**: descubrimiento automático en `scripts/<módulo>/`.
- **Contrato explícito** (docs, YAML, parámetros `--key`).
- **Enfoque educativo y operativo** en la misma base.
- **Local-first, extensible**: CLI, agente, MCP opcional.
- **Servidor MCP**: integración con Cursor, Claude Desktop y otros clientes MCP.

---

[← Status](Status) · [Home](Home)
