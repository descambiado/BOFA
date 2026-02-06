# Convención de reportes BOFA

Cómo se generan y estructuran los reportes en BOFA (flujos y scripts).

---

## Reportes de flujos (BOFA Flow)

Los flujos generan informes en **Markdown** en el directorio `reports/`.

- **Ruta**: `reports/flow_{flow_id}_{timestamp}.md`
- **Estructura**:
  - Título: `# BOFA Flow Report: {nombre_flujo}`
  - Metadatos: Target, Status, Timestamp
  - Sección **Steps**: por cada paso, módulo/script, status, exit code, duration, stdout/stderr (preview), error si aplica

El flow runner escribe este Markdown automáticamente; no hace falta que los scripts lo generen.

---

## Salida de scripts

Los scripts pueden emitir salida libre por stdout/stderr. Opcionalmente pueden seguir una convención para facilitar agregación o parsing:

### Opcional: JSON estructurado

Si un script quiere salida máquina-parseable, puede imprimir un único objeto JSON por ejecución, por ejemplo:

```json
{
  "status": "ok",
  "module": "nombre_modulo",
  "script": "nombre_script",
  "data": { ... },
  "summary": "Resumen breve"
}
```

- `status`: `"ok"` | `"error"` | `"partial"`
- `data`: objeto libre con resultados
- `summary`: texto breve para logs o resúmenes

No es obligatorio; el core no valida este formato. Es una convención para scripts que quieran interoperar con reportes agregados.

### Opcional: Markdown

Un script puede emitir Markdown en stdout (encabezados, listas, bloques de código). El flow runner ya captura stdout y lo incluye como preview en el informe del flujo.

---

## Resumen

| Origen        | Formato   | Dónde                    |
|---------------|-----------|--------------------------|
| Flujos        | Markdown  | `reports/flow_*.md`      |
| Scripts       | Libre     | stdout/stderr            |
| Scripts (opt) | JSON/MD   | stdout (convención propia) |
