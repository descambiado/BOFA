# 💻 BOFA CLI

Interfaz de línea de comandos de BOFA. **Solo capa de presentación** sobre el core: descubre módulos y ejecuta scripts mediante el core engine.

## 🚀 Uso

### Desde el directorio raíz del proyecto

```bash
# Opción recomendada
./bofa.sh

# O directamente con Python
python3 cli/bofa_cli.py
```

### Con pip (instalación editable)

```bash
pip install -e .
bofa-cli
```

## 📋 Menú principal

El menú muestra los **primeros 9 módulos** descubiertos por el core (orden alfabético). El resto se accede con **L**.

| Tecla | Acción |
|-------|--------|
| 1-9   | Primeros 9 módulos (recon, exploit, cloud, etc.) |
| **L** | Listar **todos** los módulos y elegir uno |
| **H** | Ayuda (atajos y comandos directos: run_agent, verify_bofa) |
| A     | Información del sistema |
| C     | Configuración |
| F     | Flujos (ejecutar + informe) |
| 0     | Salir |

## 🔧 Requisitos

- Python 3.8+
- Dependencias: `pip install -r cli/requirements.txt`
- Ejecutar **desde el directorio raíz** del repo (para que el core encuentre `scripts/` y `core/`)

## 📁 Estructura

- `bofa_cli.py` — Punto de entrada. Solo UI y delegación al core.
- `os_detector.py` — Detección de SO (Windows/WSL/Linux) para ejecución de scripts.
- `requirements.txt` — Dependencias de la CLI (colorama, etc.).

El core (`core/`) se importa desde la raíz del proyecto; no se modifica desde la CLI.

## ✅ Comportamiento

1. **Inicio**: Añade la raíz del proyecto al `PATH` e importa el core.
2. **Menú**: Muestra opciones fijas; los módulos reales los descubre el core en `scripts/`.
3. **Ejecución**: Al elegir módulo y script, la CLI pide parámetros (según el YAML del script) y llama a `engine.execute_script()`.
4. **Salida**: Muestra stdout/stderr y código de salida que devuelve el core.

No se añade lógica de negocio en la CLI: descubrimiento, validación y ejecución son responsabilidad del core.

## 📖 Documentación relacionada

- [Contrato Core–Módulos](../docs/MODULE_CONTRACT.md)
- [Arquitectura del Core](../docs/CORE_ARCHITECTURE.md)
- [Módulos de ejemplo](../scripts/examples/README.md)
