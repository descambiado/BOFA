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

| Tecla | Módulo           | Tecla | Acción              |
|-------|------------------|-------|---------------------|
| 1     | Reconocimiento   | A     | Información sistema |
| 2     | Explotación      | C     | Configuración       |
| 3     | OSINT            | 0     | Salir               |
| 4     | Ingeniería Social |       |                     |
| 5     | Blue Team        |       |                     |
| 6     | Análisis Malware |       |                     |
| 7     | Docker Labs      |       |                     |
| 8     | Modo Estudio     |       |                     |
| 9     | Purple Team      |       |                     |
| E     | **Ejemplos**     |       | Módulos de ejemplo  |

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
