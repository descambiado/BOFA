# Responsabilidades del Core de BOFA

Este documento define claramente las responsabilidades de cada componente del core.

## 📦 Componentes y sus Responsabilidades

### `core/engine/` - Motor Central

**Responsabilidad única**: Orquestar la ejecución de scripts y gestionar el ciclo de vida de módulos.

**Hace**:
- Descubre y carga módulos automáticamente
- Valida scripts antes de ejecutar
- Ejecuta scripts con control de timeout
- Gestiona resultados de ejecución
- Proporciona interfaz unificada para operaciones del framework

**NO hace**:
- No carga configuración (delega a `core/config`)
- No hace logging directo (usa `core/logger`)
- No valida parámetros en detalle (delega a `core/utils/script_validator`)
- No carga módulos directamente (delega a `core/utils/module_loader`)

### `core/config/` - Configuración

**Responsabilidad única**: Gestionar toda la configuración del framework desde múltiples fuentes.

**Hace**:
- Carga configuración desde variables de entorno
- Carga configuración desde archivos YAML/JSON
- Proporciona valores por defecto
- Gestiona prioridad de fuentes (env > file > defaults)
- Crea directorios necesarios automáticamente

**NO hace**:
- No valida configuración (solo carga)
- No gestiona ejecución
- No hace logging

### `core/logger/` - Logging

**Responsabilidad única**: Proporcionar logging estructurado y consistente.

**Hace**:
- Configura sistema de logging global
- Proporciona formateadores JSON y texto
- Gestiona colores en consola
- Gestiona archivos rotativos
- Permite contexto adicional en logs

**NO hace**:
- No decide qué loguear (eso lo hace el código que usa el logger)
- No gestiona configuración (lee de `core/config`)

### `core/errors/` - Manejo de Errores

**Responsabilidad única**: Definir excepciones específicas del framework.

**Hace**:
- Define jerarquía de excepciones
- Proporciona mensajes descriptivos
- Permite detalles adicionales en errores
- Serializa errores a diccionarios

**NO hace**:
- No maneja errores (solo los define)
- No loguea errores (el código que captura lo hace)

### `core/utils/` - Utilidades

#### `module_loader.py`

**Responsabilidad única**: Descubrir y cargar información de módulos y scripts.

**Hace**:
- Escanea directorio de scripts
- Carga metadata de módulos (metadata.yaml)
- Carga configuración de scripts (script.yaml)
- Proporciona información estructurada de módulos/scripts

**NO hace**:
- No ejecuta scripts
- No valida scripts (solo carga información)

#### `script_validator.py`

**Responsabilidad única**: Validar scripts y sus parámetros.

**Hace**:
- Valida que scripts existan
- Valida que scripts sean ejecutables
- Valida parámetros contra especificación

**NO hace**:
- No ejecuta scripts
- No carga información de scripts (usa `module_loader`)

#### `path_utils.py`

**Responsabilidad única**: Utilidades de rutas y archivos.

**Hace**:
- Construye rutas a scripts
- Asegura que directorios existan
- Busca archivos de configuración

**NO hace**:
- No valida contenido
- No carga archivos

## 🔄 Flujo de Responsabilidades

### Ejecutar un Script

1. **Engine** recibe solicitud de ejecución
2. **Engine** usa **ModuleLoader** para obtener información del script
3. **Engine** usa **ScriptValidator** para validar script y parámetros
4. **Engine** ejecuta script usando subprocess
5. **Engine** usa **Logger** para registrar ejecución
6. Si hay error, **Engine** lanza excepción de **Errors**

### Cargar Configuración

1. **ConfigManager** busca archivo de configuración
2. **ConfigManager** carga desde archivo (si existe)
3. **ConfigManager** sobrescribe con variables de entorno
4. **ConfigManager** retorna **BOFAConfig** con valores finales

### Descubrir Módulos

1. **ModuleLoader** escanea `scripts/`
2. Para cada directorio, busca `metadata.yaml`
3. Para cada `.py`, busca `script.yaml`
4. Construye **ModuleInfo** y **ScriptInfo**
5. Retorna diccionario de módulos

## ✅ Principios de Diseño

1. **Separación de responsabilidades**: Cada componente tiene una responsabilidad única
2. **Composición sobre herencia**: Los componentes se componen, no heredan
3. **Dependencias unidireccionales**: El core no depende de módulos externos
4. **Interfaces claras**: Cada componente expone una API simple y clara
5. **Sin efectos secundarios**: Los componentes son predecibles

## 🚫 Anti-patrones Evitados

- ❌ Componentes que hacen demasiadas cosas
- ❌ Dependencias circulares
- ❌ Lógica de negocio en utilidades
- ❌ Configuración hardcodeada
- ❌ Logging directo sin usar el logger del core
