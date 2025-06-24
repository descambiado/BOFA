
# 📊 BOFA Reports - Sistema de Reportes Profesionales

## 🎯 Descripción
Sistema automatizado de generación de reportes para BOFA v2.3.0 que permite exportar ejecuciones de scripts en múltiples formatos: PDF, Markdown y JSON.

## 📁 Estructura
```
reports/
├── pdf/           # Reportes en formato PDF
├── markdown/      # Reportes en formato Markdown  
├── json/          # Reportes en formato JSON
└── README.md      # Esta documentación
```

## 💻 Uso desde CLI
```bash
# Generar reporte de la última ejecución
bofa report --last

# Generar reporte específico en PDF
bofa report --module exploit --output pdf

# Generar reporte con ID específico
bofa report --execution-id 20250619_143022_exploit_cve_test
```

## 🌐 Uso desde Web
1. Ejecuta cualquier script desde el panel web
2. Haz clic en "Exportar Reporte 📄" en la consola
3. Selecciona el formato deseado (PDF/Markdown/JSON)
4. Descarga automáticamente desde el navegador

## 🔗 API Endpoints
```bash
# Obtener última ejecución en JSON
GET /reports/latest

# Descargar reporte en PDF
GET /reports/pdf?execution_id=<ID>

# Obtener metadatos de reportes
GET /reports/list
```

## 📋 Contenido de Reportes
Cada reporte incluye:
- **Metadatos**: Nombre, categoría, autor del script
- **Timestamp**: Fecha y hora de ejecución
- **Parámetros**: Configuración utilizada
- **Resultados**: Output completo del script
- **Errores**: Stderr si los hubo
- **Duración**: Tiempo de ejecución
- **Nivel de riesgo**: Clasificación de seguridad
- **Origen**: CLI/API/Web
- **Firma**: Desarrollado por @descambiado

## 🛠️ Dependencias
- reportlab (para PDFs)
- markdown (para conversión MD)
- json (nativo Python)

## 👨‍💻 Desarrollado por
@descambiado (David Hernández Jiménez)
BOFA v2.3.0 - Professional Security Suite
