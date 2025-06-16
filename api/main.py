
"""
BOFA API - Best Of All Backend
Desarrollado por @descambiado (David Hernández Jiménez)
FastAPI Backend para la suite de ciberseguridad BOFA
"""

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import os
import json
import subprocess
import shlex
from datetime import datetime
import asyncio

# Configuración de la aplicación
app = FastAPI(
    title="BOFA API",
    description="API Backend para la suite de ciberseguridad BOFA - Desarrollado por @descambiado",
    version="1.0.0",
    contact={
        "name": "David Hernández Jiménez (@descambiado)",
        "email": "david@descambiado.com",
        "url": "https://github.com/descambiado"
    },
    license_info={
        "name": "MIT",
        "url": "https://opensource.org/licenses/MIT"
    }
)

# Configuración CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # En producción, especificar dominios exactos
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ruta base de scripts
SCRIPTS_BASE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")

# Modelos Pydantic
class ScriptInfo(BaseModel):
    name: str
    description: str
    category: str
    author: str = "@descambiado"
    version: str = "1.0.0"
    last_updated: str

class ModuleInfo(BaseModel):
    name: str
    description: str
    icon: str
    script_count: int
    scripts: List[ScriptInfo]

class SystemStatus(BaseModel):
    status: str
    version: str
    uptime: str
    modules_active: int
    scripts_available: int
    developer: str

class ScriptExecutionRequest(BaseModel):
    parameters: Optional[Dict[str, str]] = {}
    timeout: Optional[int] = 60

class ScriptExecutionResponse(BaseModel):
    status: str
    message: str
    module: str
    script: str
    execution_time: str
    output: Optional[str] = None
    error: Optional[str] = None
    return_code: Optional[int] = None
    timestamp: str

# ... keep existing code (MODULES_DATA dictionary and basic endpoints)

# Datos de ejemplo (en producción, estos vendrían de una base de datos)
MODULES_DATA = {
    "recon": {
        "name": "Reconocimiento",
        "description": "Herramientas de reconocimiento y enumeración",
        "icon": "🕵️",
        "scripts": [
            {
                "name": "web_discover.py",
                "description": "Descubrimiento automático de servicios web",
                "category": "recon",
                "version": "1.0.0",
                "last_updated": "2024-01-15"
            },
            {
                "name": "port_slayer.sh",
                "description": "Escaneo de puertos avanzado con Nmap",
                "category": "recon",
                "version": "1.0.0",
                "last_updated": "2024-01-15"
            }
        ]
    },
    "exploit": {
        "name": "Explotación",
        "description": "Herramientas de explotación y post-explotación",
        "icon": "💥",
        "scripts": [
            {
                "name": "reverse_shell_generator.py",
                "description": "Generador de reverse shells multiplataforma",
                "category": "exploit",
                "version": "1.0.0",
                "last_updated": "2024-01-15"
            }
        ]
    },
    "osint": {
        "name": "OSINT",
        "description": "Inteligencia de fuentes abiertas",
        "icon": "🔍",
        "scripts": [
            {
                "name": "social_profile_mapper.py",
                "description": "Mapeo automático de perfiles sociales",
                "category": "osint",
                "version": "1.0.0",
                "last_updated": "2024-01-15"
            }
        ]
    },
    "blue": {
        "name": "Blue Team",
        "description": "Herramientas de defensa y monitoreo",
        "icon": "🛡️",
        "scripts": [
            {
                "name": "log_guardian.py",
                "description": "Monitor avanzado de logs del sistema",
                "category": "blue",
                "version": "1.0.0",
                "last_updated": "2024-01-15"
            }
        ]
    }
}

def validate_script_path(module_id: str, script_name: str) -> str:
    """Valida y construye la ruta segura del script"""
    # Validar que el módulo existe
    if module_id not in MODULES_DATA:
        raise HTTPException(status_code=404, detail="Módulo no encontrado")
    
    # Verificar que el script existe en el módulo
    script_found = False
    for script in MODULES_DATA[module_id]["scripts"]:
        if script["name"] == script_name:
            script_found = True
            break
    
    if not script_found:
        raise HTTPException(status_code=404, detail="Script no encontrado")
    
    # Construir ruta del script
    script_path = os.path.join(SCRIPTS_BASE_PATH, module_id, script_name)
    
    # Validación de seguridad: verificar que la ruta está dentro del directorio permitido
    if not script_path.startswith(SCRIPTS_BASE_PATH):
        raise HTTPException(status_code=403, detail="Ruta de script no permitida")
    
    # Verificar que el archivo existe
    if not os.path.exists(script_path):
        raise HTTPException(status_code=404, detail="Archivo de script no encontrado")
    
    return script_path

def build_script_command(script_path: str, parameters: Dict[str, str]) -> List[str]:
    """Construye el comando para ejecutar el script con parámetros"""
    cmd = []
    
    if script_path.endswith('.py'):
        cmd = ['python3', script_path]
    elif script_path.endswith('.sh'):
        cmd = ['bash', script_path]
    else:
        cmd = [script_path]
    
    # Añadir parámetros de forma segura
    for key, value in parameters.items():
        if key and value:
            # Sanitizar parámetros
            key = shlex.quote(str(key))
            value = shlex.quote(str(value))
            cmd.extend([key, value])
    
    return cmd

async def execute_script_safely(cmd: List[str], timeout: int = 60) -> Dict[str, Any]:
    """Ejecuta un script de forma segura con timeout"""
    try:
        start_time = datetime.now()
        
        # Ejecutar el comando
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=os.path.dirname(cmd[1]) if len(cmd) > 1 else None
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=timeout
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise HTTPException(status_code=408, detail="Timeout de ejecución alcanzado")
        
        end_time = datetime.now()
        execution_time = str(end_time - start_time)
        
        return {
            "return_code": process.returncode,
            "stdout": stdout.decode('utf-8', errors='replace') if stdout else "",
            "stderr": stderr.decode('utf-8', errors='replace') if stderr else "",
            "execution_time": execution_time
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error durante la ejecución: {str(e)}")

# Endpoints principales
@app.get("/", response_model=Dict[str, Any])
async def read_root():
    """Endpoint raíz con información básica de la API"""
    return {
        "message": "🛡️ BOFA API - Best Of All Suite",
        "description": "API Backend para la suite de ciberseguridad profesional",
        "developer": "@descambiado (David Hernández Jiménez)",
        "version": "1.0.0",
        "status": "active",
        "docs": "/docs",
        "modules": len(MODULES_DATA),
        "timestamp": datetime.now().isoformat()
    }

@app.get("/health")
async def health_check():
    """Endpoint de verificación de salud del servicio"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "BOFA API",
        "scripts_path": SCRIPTS_BASE_PATH
    }

@app.get("/modules", response_model=List[Dict[str, Any]])
async def get_modules():
    """Obtener lista de todos los módulos disponibles"""
    modules = []
    for module_id, module_data in MODULES_DATA.items():
        modules.append({
            "id": module_id,
            "name": module_data["name"],
            "description": module_data["description"],
            "icon": module_data["icon"],
            "script_count": len(module_data["scripts"])
        })
    return modules

@app.get("/modules/{module_id}", response_model=Dict[str, Any])
async def get_module_detail(module_id: str):
    """Obtener detalles de un módulo específico"""
    if module_id not in MODULES_DATA:
        raise HTTPException(status_code=404, detail="Módulo no encontrado")
    
    module_data = MODULES_DATA[module_id]
    return {
        "id": module_id,
        "name": module_data["name"],
        "description": module_data["description"],
        "icon": module_data["icon"],
        "scripts": module_data["scripts"]
    }

@app.get("/scripts", response_model=List[ScriptInfo])
async def get_all_scripts():
    """Obtener lista de todos los scripts disponibles"""
    all_scripts = []
    for module_data in MODULES_DATA.values():
        all_scripts.extend(module_data["scripts"])
    return all_scripts

@app.get("/scripts/{module_id}", response_model=List[ScriptInfo])
async def get_scripts_by_module(module_id: str):
    """Obtener scripts de un módulo específico"""
    if module_id not in MODULES_DATA:
        raise HTTPException(status_code=404, detail="Módulo no encontrado")
    
    return MODULES_DATA[module_id]["scripts"]

@app.post("/scripts/{module_id}/{script_name}/execute", response_model=ScriptExecutionResponse)
async def execute_script(
    module_id: str, 
    script_name: str, 
    request: ScriptExecutionRequest = ScriptExecutionRequest()
):
    """Ejecutar un script real del sistema"""
    try:
        # Validar ruta del script
        script_path = validate_script_path(module_id, script_name)
        
        # Verificar permisos de ejecución
        if not os.access(script_path, os.X_OK):
            try:
                os.chmod(script_path, 0o755)
            except Exception as e:
                raise HTTPException(status_code=403, detail=f"No se pueden establecer permisos de ejecución: {str(e)}")
        
        # Construir comando
        cmd = build_script_command(script_path, request.parameters)
        
        # Ejecutar script
        result = await execute_script_safely(cmd, request.timeout)
        
        # Determinar estado basado en el código de retorno
        status = "success" if result["return_code"] == 0 else "warning"
        message = f"Script {script_name} ejecutado"
        
        if result["return_code"] != 0:
            message += f" con código de salida {result['return_code']}"
        
        return ScriptExecutionResponse(
            status=status,
            message=message,
            module=module_id,
            script=script_name,
            execution_time=result["execution_time"],
            output=result["stdout"] if result["stdout"] else None,
            error=result["stderr"] if result["stderr"] else None,
            return_code=result["return_code"],
            timestamp=datetime.now().isoformat()
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error inesperado: {str(e)}")

@app.get("/stats", response_model=SystemStatus)
async def get_system_stats():
    """Obtener estadísticas del sistema"""
    total_scripts = sum(len(module["scripts"]) for module in MODULES_DATA.values())
    
    return SystemStatus(
        status="operational",
        version="1.0.0",
        uptime="24h 15m",
        modules_active=len(MODULES_DATA),
        scripts_available=total_scripts,
        developer="@descambiado"
    )

@app.get("/search/{query}")
async def search_scripts(query: str):
    """Buscar scripts por nombre o descripción"""
    results = []
    query_lower = query.lower()
    
    for module_id, module_data in MODULES_DATA.items():
        for script in module_data["scripts"]:
            if (query_lower in script["name"].lower() or 
                query_lower in script["description"].lower()):
                results.append({
                    **script,
                    "module_id": module_id,
                    "module_name": module_data["name"]
                })
    
    return {
        "query": query,
        "results_count": len(results),
        "results": results
    }

# Manejo de errores
@app.exception_handler(404)
async def not_found_handler(request, exc):
    return JSONResponse(
        status_code=404,
        content={
            "error": "Recurso no encontrado",
            "message": "El recurso solicitado no existe en BOFA API",
            "developer": "@descambiado"
        }
    )

@app.exception_handler(500)
async def internal_error_handler(request, exc):
    return JSONResponse(
        status_code=500,
        content={
            "error": "Error interno del servidor",
            "message": "Ha ocurrido un error interno en BOFA API",
            "contact": "david@descambiado.com"
        }
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
