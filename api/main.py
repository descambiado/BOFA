
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
import yaml
import glob

# Configuración de la aplicación
app = FastAPI(
    title="BOFA API",
    description="API Backend para la suite de ciberseguridad BOFA - Desarrollado por @descambiado",
    version="2.2.0",
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

# Rutas base
SCRIPTS_BASE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
LOGS_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")

# Crear directorio de logs si no existe
os.makedirs(LOGS_PATH, exist_ok=True)

# Modelos Pydantic
class ScriptInfo(BaseModel):
    name: str
    description: str
    category: str
    author: str = "@descambiado"
    version: str = "1.0.0"
    last_updated: str
    impact_level: Optional[str] = None
    educational_value: Optional[int] = None
    required_privileges: Optional[str] = None

class ModuleInfo(BaseModel):
    name: str
    description: str
    icon: str
    script_count: int
    scripts: List[ScriptInfo]

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

class ExecutionHistory(BaseModel):
    id: str
    module: str
    script: str
    parameters: Dict[str, str]
    timestamp: str
    status: str
    execution_time: str
    output: Optional[str] = None
    error: Optional[str] = None

def load_scripts_from_yaml() -> Dict[str, Any]:
    """Carga dinámicamente todos los scripts desde archivos YAML"""
    modules_data = {}
    
    # Mapeo de categorías a nombres y descripciones
    category_mapping = {
        "red": {"name": "Red Team", "description": "Arsenal ofensivo avanzado y técnicas de penetración", "icon": "🔴"},
        "blue": {"name": "Blue Team", "description": "Herramientas defensivas, monitoreo y análisis forense", "icon": "🔵"},
        "purple": {"name": "Purple Team", "description": "Ejercicios coordinados de ataque y defensa", "icon": "🟣"},
        "recon": {"name": "Reconocimiento", "description": "Herramientas de descubrimiento y enumeración", "icon": "🕵️"},
        "osint": {"name": "OSINT", "description": "Inteligencia de fuentes abiertas", "icon": "🔍"},
        "forensics": {"name": "Análisis Forense", "description": "Investigación digital y análisis de evidencia", "icon": "🧪"},
        "study": {"name": "Modo Estudio", "description": "Lecciones interactivas y entrenamiento", "icon": "🎓"},
        "mobile": {"name": "Mobile Stinger", "description": "Herramientas móviles y testing wireless", "icon": "📱"}
    }
    
    # Buscar todos los archivos YAML en subcarpetas
    yaml_pattern = os.path.join(SCRIPTS_BASE_PATH, "**", "*.yaml")
    yaml_files = glob.glob(yaml_pattern, recursive=True)
    
    for yaml_file in yaml_files:
        try:
            with open(yaml_file, 'r', encoding='utf-8') as f:
                script_data = yaml.safe_load(f)
            
            if not script_data or 'name' not in script_data:
                continue
                
            # Determinar categoría desde la ruta del archivo
            relative_path = os.path.relpath(yaml_file, SCRIPTS_BASE_PATH)
            category = relative_path.split(os.sep)[0]
            
            # Inicializar módulo si no existe
            if category not in modules_data:
                module_info = category_mapping.get(category, {
                    "name": category.title(),
                    "description": f"Herramientas de {category}",
                    "icon": "🔧"
                })
                modules_data[category] = {
                    "name": module_info["name"],
                    "description": module_info["description"],
                    "icon": module_info["icon"],
                    "scripts": []
                }
            
            # Añadir script al módulo
            script_info = {
                "name": script_data.get("name", "Unknown"),
                "description": script_data.get("description", ""),
                "category": category,
                "author": script_data.get("author", "@descambiado"),
                "version": script_data.get("version", "1.0"),
                "last_updated": script_data.get("last_updated", "2025-06-19"),
                "impact_level": script_data.get("impact_level"),
                "educational_value": script_data.get("educational_value"),
                "required_privileges": script_data.get("required_privileges")
            }
            
            modules_data[category]["scripts"].append(script_info)
            
        except Exception as e:
            print(f"Error cargando {yaml_file}: {e}")
            continue
    
    return modules_data

def log_execution(module: str, script: str, parameters: Dict[str, str], 
                 result: Dict[str, Any]) -> str:
    """Registra la ejecución en el archivo de logs"""
    execution_id = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{module}_{script}"
    
    log_entry = {
        "id": execution_id,
        "module": module,
        "script": script,
        "parameters": parameters,
        "timestamp": datetime.now().isoformat(),
        "status": result.get("status", "unknown"),
        "execution_time": result.get("execution_time", "0s"),
        "return_code": result.get("return_code"),
        "output": result.get("stdout", ""),
        "error": result.get("stderr", "")
    }
    
    # Guardar en archivo de logs
    log_file = os.path.join(LOGS_PATH, "executions.log")
    try:
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
    except Exception as e:
        print(f"Error guardando log: {e}")
    
    return execution_id

def load_execution_history() -> List[ExecutionHistory]:
    """Carga el historial de ejecuciones desde el archivo de logs"""
    log_file = os.path.join(LOGS_PATH, "executions.log")
    history = []
    
    if not os.path.exists(log_file):
        return history
    
    try:
        with open(log_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        log_entry = json.loads(line.strip())
                        history.append(ExecutionHistory(**log_entry))
                    except json.JSONDecodeError:
                        continue
    except Exception as e:
        print(f"Error cargando historial: {e}")
    
    # Ordenar por timestamp descendente (más reciente primero)
    history.sort(key=lambda x: x.timestamp, reverse=True)
    return history

# ... keep existing code (validate_script_path, build_script_command, execute_script_safely functions)

def validate_script_path(module_id: str, script_name: str) -> str:
    """Valida y construye la ruta segura del script"""
    modules_data = load_scripts_from_yaml()
    
    # Validar que el módulo existe
    if module_id not in modules_data:
        raise HTTPException(status_code=404, detail="Módulo no encontrado")
    
    # Verificar que el script existe en el módulo
    script_found = False
    for script in modules_data[module_id]["scripts"]:
        if script["name"] == script_name:
            script_found = True
            break
    
    if not script_found:
        raise HTTPException(status_code=404, detail="Script no encontrado")
    
    # Buscar archivo del script (Python o Shell)
    script_base_name = script_name.replace('.py', '').replace('.sh', '')
    possible_extensions = ['.py', '.sh', '.ps1']
    
    script_path = None
    for ext in possible_extensions:
        potential_path = os.path.join(SCRIPTS_BASE_PATH, module_id, script_base_name + ext)
        if os.path.exists(potential_path):
            script_path = potential_path
            break
    
    if not script_path:
        raise HTTPException(status_code=404, detail="Archivo de script no encontrado")
    
    # Validación de seguridad
    if not script_path.startswith(SCRIPTS_BASE_PATH):
        raise HTTPException(status_code=403, detail="Ruta de script no permitida")
    
    return script_path

def build_script_command(script_path: str, parameters: Dict[str, str]) -> List[str]:
    """Construye el comando para ejecutar el script con parámetros"""
    cmd = []
    
    if script_path.endswith('.py'):
        cmd = ['python3', script_path]
    elif script_path.endswith('.sh'):
        cmd = ['bash', script_path]
    elif script_path.endswith('.ps1'):
        cmd = ['powershell', '-File', script_path]
    else:
        cmd = [script_path]
    
    # Añadir parámetros de forma segura
    for key, value in parameters.items():
        if key and value:
            key = shlex.quote(str(key))
            value = shlex.quote(str(value))
            cmd.extend([f"--{key}", value])
    
    return cmd

async def execute_script_safely(cmd: List[str], timeout: int = 60) -> Dict[str, Any]:
    """Ejecuta un script de forma segura con timeout"""
    try:
        start_time = datetime.now()
        
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
            "execution_time": execution_time,
            "status": "success" if process.returncode == 0 else "error"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error durante la ejecución: {str(e)}")

# Endpoints principales
@app.get("/", response_model=Dict[str, Any])
async def read_root():
    """Endpoint raíz con información básica de la API"""
    return {
        "message": "🛡️ BOFA API v2.2.0 - Best Of All Suite",
        "description": "API Backend consolidado para la suite de ciberseguridad profesional",
        "developer": "@descambiado (David Hernández Jiménez)",
        "version": "2.2.0",
        "status": "active",
        "docs": "/docs",
        "modules": len(load_scripts_from_yaml()),
        "features": ["Dynamic YAML Loading", "Execution History", "Persistent Logging"],
        "timestamp": datetime.now().isoformat()
    }

@app.get("/health")
async def health_check():
    """Endpoint de verificación de salud del servicio"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "BOFA API v2.2.0",
        "scripts_path": SCRIPTS_BASE_PATH,
        "logs_path": LOGS_PATH
    }

@app.get("/modules", response_model=List[Dict[str, Any]])
async def get_modules():
    """Obtener lista de todos los módulos disponibles (carga dinámica)"""
    modules_data = load_scripts_from_yaml()
    modules = []
    
    for module_id, module_data in modules_data.items():
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
    modules_data = load_scripts_from_yaml()
    
    if module_id not in modules_data:
        raise HTTPException(status_code=404, detail="Módulo no encontrado")
    
    module_data = modules_data[module_id]
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
    modules_data = load_scripts_from_yaml()
    all_scripts = []
    
    for module_data in modules_data.values():
        all_scripts.extend(module_data["scripts"])
    
    return all_scripts

@app.get("/scripts/{module_id}", response_model=List[ScriptInfo])
async def get_scripts_by_module(module_id: str):
    """Obtener scripts de un módulo específico"""
    modules_data = load_scripts_from_yaml()
    
    if module_id not in modules_data:
        raise HTTPException(status_code=404, detail="Módulo no encontrado")
    
    return modules_data[module_id]["scripts"]

@app.post("/scripts/{module_id}/{script_name}/execute", response_model=ScriptExecutionResponse)
async def execute_script(
    module_id: str, 
    script_name: str, 
    request: ScriptExecutionRequest = ScriptExecutionRequest()
):
    """Ejecutar un script real del sistema con logging persistente"""
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
        
        # Registrar ejecución en logs
        execution_id = log_execution(module_id, script_name, request.parameters, result)
        
        # Determinar estado
        status = "success" if result["return_code"] == 0 else "warning"
        message = f"Script {script_name} ejecutado (ID: {execution_id})"
        
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

@app.get("/history", response_model=List[ExecutionHistory])
async def get_execution_history():
    """Obtener historial de ejecuciones de scripts"""
    return load_execution_history()

@app.get("/history/{execution_id}", response_model=ExecutionHistory)
async def get_execution_detail(execution_id: str):
    """Obtener detalles de una ejecución específica"""
    history = load_execution_history()
    
    for execution in history:
        if execution.id == execution_id:
            return execution
    
    raise HTTPException(status_code=404, detail="Ejecución no encontrada")

@app.get("/stats", response_model=Dict[str, Any])
async def get_system_stats():
    """Obtener estadísticas del sistema"""
    modules_data = load_scripts_from_yaml()
    history = load_execution_history()
    
    total_scripts = sum(len(module["scripts"]) for module in modules_data.values())
    
    return {
        "status": "operational",
        "version": "2.2.0",
        "uptime": "24h 15m",
        "modules_active": len(modules_data),
        "scripts_available": total_scripts,
        "total_executions": len(history),
        "developer": "@descambiado",
        "features": ["Dynamic Loading", "Persistent Logging", "History Tracking"]
    }

@app.get("/search/{query}")
async def search_scripts(query: str):
    """Buscar scripts por nombre o descripción"""
    modules_data = load_scripts_from_yaml()
    results = []
    query_lower = query.lower()
    
    for module_id, module_data in modules_data.items():
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
            "message": "El recurso solicitado no existe en BOFA API v2.2.0",
            "developer": "@descambiado"
        }
    )

@app.exception_handler(500)
async def internal_error_handler(request, exc):
    return JSONResponse(
        status_code=500,
        content={
            "error": "Error interno del servidor",
            "message": "Ha ocurrido un error interno en BOFA API v2.2.0",
            "contact": "david@descambiado.com"
        }
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
