
#!/usr/bin/env python3
"""
BOFA Extended Systems v2.5.0 - Main API
Fast API backend for cybersecurity platform
"""

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import uvicorn
import os
import sys
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
import yaml
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/api.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Initialize FastAPI
app = FastAPI(
    title="BOFA Extended Systems API",
    description="Cybersecurity Platform API v2.5.0 with 2025 Technologies",
    version="2.5.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# Data Models
class ScriptExecution:
    def __init__(self, module: str, script: str, parameters: Dict[str, Any]):
        self.id = f"exec-{datetime.now().timestamp()}"
        self.module = module
        self.script = script
        self.parameters = parameters
        self.timestamp = datetime.now().isoformat()
        self.status = "running"
        self.output = ""
        self.execution_time = "0s"

# Storage (In production, use proper database)
executions_history = []
active_labs = {}

def load_script_configs():
    """Load script configurations from YAML files"""
    scripts_dir = Path("/app/scripts")
    configs = {}
    
    for module_dir in scripts_dir.iterdir():
        if module_dir.is_dir():
            module_name = module_dir.name
            configs[module_name] = []
            
            for script_file in module_dir.glob("*.yaml"):
                try:
                    with open(script_file, 'r', encoding='utf-8') as f:
                        script_config = yaml.safe_load(f)
                        script_config['file_path'] = str(script_file)
                        configs[module_name].append(script_config)
                except Exception as e:
                    logger.error(f"Error loading {script_file}: {e}")
    
    return configs

# Load configurations at startup
SCRIPT_CONFIGS = load_script_configs()

@app.on_event("startup")
async def startup_event():
    """Initialize application on startup"""
    logger.info("🚀 BOFA Extended Systems v2.5.0 API Starting...")
    logger.info(f"📁 Scripts loaded from {len(SCRIPT_CONFIGS)} modules")
    
    # Create necessary directories
    os.makedirs("/app/logs", exist_ok=True)
    os.makedirs("/app/uploads", exist_ok=True)
    os.makedirs("/app/temp", exist_ok=True)
    
    logger.info("✅ BOFA API Ready!")

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": "BOFA Extended Systems API",
        "version": "2.5.0",
        "status": "operational",
        "timestamp": datetime.now().isoformat(),
        "features": [
            "AI/ML Integration",
            "Post-Quantum Ready", 
            "Supply Chain Security",
            "Zero Trust Validation",
            "Cloud Native Attacks",
            "Deepfake Detection",
            "IoT Security Mapping"
        ]
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "2.5.0",
        "uptime": "operational"
    }

@app.get("/modules")
async def get_modules():
    """Get available modules"""
    modules = []
    
    module_descriptions = {
        "red": {
            "name": "Red Team",
            "description": "Arsenal ofensivo avanzado + Supply Chain + Cloud Native",
            "icon": "terminal"
        },
        "blue": {
            "name": "Blue Team", 
            "description": "Defensiva + AI Threat Hunting + Zero Trust",
            "icon": "shield"
        },
        "purple": {
            "name": "Purple Team",
            "description": "Coordinado + Quantum-Safe + Behavioral",
            "icon": "users"
        },
        "osint": {
            "name": "OSINT",
            "description": "Intelligence + IoT Mapping + Threat Intel",
            "icon": "search"
        },
        "malware": {
            "name": "Malware Analysis",
            "description": "Análisis estático + IOC extraction + Forensics",
            "icon": "bug"
        },
        "social": {
            "name": "Social Engineering",
            "description": "Concienciación + Phishing + Training",
            "icon": "users"
        },
        "study": {
            "name": "Study & Training",
            "description": "CTF + Educational + Skill Assessment",
            "icon": "book-open"
        }
    }
    
    for module_id, scripts in SCRIPT_CONFIGS.items():
        module_info = module_descriptions.get(module_id, {
            "name": module_id.title(),
            "description": f"Herramientas de {module_id}",
            "icon": "terminal"
        })
        
        modules.append({
            "id": module_id,
            "name": module_info["name"],
            "description": module_info["description"], 
            "icon": module_info["icon"],
            "script_count": len(scripts)
        })
    
    return modules

@app.get("/modules/{module_id}/scripts")
async def get_scripts_by_module(module_id: str):
    """Get scripts for specific module"""
    if module_id not in SCRIPT_CONFIGS:
        raise HTTPException(status_code=404, detail=f"Module {module_id} not found")
    
    return SCRIPT_CONFIGS[module_id]

@app.post("/execute")
async def execute_script(
    background_tasks: BackgroundTasks,
    execution_data: Dict[str, Any]
):
    """Execute a script"""
    module = execution_data.get("module")
    script = execution_data.get("script") 
    parameters = execution_data.get("parameters", {})
    
    if not module or not script:
        raise HTTPException(status_code=400, detail="Module and script are required")
    
    # Create execution record
    execution = ScriptExecution(module, script, parameters)
    executions_history.append(execution)
    
    # Simulate script execution (in production, run actual scripts)
    execution.status = "success"
    execution.execution_time = "3.2s"
    execution.output = f"Script {script} executed successfully with parameters: {parameters}"
    
    logger.info(f"🔧 Executed {module}/{script} with params: {parameters}")
    
    return {
        "id": execution.id,
        "module": execution.module,
        "script": execution.script,
        "parameters": execution.parameters,
        "timestamp": execution.timestamp,
        "status": execution.status,
        "execution_time": execution.execution_time,
        "output": execution.output
    }

@app.get("/history")
async def get_execution_history():
    """Get execution history"""
    history = []
    for exec in executions_history[-50:]:  # Last 50 executions
        history.append({
            "id": exec.id,
            "module": exec.module,
            "script": exec.script,
            "parameters": exec.parameters,
            "timestamp": exec.timestamp,
            "status": exec.status,
            "execution_time": exec.execution_time,
            "output": exec.output[:200] + "..." if len(exec.output) > 200 else exec.output
        })
    
    return sorted(history, key=lambda x: x["timestamp"], reverse=True)

@app.get("/labs")
async def get_labs():
    """Get available labs"""
    labs = [
        {
            "id": "web-application-security",
            "name": "Web Application Security Lab",
            "description": "Laboratorio completo para práctica de vulnerabilidades web (OWASP Top 10)",
            "category": "web_security",
            "difficulty": "intermediate",
            "status": active_labs.get("web-application-security", "stopped"),
            "estimated_time": "240 minutos",
            "port": 8080,
            "url": "http://localhost:8080"
        },
        {
            "id": "kubernetes-cluster",
            "name": "Kubernetes Security Cluster", 
            "description": "Cluster Kubernetes vulnerable para práctica de Cloud Native Security",
            "category": "cloud_native",
            "difficulty": "advanced",
            "status": active_labs.get("kubernetes-cluster", "stopped"),
            "estimated_time": "300 minutos",
            "port": 6443
        },
        {
            "id": "iot-simulation",
            "name": "IoT/OT Simulation Environment",
            "description": "Entorno simulado de dispositivos IoT/OT con protocolos industriales",
            "category": "iot_security", 
            "difficulty": "expert",
            "status": active_labs.get("iot-simulation", "stopped"),
            "estimated_time": "360 minutos",
            "port": 8502
        },
        {
            "id": "android-lab",
            "name": "Android Security Lab",
            "description": "Emulador Android con apps vulnerables para testing móvil",
            "category": "mobile",
            "difficulty": "advanced", 
            "status": active_labs.get("android-lab", "stopped"),
            "estimated_time": "150 minutos",
            "port": 5555
        },
        {
            "id": "internal-network",
            "name": "Red Interna Corporativa",
            "description": "Simula una red corporativa completa con múltiples servicios",
            "category": "network",
            "difficulty": "intermediate",
            "status": active_labs.get("internal-network", "stopped"), 
            "estimated_time": "180 minutos"
        }
    ]
    
    return labs

@app.post("/labs/{lab_id}/start")
async def start_lab(lab_id: str):
    """Start a lab"""
    logger.info(f"🧪 Starting lab: {lab_id}")
    active_labs[lab_id] = "running"
    
    return {
        "status": "success",
        "message": f"Lab {lab_id} started successfully",
        "lab_id": lab_id,
        "timestamp": datetime.now().isoformat()
    }

@app.post("/labs/{lab_id}/stop")
async def stop_lab(lab_id: str):
    """Stop a lab"""
    logger.info(f"🛑 Stopping lab: {lab_id}")
    active_labs[lab_id] = "stopped"
    
    return {
        "status": "success", 
        "message": f"Lab {lab_id} stopped successfully",
        "lab_id": lab_id,
        "timestamp": datetime.now().isoformat()
    }

@app.get("/study/lessons")
async def get_study_lessons():
    """Get study lessons"""
    lessons = [
        {
            "id": "web_application_security",
            "title": "Seguridad en Aplicaciones Web",
            "description": "Curso completo sobre vulnerabilidades web y OWASP Top 10",
            "category": "web_security",
            "difficulty": "intermediate",
            "duration": 180,
            "completed": False,
            "progress": 25
        },
        {
            "id": "cloud_native_security",
            "title": "Cloud Native Security",
            "description": "Seguridad en contenedores, Kubernetes y arquitecturas serverless",
            "category": "cloud_security",
            "difficulty": "expert",
            "duration": 420,
            "completed": False,
            "progress": 15
        },
        {
            "id": "ai_threat_hunting",
            "title": "AI-Powered Threat Hunting",
            "description": "Uso de inteligencia artificial para detección avanzada de amenazas", 
            "category": "ai_security",
            "difficulty": "expert",
            "duration": 360,
            "completed": False,
            "progress": 0
        },
        {
            "id": "malware_analysis_fundamentals",
            "title": "Fundamentos de Análisis de Malware",
            "description": "Técnicas básicas y avanzadas para análisis de malware",
            "category": "malware_analysis",
            "difficulty": "advanced",
            "duration": 300,
            "completed": True,
            "progress": 100
        }
    ]
    
    return lessons

@app.get("/dashboard/stats")
async def get_dashboard_stats():
    """Get dashboard statistics"""
    total_scripts = sum(len(scripts) for scripts in SCRIPT_CONFIGS.values())
    new_scripts_2025 = 0
    
    # Count new 2025 scripts
    for scripts in SCRIPT_CONFIGS.values():
        for script in scripts:
            if script.get("last_updated") == "2025-01-20":
                new_scripts_2025 += 1
    
    return {
        "total_scripts": total_scripts,
        "new_scripts_2025": new_scripts_2025,
        "total_executions": len(executions_history),
        "active_labs": len([lab for lab in active_labs.values() if lab == "running"]),
        "completion_rate": 78,
        "threat_level": "MEDIUM",
        "last_scan": datetime.now().isoformat(),
        "modules": len(SCRIPT_CONFIGS),
        "system_status": "operational"
    }

@app.exception_handler(404)
async def not_found_handler(request, exc):
    """Handle 404 errors"""
    return JSONResponse(
        status_code=404,
        content={
            "error": "Not Found",
            "message": "The requested resource was not found",
            "timestamp": datetime.now().isoformat()
        }
    )

@app.exception_handler(500)
async def server_error_handler(request, exc):
    """Handle 500 errors"""
    logger.error(f"Internal server error: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error", 
            "message": "An internal error occurred",
            "timestamp": datetime.now().isoformat()
        }
    )

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
