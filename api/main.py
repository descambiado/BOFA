
#!/usr/bin/env python3
"""
BOFA Extended Systems v2.5.1 - Main API
Fast API backend for cybersecurity platform with real functionality
"""

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import uvicorn
import os
import sys
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
import yaml
from pathlib import Path

# Import our modules
from database import db
from auth import AuthManager, Roles, check_permission
from script_executor import ScriptExecutor
from lab_manager import LabManager

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
    description="Cybersecurity Platform API v2.5.1 - Neural Security Edge with Real Functionality",
    version="2.5.1",
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

# Initialize services
auth_manager = AuthManager(db)
script_executor = ScriptExecutor(db)
lab_manager = LabManager(db)

# Pydantic models
class LoginRequest(BaseModel):
    username: str
    password: str

class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str
    role: str = "user"

class ExecuteScriptRequest(BaseModel):
    module: str
    script: str
    parameters: Dict[str, Any] = {}

class UpdateProgressRequest(BaseModel):
    progress: float

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
    logger.info("🚀 BOFA Extended Systems v2.5.1 - Neural Security Edge API Starting...")
    logger.info(f"📁 Scripts loaded from {len(SCRIPT_CONFIGS)} modules")
    
    # Create necessary directories
    os.makedirs("/app/logs", exist_ok=True)
    os.makedirs("/app/uploads", exist_ok=True)
    os.makedirs("/app/temp", exist_ok=True)
    os.makedirs("/app/data", exist_ok=True)
    
    # Initialize database and services
    logger.info("🗄️ Database initialized")
    logger.info("🔐 Authentication system ready")
    logger.info("⚙️ Script executor ready")
    logger.info("🐳 Lab manager initialized")
    
    logger.info("✅ BOFA API v2.5.1 Ready!")

# Authentication endpoints
@app.post("/auth/login")
async def login(request: LoginRequest):
    """Authenticate user and return JWT token"""
    user = auth_manager.authenticate_user(request.username, request.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = auth_manager.create_access_token(user)
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": user,
        "expires_in": 86400  # 24 hours
    }

@app.post("/auth/register")
async def register(request: RegisterRequest):
    """Register new user"""
    user_id = auth_manager.register_user(
        request.username, 
        request.email, 
        request.password, 
        request.role
    )
    
    if not user_id:
        raise HTTPException(status_code=400, detail="Username or email already exists")
    
    return {"message": "User registered successfully", "user_id": user_id}

@app.get("/auth/me")
async def get_current_user_info(current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    """Get current user information"""
    permissions = Roles.get_permissions(current_user['role'])
    return {
        "user": current_user,
        "permissions": permissions
    }

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": "BOFA Extended Systems API",
        "version": "2.5.1",
        "edition": "Neural Security Edge",
        "status": "operational",
        "timestamp": datetime.now().isoformat(),
        "features": [
            "Real Script Execution",
            "JWT Authentication", 
            "Docker Lab Management",
            "SQLite Database",
            "AI/ML Integration",
            "Post-Quantum Ready", 
            "Supply Chain Security",
            "Zero Trust Validation",
            "Cloud Native Attacks",
            "Deepfake Detection",
            "IoT Security Mapping"
        ],
        "capabilities": {
            "authentication": True,
            "script_execution": True,
            "lab_management": True,
            "user_management": True,
            "real_time_monitoring": True
        }
    }

@app.get("/health")
async def health_check():
    """Health check endpoint with comprehensive status"""
    try:
        # Test database connection
        db_status = "healthy"
        try:
            test_user = db.get_user_by_username("admin")
            if not test_user:
                db_status = "no_admin_user"
        except Exception:
            db_status = "error"
        
        # Test Docker availability
        docker_status = "healthy" if lab_manager.is_docker_available() else "unavailable"
        
        # System stats
        system_stats = script_executor.get_system_stats()
        
        return {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "version": "2.5.1",
            "edition": "Neural Security Edge",
            "services": {
                "database": db_status,
                "docker": docker_status,
                "authentication": "healthy",
                "script_executor": "healthy"
            },
            "system": {
                "cpu_usage": system_stats.get("cpu_percent", 0),
                "memory_usage": system_stats.get("memory_percent", 0),
                "active_executions": system_stats.get("active_executions", 0)
            },
            "uptime": "operational"
        }
    except Exception as e:
        logger.error(f"Health check error: {e}")
        return {
            "status": "degraded",
            "timestamp": datetime.now().isoformat(),
            "error": str(e)
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

# New: Scripts catalog and code endpoints
@app.get("/scripts/catalog")
async def get_scripts_catalog():
    """Return catalog of all scripts with metadata, grouped by module"""
    catalog = []
    for module_id, scripts in SCRIPT_CONFIGS.items():
        for sc in scripts:
            try:
                yaml_path = Path(sc.get('file_path', ''))
                slug = yaml_path.stem
                py_path = yaml_path.with_suffix('.py')
                if not py_path.exists():
                    # try to find a matching .py in the same folder
                    for alt in yaml_path.parent.glob('*.py'):
                        if slug.lower() in alt.stem.lower():
                            py_path = alt
                            break
                item = {
                    "id": slug,
                    "name": sc.get('display_name') or sc.get('name') or slug,
                    "description": sc.get('description', ''),
                    "category": module_id,
                    "author": sc.get('author', 'unknown'),
                    "version": sc.get('version', '1.0'),
                    "last_updated": sc.get('last_updated'),
                    "usage": sc.get('usage') or (sc.get('usage_examples', [])[:1] or [None])[0],
                    "dependencies": sc.get('dependencies') or sc.get('requirements'),
                    "file_path_yaml": str(yaml_path),
                    "file_path_py": str(py_path) if py_path and py_path.exists() else None,
                    "has_code": bool(py_path and py_path.exists()),
                }
                catalog.append(item)
            except Exception as e:
                logger.warning(f"Catalog build error for {sc}: {e}")
    # Sort by module then name
    catalog.sort(key=lambda x: (x['category'], x['name']))
    return catalog

@app.get("/scripts/{module_id}/{script_name}/code")
async def get_script_code(module_id: str, script_name: str):
    """Return the Python source code for a script"""
    module_dir = Path("/app/scripts") / module_id
    if not module_dir.exists():
        raise HTTPException(status_code=404, detail=f"Module {module_id} not found")
    py_file = module_dir / f"{script_name}.py"
    if not py_file.exists():
        # Try alternative matching
        matches = [f for f in module_dir.glob('*.py') if script_name.lower() in f.stem.lower()]
        if matches:
            py_file = matches[0]
    if not py_file.exists():
        raise HTTPException(status_code=404, detail=f"Script code not found for {script_name}")
    try:
        content = py_file.read_text(encoding='utf-8')
        return {
            "filename": py_file.name,
            "language": "python",
            "size": py_file.stat().st_size,
            "lines": len(content.splitlines()),
            "content": content,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading code: {e}")

@app.post("/execute")
async def execute_script(
    request: ExecuteScriptRequest,
    current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)
):
    """Execute a script with real execution"""
    if not check_permission(current_user, "execute_scripts"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    module = request.module
    script = request.script
    parameters = request.parameters
    
    if not module or not script:
        raise HTTPException(status_code=400, detail="Module and script are required")
    
    # Start script execution
    execution_id = script_executor.execute_script(
        current_user['user_id'], 
        module, 
        script, 
        parameters
    )
    
    logger.info(f"🔧 Started execution {execution_id}: {module}/{script} by {current_user['username']}")
    
    return {
        "execution_id": execution_id,
        "status": "started",
        "message": f"Script {script} execution started",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/execute/{execution_id}")
async def get_execution_status(
    execution_id: str,
    current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)
):
    """Get execution status"""
    execution = script_executor.get_execution_status(execution_id)
    if not execution:
        raise HTTPException(status_code=404, detail="Execution not found")
    
    # Check if user owns this execution or is admin
    if execution['user_id'] != current_user['user_id'] and current_user['role'] != 'admin':
        raise HTTPException(status_code=403, detail="Access denied")
    
    return execution

@app.post("/execute/{execution_id}/stop")
async def stop_execution(
    execution_id: str,
    current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)
):
    """Stop running execution"""
    success = script_executor.stop_execution(execution_id, current_user['user_id'])
    
    if not success:
        raise HTTPException(status_code=404, detail="Execution not found or already stopped")
    
    return {"message": "Execution stopped", "execution_id": execution_id}

@app.get("/history")
async def get_execution_history(
    limit: int = 50,
    current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)
):
    """Get execution history"""
    # Admins can see all history, users only their own
    if current_user['role'] == 'admin':
        history = db.get_execution_history(limit=limit)
    else:
        history = db.get_execution_history(user_id=current_user['user_id'], limit=limit)
    
    # Add username for display
    for item in history:
        if 'parameters' in item and isinstance(item['parameters'], str):
            try:
                import json
                item['parameters'] = json.loads(item['parameters'])
            except:
                pass
        
        # Truncate long outputs
        if item.get('output') and len(item['output']) > 200:
            item['output'] = item['output'][:200] + "..."
    
    return history

@app.get("/labs")
async def get_labs(current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    """Get available labs with real Docker integration"""
    if not check_permission(current_user, "manage_labs"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    labs = lab_manager.get_available_labs()
    
    # Get real status for each lab
    for lab in labs:
        try:
            status_info = lab_manager.get_lab_status(lab['id'], current_user['user_id'])
            lab.update(status_info)
        except Exception as e:
            logger.warning(f"Error getting status for lab {lab['id']}: {e}")
            lab['status'] = 'unknown'
    
    return labs

@app.post("/labs/{lab_id}/start")
async def start_lab(
    lab_id: str, 
    current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)
):
    """Start a lab with real Docker containers"""
    if not check_permission(current_user, "manage_labs"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    result = lab_manager.start_lab(lab_id, current_user['user_id'])
    
    if result['status'] != 'success':
        raise HTTPException(status_code=400, detail=result['message'])
    
    return result

@app.post("/labs/{lab_id}/stop")
async def stop_lab(
    lab_id: str, 
    current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)
):
    """Stop a lab"""
    if not check_permission(current_user, "manage_labs"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    result = lab_manager.stop_lab(lab_id, current_user['user_id'])
    
    if result['status'] != 'success':
        raise HTTPException(status_code=400, detail=result['message'])
    
    return result

@app.get("/study/lessons")
async def get_study_lessons(current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    """Get study lessons with user progress"""
    default_lessons = [
        {
            "id": "web_application_security",
            "title": "Seguridad en Aplicaciones Web",
            "description": "Curso completo sobre vulnerabilidades web y OWASP Top 10",
            "category": "web_security",
            "difficulty": "intermediate",
            "duration": 180,
            "completed": False,
            "progress": 0
        },
        {
            "id": "cloud_native_security",
            "title": "Cloud Native Security",
            "description": "Seguridad en contenedores, Kubernetes y arquitecturas serverless",
            "category": "cloud_security",
            "difficulty": "expert",
            "duration": 420,
            "completed": False,
            "progress": 0
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
            "completed": False,
            "progress": 0
        },
        {
            "id": "quantum_cryptography",
            "title": "Post-Quantum Cryptography",
            "description": "Criptografía resistente a computación cuántica",
            "category": "quantum_security",
            "difficulty": "expert",
            "duration": 480,
            "completed": False,
            "progress": 0
        }
    ]
    
    # Get user progress from database
    try:
        user_progress = db.get_learning_progress(current_user['user_id'])
        progress_dict = {p['lesson_id']: p for p in user_progress}
        
        # Update lessons with user progress
        for lesson in default_lessons:
            if lesson['id'] in progress_dict:
                progress = progress_dict[lesson['id']]
                lesson['progress'] = progress['progress']
                lesson['completed'] = progress['completed']
    except Exception as e:
        logger.warning(f"Error loading user progress: {e}")
    
    return default_lessons

@app.put("/study/lessons/{lesson_id}/progress")
async def update_lesson_progress(
    lesson_id: str,
    request: UpdateProgressRequest,
    current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)
):
    """Update lesson progress"""
    try:
        db.update_lesson_progress(current_user['user_id'], lesson_id, request.progress)
        return {"message": "Progress updated", "lesson_id": lesson_id, "progress": request.progress}
    except Exception as e:
        logger.error(f"Error updating progress: {e}")
        raise HTTPException(status_code=500, detail="Error updating progress")

# API Key management
@app.post("/api-keys/{service_name}")
async def store_api_key(
    service_name: str,
    api_key: str = Form(...),
    current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)
):
    """Store API key for external services"""
    if not check_permission(current_user, "manage_api_keys"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    allowed_services = ['shodan_key', 'virustotal_key', 'hibp_key', 'github_token']
    if service_name not in allowed_services:
        raise HTTPException(status_code=400, detail=f"Service must be one of: {allowed_services}")
    
    try:
        db.store_api_key(current_user['user_id'], service_name, api_key)
        return {"message": f"API key for {service_name} stored successfully"}
    except Exception as e:
        logger.error(f"Error storing API key: {e}")
        raise HTTPException(status_code=500, detail="Error storing API key")

@app.get("/api-keys")
async def get_user_api_keys(current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    """Get user's stored API keys (masked)"""
    if not check_permission(current_user, "manage_api_keys"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    services = ['shodan_key', 'virustotal_key', 'hibp_key', 'github_token']
    keys_status = {}
    
    for service in services:
        api_key = db.get_api_key(current_user['user_id'], service)
        keys_status[service] = {
            "configured": bool(api_key),
            "masked_key": f"****{api_key[-4:]}" if api_key else None
        }
    
    return keys_status

@app.get("/dashboard/stats")
async def get_dashboard_stats(current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    """Get dashboard statistics with real data"""
    try:
        total_scripts = sum(len(scripts) for scripts in SCRIPT_CONFIGS.values())
        new_scripts_2025 = 0
        
        # Count new 2025 scripts
        for scripts in SCRIPT_CONFIGS.values():
            for script in scripts:
                if script.get("last_updated") == "2025-01-20":
                    new_scripts_2025 += 1
        
        # Get real execution data
        if current_user['role'] == 'admin':
            executions = db.get_execution_history(limit=1000)
        else:
            executions = db.get_execution_history(user_id=current_user['user_id'], limit=100)
        
        # Calculate completion rate
        total_executions = len(executions)
        successful_executions = len([e for e in executions if e.get('status') == 'success'])
        completion_rate = (successful_executions / total_executions * 100) if total_executions > 0 else 0
        
        # Get system stats
        system_stats = script_executor.get_system_stats()
        docker_resources = lab_manager.get_system_resources()
        
        # Recent activity
        recent_executions = [e for e in executions[:10]]
        
        return {
            "total_scripts": total_scripts,
            "new_scripts_2025": new_scripts_2025,
            "total_executions": total_executions,
            "successful_executions": successful_executions,
            "active_labs": docker_resources.get('containers_running', 0),
            "completion_rate": round(completion_rate, 1),
            "threat_level": "MEDIUM",
            "last_scan": datetime.now().isoformat(),
            "modules": len(SCRIPT_CONFIGS),
            "system_status": "operational",
            "system_performance": {
                "cpu_usage": system_stats.get("cpu_percent", 0),
                "memory_usage": system_stats.get("memory_percent", 0),
                "active_executions": system_stats.get("active_executions", 0),
                "disk_free_gb": system_stats.get("disk_free_gb", 0)
            },
            "docker_stats": docker_resources,
            "recent_activity": recent_executions,
            "user_stats": {
                "user_executions": len([e for e in executions if e.get('user_id') == current_user['user_id']]),
                "role": current_user['role'],
                "permissions": Roles.get_permissions(current_user['role'])
            }
        }
    except Exception as e:
        logger.error(f"Error getting dashboard stats: {e}")
        # Fallback to basic stats
        return {
            "total_scripts": sum(len(scripts) for scripts in SCRIPT_CONFIGS.values()),
            "total_executions": 0,
            "active_labs": 0,
            "completion_rate": 0,
            "threat_level": "UNKNOWN",
            "system_status": "degraded",
            "error": str(e)
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
