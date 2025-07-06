# 🚀 BOFA API Backend v2.5.0

FastAPI backend para BOFA Extended Systems con funcionalidades de ciberseguridad.

## 🏗️ Arquitectura

### Componentes Principales
- **FastAPI**: Framework web asíncrono
- **PostgreSQL**: Base de datos principal
- **Redis**: Cache y sesiones
- **SQLAlchemy**: ORM para base de datos
- **JWT**: Autenticación y autorización
- **Pydantic**: Validación de datos

### Estructura del Proyecto
```
api/
├── main.py              # Aplicación principal
├── models/              # Modelos de base de datos
├── schemas/             # Esquemas Pydantic
├── routes/              # Endpoints de API
├── services/            # Lógica de negocio
├── utils/               # Utilidades compartidas
├── middleware/          # Middleware personalizado
├── tests/               # Tests automatizados
├── migrations/          # Migraciones de BD
└── requirements.txt     # Dependencias Python
```

## 🔧 Configuración

### Variables de Entorno
```bash
# Database
DATABASE_URL=postgresql://bofa:bofa123@localhost:5432/bofa_db

# Redis
REDIS_URL=redis://localhost:6379
REDIS_PASSWORD=bofa123

# JWT
JWT_SECRET=your_super_secure_jwt_secret
JWT_ALGORITHM=HS256
JWT_EXPIRE_MINUTES=1440

# API Configuration
API_VERSION=v2.5
DEBUG=true
CORS_ORIGINS=http://localhost:3000,http://localhost:8080

# External APIs
SHODAN_API_KEY=your_shodan_key
VIRUSTOTAL_API_KEY=your_vt_key
HIBP_API_KEY=your_hibp_key
```

## 🚀 Instalación y Ejecución

### Desarrollo Local
```bash
# Crear entorno virtual
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# Instalar dependencias
pip install -r requirements.txt

# Configurar variables de entorno
cp .env.template .env
# Editar .env con tus valores

# Ejecutar migraciones
alembic upgrade head

# Iniciar servidor de desarrollo
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Docker
```bash
# Construir imagen
docker build -t bofa-api .

# Ejecutar contenedor
docker run -p 8000:8000 --env-file .env bofa-api

# Con Docker Compose
docker-compose up api -d
```

## 📋 Endpoints de API

### Autenticación
```http
POST /auth/login          # Iniciar sesión
POST /auth/register       # Registrar usuario
POST /auth/refresh        # Renovar token
DELETE /auth/logout       # Cerrar sesión
```

### Scripts
```http
GET /scripts              # Listar todos los scripts
GET /scripts/{module}     # Scripts por módulo
POST /scripts/execute     # Ejecutar script
GET /scripts/{id}/status  # Estado de ejecución
GET /scripts/{id}/output  # Salida de script
```

### Laboratorios
```http
GET /labs                 # Listar laboratorios
POST /labs/{name}/start   # Iniciar laboratorio
POST /labs/{name}/stop    # Detener laboratorio
GET /labs/{name}/status   # Estado del laboratorio
GET /labs/{name}/logs     # Logs del laboratorio
```

### Historial
```http
GET /history              # Historial de ejecuciones
GET /history/{id}         # Ejecución específica
DELETE /history/{id}      # Eliminar registro
GET /history/export       # Exportar historial
```

### Métricas
```http
GET /metrics              # Métricas del sistema
GET /metrics/dashboard    # Datos para dashboard
GET /metrics/scripts      # Estadísticas de scripts
GET /metrics/threats      # Eventos de amenazas
```

### Sistema
```http
GET /health               # Estado de salud
GET /info                 # Información del sistema
GET /version              # Versión de la API
GET /docs                 # Documentación Swagger
```

## 🔐 Autenticación y Autorización

### JWT Tokens
```python
# Estructura del token
{
  "sub": "user_id",
  "username": "admin",
  "email": "admin@bofa.local",
  "is_admin": true,
  "exp": 1642780800,
  "iat": 1642694400
}
```

### Middleware de Autenticación
```python
from fastapi import Depends, HTTPException
from .auth import get_current_user

@app.get("/protected")
async def protected_route(current_user: User = Depends(get_current_user)):
    return {"message": f"Hello {current_user.username}"}
```

### Roles y Permisos
- **Admin**: Acceso completo al sistema
- **User**: Acceso a scripts y laboratorios
- **Viewer**: Solo lectura de datos

## 📊 Modelos de Datos

### Usuario
```python
class User(Base):
    __tablename__ = "users"
    
    id = Column(UUID(as_uuid=True), primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=func.now())
```

### Ejecución de Script
```python
class ScriptExecution(Base):
    __tablename__ = "script_executions"
    
    id = Column(UUID(as_uuid=True), primary_key=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    script_name = Column(String(100), nullable=False)
    module = Column(String(50), nullable=False)
    parameters = Column(JSON)
    status = Column(String(20), nullable=False)
    output = Column(Text)
    execution_time = Column(Integer)
    started_at = Column(DateTime(timezone=True), default=func.now())
```

### Evento de Amenaza
```python
class ThreatEvent(Base):
    __tablename__ = "threat_events"
    
    id = Column(UUID(as_uuid=True), primary_key=True)
    event_type = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False)
    title = Column(String(200), nullable=False)
    description = Column(Text)
    mitre_tactic = Column(String(50))
    mitre_technique = Column(String(50))
    ioc_data = Column(JSON)
    status = Column(String(20), default="open")
```

## 🛠️ Servicios

### Script Execution Service
```python
class ScriptExecutionService:
    def __init__(self):
        self.redis_client = Redis()
        
    async def execute_script(self, script_config, parameters, user_id):
        # Validar parámetros
        # Ejecutar script de forma asíncrona
        # Almacenar resultado en base de datos
        # Notificar via WebSocket
        pass
```

### Lab Management Service
```python
class LabManagementService:
    def __init__(self):
        self.docker_client = docker.from_env()
        
    async def start_lab(self, lab_name, user_id):
        # Verificar recursos disponibles
        # Iniciar contenedores del laboratorio
        # Configurar red y puertos
        # Registrar instancia en BD
        pass
```

### Threat Intelligence Service
```python
class ThreatIntelligenceService:
    def __init__(self):
        self.shodan_api = shodan.Shodan(API_KEY)
        self.vt_client = vt.Client(VT_API_KEY)
        
    async def analyze_ioc(self, indicator_type, indicator_value):
        # Consultar múltiples fuentes
        # Correlacionar información
        # Generar score de confianza
        # Almacenar en base de datos
        pass
```

## 🔄 WebSockets

### Conexiones en Tiempo Real
```python
from fastapi import WebSocket

@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: str):
    await websocket.accept()
    # Gestionar conexión de usuario
    # Enviar actualizaciones en tiempo real
    # Manejar desconexiones
```

### Eventos Soportados
- **script_status**: Estado de ejecución de scripts
- **lab_status**: Estado de laboratorios
- **threat_alert**: Nuevas amenazas detectadas
- **system_metric**: Métricas del sistema

## 📈 Monitoreo y Métricas

### Prometheus Metrics
```python
from prometheus_client import Counter, Histogram, Gauge

# Métricas personalizadas
script_executions = Counter('bofa_script_executions_total', 'Total script executions', ['module', 'status'])
api_request_duration = Histogram('bofa_api_request_duration_seconds', 'API request duration')
active_labs = Gauge('bofa_active_labs', 'Number of active labs')
```

### Health Checks
```python
@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow(),
        "version": "2.5.0",
        "database": await check_database(),
        "redis": await check_redis(),
        "services": await check_services()
    }
```

## 🧪 Testing

### Tests Unitarios
```python
import pytest
from fastapi.testclient import TestClient
from .main import app

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
```

### Tests de Integración
```python
@pytest.mark.asyncio
async def test_script_execution():
    # Test completo de ejecución de script
    # Incluye validación de parámetros
    # Verificación de resultados
    # Limpieza de recursos
    pass
```

### Ejecutar Tests
```bash
# Tests unitarios
pytest tests/unit/

# Tests de integración
pytest tests/integration/

# Coverage report
pytest --cov=api tests/

# Tests con Docker
docker-compose -f docker-compose.test.yml up --abort-on-container-exit
```

## 🔒 Seguridad

### Validación de Entrada
```python
from pydantic import BaseModel, validator

class ScriptExecutionRequest(BaseModel):
    script_name: str
    parameters: dict
    
    @validator('script_name')
    def validate_script_name(cls, v):
        # Validar que el script existe
        # Verificar permisos de ejecución
        return v
```

### Rate Limiting
```python
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@app.post("/scripts/execute")
@limiter.limit("10/minute")
async def execute_script(request: Request):
    # Lógica de ejecución
    pass
```

### Sanitización de Datos
```python
import bleach

def sanitize_output(output: str) -> str:
    return bleach.clean(output, tags=[], attributes={}, strip=True)
```

## 📦 Deployment

### Configuración de Producción
```python
# settings.py
class ProductionSettings(BaseSettings):
    debug: bool = False
    log_level: str = "INFO"
    workers: int = 4
    max_connections: int = 1000
    
    class Config:
        env_file = ".env.production"
```

### Docker Multi-Stage
```dockerfile
# Dockerfile
FROM python:3.11-slim as builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --user -r requirements.txt

FROM python:3.11-slim as runtime
WORKDIR /app
COPY --from=builder /root/.local /root/.local
COPY . .
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
```

### Nginx Reverse Proxy
```nginx
upstream bofa_api {
    server api:8000;
}

server {
    listen 80;
    location /api/ {
        proxy_pass http://bofa_api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## 📚 Documentación

### Swagger/OpenAPI
Documentación automática disponible en:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **OpenAPI JSON**: http://localhost:8000/openapi.json

### Ejemplos de Uso
```python
# Cliente Python
import httpx

async def execute_script_example():
    async with httpx.AsyncClient() as client:
        # Autenticación
        login_response = await client.post("/auth/login", json={
            "username": "admin",
            "password": "admin123"
        })
        token = login_response.json()["access_token"]
        
        # Ejecutar script
        headers = {"Authorization": f"Bearer {token}"}
        response = await client.post("/scripts/execute", 
            json={
                "script_name": "ai_threat_hunter",
                "parameters": {"log_file": "security.log"}
            },
            headers=headers
        )
        return response.json()
```

## 📞 Soporte y Contribución

### Desarrollo
```bash
# Setup de desarrollo
git clone https://github.com/descambiado/BOFA
cd BOFA/api
python -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt
pre-commit install
```

### Guías de Contribución
- Seguir convenciones PEP 8
- Escribir tests para nuevo código
- Documentar APIs con docstrings
- Actualizar CHANGELOG.md

### Contacto
- **GitHub**: [Issues API](https://github.com/descambiado/BOFA/labels/api)
- **Email**: api@bofa.dev
- **Discord**: [Canal #api-development](https://discord.gg/bofa-api)

---

**🚀 BOFA API - Potencia Backend para Ciberseguridad**  
*Desarrollado con ❤️ por @descambiado*