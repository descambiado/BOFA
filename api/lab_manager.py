#!/usr/bin/env python3
"""
BOFA Extended Systems v2.5.1 - Docker Lab Management
Docker container orchestration for security labs
"""

import docker
import yaml
import logging
import time
import random
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class LabManager:
    def __init__(self, database_manager, labs_dir: str = "/app/labs"):
        self.db = database_manager
        self.labs_dir = Path(labs_dir)
        self.docker_client = None
        self.available_ports = list(range(8080, 8200))
        
        try:
            self.docker_client = docker.from_env()
            logger.info("🐳 Docker client connected")
        except Exception as e:
            logger.error(f"❌ Docker connection failed: {e}")
    
    def is_docker_available(self) -> bool:
        """Check if Docker is available"""
        if not self.docker_client:
            return False
        
        try:
            self.docker_client.ping()
            return True
        except Exception:
            return False
    
    def load_lab_config(self, lab_id: str) -> Optional[Dict[str, Any]]:
        """Load lab configuration"""
        metadata_file = self.labs_dir / lab_id / "metadata.yaml"
        
        if not metadata_file.exists():
            logger.error(f"Lab metadata not found: {metadata_file}")
            return None
        
        try:
            with open(metadata_file, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            return config
        except Exception as e:
            logger.error(f"Error loading lab config {metadata_file}: {e}")
            return None
    
    def get_available_labs(self) -> List[Dict[str, Any]]:
        """Get list of available labs"""
        labs = []
        
        # Default labs configuration
        default_labs = [
            {
                "id": "web-application-security",
                "name": "Web Application Security Lab",
                "description": "Laboratorio completo para práctica de vulnerabilidades web (OWASP Top 10)",
                "category": "web_security",
                "difficulty": "intermediate",
                "estimated_time": "240 minutos",
                "status": "stopped",
                "features": ["DVWA", "WebGoat", "bWAPP", "Mutillidae"],
                "technologies": ["PHP", "MySQL", "Apache", "Docker"]
            },
            {
                "id": "kubernetes-cluster",
                "name": "Kubernetes Security Cluster",
                "description": "Cluster Kubernetes vulnerable para práctica de Cloud Native Security",
                "category": "cloud_native",
                "difficulty": "advanced",
                "estimated_time": "300 minutos",
                "status": "stopped",
                "features": ["Vulnerable Pods", "RBAC Misconfigs", "Network Policies", "Secrets"],
                "technologies": ["Kubernetes", "Docker", "Helm", "Kubectl"]
            },
            {
                "id": "iot-simulation",
                "name": "IoT/OT Simulation Environment",
                "description": "Entorno simulado de dispositivos IoT/OT con protocolos industriales",
                "category": "iot_security",
                "difficulty": "expert",
                "estimated_time": "360 minutos",
                "status": "stopped",
                "features": ["MQTT Broker", "Modbus", "CoAP", "Industrial Protocols"],
                "technologies": ["Node-RED", "Mosquitto", "OpenPLC", "Docker"]
            },
            {
                "id": "android-lab",
                "name": "Android Security Lab",
                "description": "Emulador Android con apps vulnerables para testing móvil",
                "category": "mobile",
                "difficulty": "advanced",
                "estimated_time": "150 minutos",
                "status": "stopped",
                "features": ["DIVA", "UnCrackable Apps", "Vulnerable APKs", "ADB Access"],
                "technologies": ["Android", "ADB", "Frida", "Docker"]
            },
            {
                "id": "internal-network",
                "name": "Red Interna Corporativa",
                "description": "Simula una red corporativa completa con múltiples servicios",
                "category": "network",
                "difficulty": "intermediate",
                "estimated_time": "180 minutos",
                "status": "stopped",
                "features": ["AD Domain", "Web Services", "Database", "File Shares"],
                "technologies": ["Windows Server", "Linux", "MySQL", "Samba"]
            },
            {
                "id": "ai-security-lab",
                "name": "AI/ML Security Lab",
                "description": "Laboratorio para testing de modelos AI/ML y detección de adversarial attacks",
                "category": "ai_security",
                "difficulty": "expert",
                "estimated_time": "400 minutos",
                "status": "stopped",
                "features": ["Model Poisoning", "Adversarial Examples", "Privacy Attacks", "Federated Learning"],
                "technologies": ["TensorFlow", "PyTorch", "Jupyter", "Python"]
            }
        ]
        
        # Load custom labs from filesystem
        if self.labs_dir.exists():
            for lab_dir in self.labs_dir.iterdir():
                if lab_dir.is_dir():
                    config = self.load_lab_config(lab_dir.name)
                    if config:
                        labs.append({
                            "id": lab_dir.name,
                            "name": config.get("name", lab_dir.name),
                            "description": config.get("description", ""),
                            "category": config.get("category", "general"),
                            "difficulty": config.get("difficulty", "intermediate"),
                            "estimated_time": config.get("estimated_time", "120 minutos"),
                            "status": "stopped",
                            "features": config.get("features", []),
                            "technologies": config.get("technologies", [])
                        })
        
        # Merge with defaults
        lab_ids = {lab["id"] for lab in labs}
        for default_lab in default_labs:
            if default_lab["id"] not in lab_ids:
                labs.append(default_lab)
        
        return labs
    
    def get_free_port(self) -> int:
        """Get available port for lab"""
        used_ports = set()
        
        # Check database for used ports
        if self.db:
            try:
                user_labs = self.db.get_user_labs(1)  # Check all users
                for lab in user_labs:
                    if lab.get('port') and lab.get('status') == 'running':
                        used_ports.add(lab['port'])
            except Exception:
                pass
        
        # Check Docker containers
        if self.docker_client:
            try:
                containers = self.docker_client.containers.list()
                for container in containers:
                    for port_info in container.attrs.get('NetworkSettings', {}).get('Ports', {}).values():
                        if port_info:
                            for port_binding in port_info:
                                used_ports.add(int(port_binding['HostPort']))
            except Exception:
                pass
        
        # Find free port
        available = [p for p in self.available_ports if p not in used_ports]
        return random.choice(available) if available else random.randint(8200, 9000)
    
    def start_lab(self, lab_id: str, user_id: int) -> Dict[str, Any]:
        """Start lab container"""
        if not self.is_docker_available():
            return {
                "status": "error",
                "message": "Docker no está disponible. Usando modo simulado.",
                "simulated": True
            }
        
        try:
            # Check if lab is already running
            existing_containers = self.docker_client.containers.list(
                filters={"label": f"bofa.lab_id={lab_id}"}
            )
            
            if existing_containers:
                container = existing_containers[0]
                port_bindings = container.attrs.get('NetworkSettings', {}).get('Ports', {})
                port = None
                for port_info in port_bindings.values():
                    if port_info:
                        port = int(port_info[0]['HostPort'])
                        break
                
                self.db.update_lab_status(lab_id, user_id, "running")
                
                return {
                    "status": "success",
                    "message": f"Lab {lab_id} ya está en ejecución",
                    "container_id": container.id,
                    "port": port,
                    "url": f"http://localhost:{port}" if port else None
                }
            
            # Get free port
            port = self.get_free_port()
            
            # Create lab instance in database
            instance_id = self.db.create_lab_instance(lab_id, user_id, port=port)
            
            # Docker configuration based on lab type
            lab_configs = {
                "web-application-security": {
                    "image": "vulnerables/web-dvwa",
                    "ports": {80: port},
                    "environment": {
                        "MYSQL_ROOT_PASSWORD": "dvwa",
                        "MYSQL_DATABASE": "dvwa",
                        "MYSQL_USER": "dvwa",
                        "MYSQL_PASSWORD": "password"
                    }
                },
                "kubernetes-cluster": {
                    "image": "kindest/node:v1.27.3",
                    "ports": {6443: port},
                    "privileged": True,
                    "environment": {"KUBECONFIG": "/etc/kubernetes/admin.conf"}
                },
                "android-lab": {
                    "image": "budtmo/docker-android-x86-11.0",
                    "ports": {6080: port, 5555: port + 1},
                    "privileged": True,
                    "environment": {"DEVICE": "Samsung Galaxy S6"}
                },
                "iot-simulation": {
                    "image": "nodered/node-red",
                    "ports": {1880: port},
                    "volumes": {f"/app/labs/{lab_id}/flows": {"bind": "/data", "mode": "rw"}}
                }
            }
            
            # Default configuration
            config = lab_configs.get(lab_id, {
                "image": "ubuntu:20.04",
                "ports": {22: port},
                "command": "tail -f /dev/null"
            })
            
            # Start container
            container = self.docker_client.containers.run(
                image=config["image"],
                ports=config.get("ports", {}),
                environment=config.get("environment", {}),
                volumes=config.get("volumes", {}),
                privileged=config.get("privileged", False),
                detach=True,
                labels={
                    "bofa.lab_id": lab_id,
                    "bofa.user_id": str(user_id),
                    "bofa.instance_id": str(instance_id),
                    "bofa.created": datetime.now().isoformat()
                },
                name=f"bofa-{lab_id}-{user_id}",
                command=config.get("command")
            )
            
            # Wait for container to be ready
            time.sleep(3)
            
            # Update database
            self.db.update_lab_status(lab_id, user_id, "running")
            
            logger.info(f"🧪 Lab started: {lab_id} on port {port} (container: {container.id[:12]})")
            
            return {
                "status": "success",
                "message": f"Lab {lab_id} iniciado correctamente",
                "container_id": container.id,
                "port": port,
                "url": f"http://localhost:{port}",
                "instance_id": instance_id
            }
            
        except docker.errors.ImageNotFound:
            # Pull image and retry
            try:
                logger.info(f"📥 Pulling image for lab {lab_id}")
                config = lab_configs.get(lab_id, {"image": "ubuntu:20.04"})
                self.docker_client.images.pull(config["image"])
                return self.start_lab(lab_id, user_id)
            except Exception as e:
                return {
                    "status": "error",
                    "message": f"Error descargando imagen: {str(e)}"
                }
        
        except Exception as e:
            logger.error(f"❌ Error starting lab {lab_id}: {e}")
            return {
                "status": "error",
                "message": f"Error iniciando lab: {str(e)}"
            }
    
    def stop_lab(self, lab_id: str, user_id: int) -> Dict[str, Any]:
        """Stop lab container"""
        if not self.is_docker_available():
            self.db.update_lab_status(lab_id, user_id, "stopped")
            return {
                "status": "success",
                "message": f"Lab {lab_id} detenido (simulado)",
                "simulated": True
            }
        
        try:
            # Find containers for this lab
            containers = self.docker_client.containers.list(
                filters={"label": f"bofa.lab_id={lab_id}"}
            )
            
            if not containers:
                self.db.update_lab_status(lab_id, user_id, "stopped")
                return {
                    "status": "success",
                    "message": f"Lab {lab_id} ya está detenido"
                }
            
            # Stop and remove containers
            for container in containers:
                try:
                    container.stop(timeout=10)
                    container.remove()
                    logger.info(f"🛑 Container stopped: {container.id[:12]}")
                except Exception as e:
                    logger.warning(f"Error stopping container {container.id[:12]}: {e}")
            
            # Update database
            self.db.update_lab_status(lab_id, user_id, "stopped")
            
            return {
                "status": "success",
                "message": f"Lab {lab_id} detenido correctamente"
            }
            
        except Exception as e:
            logger.error(f"❌ Error stopping lab {lab_id}: {e}")
            return {
                "status": "error",
                "message": f"Error deteniendo lab: {str(e)}"
            }
    
    def get_lab_status(self, lab_id: str, user_id: int) -> Dict[str, Any]:
        """Get lab status"""
        if not self.is_docker_available():
            return {"status": "stopped", "simulated": True}
        
        try:
            containers = self.docker_client.containers.list(
                filters={"label": f"bofa.lab_id={lab_id}"}
            )
            
            if not containers:
                return {"status": "stopped"}
            
            container = containers[0]
            
            # Get port mapping
            port = None
            port_bindings = container.attrs.get('NetworkSettings', {}).get('Ports', {})
            for port_info in port_bindings.values():
                if port_info:
                    port = int(port_info[0]['HostPort'])
                    break
            
            return {
                "status": "running",
                "container_id": container.id,
                "port": port,
                "url": f"http://localhost:{port}" if port else None,
                "created": container.attrs.get('Created', ''),
                "uptime": container.attrs.get('State', {}).get('StartedAt', '')
            }
            
        except Exception as e:
            logger.error(f"❌ Error getting lab status {lab_id}: {e}")
            return {"status": "error", "message": str(e)}
    
    def cleanup_stopped_labs(self):
        """Clean up stopped lab containers"""
        if not self.is_docker_available():
            return
        
        try:
            # Remove stopped BOFA containers
            containers = self.docker_client.containers.list(
                all=True,
                filters={"label": "bofa.lab_id"}
            )
            
            for container in containers:
                if container.status in ['exited', 'dead']:
                    try:
                        container.remove()
                        logger.info(f"🧹 Removed stopped container: {container.id[:12]}")
                    except Exception as e:
                        logger.warning(f"Error removing container {container.id[:12]}: {e}")
                        
        except Exception as e:
            logger.error(f"❌ Error during cleanup: {e}")
    
    def get_system_resources(self) -> Dict[str, Any]:
        """Get Docker system resources"""
        if not self.is_docker_available():
            return {"docker_available": False}
        
        try:
            info = self.docker_client.info()
            return {
                "docker_available": True,
                "containers_running": info.get('ContainersRunning', 0),
                "containers_total": info.get('Containers', 0),
                "images_total": info.get('Images', 0),
                "memory_total": info.get('MemTotal', 0),
                "cpu_cores": info.get('NCPU', 0),
                "docker_version": info.get('ServerVersion', 'unknown')
            }
        except Exception as e:
            logger.error(f"❌ Error getting Docker info: {e}")
            return {"docker_available": False, "error": str(e)}