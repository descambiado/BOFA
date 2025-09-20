#!/usr/bin/env python3
"""
BOFA Extended Systems v2.5.1 - Script Execution Engine
Secure script execution with sandboxing and monitoring
"""

import os
import sys
import subprocess
import tempfile
import time
import json
import yaml
import logging
import signal
import threading
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
from datetime import datetime
import resource
import psutil

logger = logging.getLogger(__name__)

class ScriptExecutor:
    def __init__(self, database_manager, scripts_dir: str = "/app/scripts"):
        self.db = database_manager
        self.scripts_dir = Path(scripts_dir)
        self.active_executions = {}
        
    def get_script_config(self, module: str, script_name: str) -> Optional[Dict[str, Any]]:
        """Load script configuration from YAML"""
        yaml_file = self.scripts_dir / module / f"{script_name}.yaml"
        
        if not yaml_file.exists():
            logger.error(f"Script config not found: {yaml_file}")
            return None
        
        try:
            with open(yaml_file, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            return config
        except Exception as e:
            logger.error(f"Error loading script config {yaml_file}: {e}")
            return None
    
    def get_script_file(self, module: str, script_name: str) -> Optional[Path]:
        """Get script Python file path"""
        py_file = self.scripts_dir / module / f"{script_name}.py"
        
        if py_file.exists():
            return py_file
        
        # Try alternative naming
        for file in (self.scripts_dir / module).glob("*.py"):
            if script_name.lower() in file.stem.lower():
                return file
        
        logger.error(f"Script file not found: {script_name} in {module}")
        return None
    
    def validate_parameters(self, config: Dict[str, Any], parameters: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate script parameters (supports list or dict in YAML)"""
        script_params = config.get('parameters', {})

        # Normalize list-style parameters from YAML to dict {name: config}
        if isinstance(script_params, list):
            normalized = {}
            for p in script_params:
                if isinstance(p, dict) and 'name' in p:
                    name = p['name']
                    p_copy = p.copy()
                    p_copy.pop('name', None)
                    # Map types like 'integer'/'float' -> 'number'
                    p_type = p_copy.get('type', 'string')
                    if p_type in ('integer', 'float', 'double'):
                        p_copy['type'] = 'number'
                    normalized[name] = p_copy
            script_params = normalized
        elif not isinstance(script_params, dict):
            script_params = {}

        for param_name, param_config in script_params.items():
            if param_config.get('required', False) and param_name not in parameters:
                return False, f"Required parameter missing: {param_name}"

            if param_name in parameters:
                value = parameters[param_name]
                param_type = param_config.get('type', 'string')

                # Type validation
                if param_type == 'number':
                    try:
                        float(value)
                    except (ValueError, TypeError):
                        return False, f"Parameter {param_name} must be a number"

                elif param_type == 'boolean':
                    if value not in ['true', 'false', True, False]:
                        return False, f"Parameter {param_name} must be true/false"

                elif param_type in ('select', 'choice'):
                    options = param_config.get('options') or param_config.get('choices') or []
                    if options and value not in options:
                        return False, f"Parameter {param_name} must be one of: {options}"

                # Range validation
                if param_type == 'number':
                    try:
                        num_value = float(value)
                        if 'min' in param_config and num_value < float(param_config['min']):
                            return False, f"Parameter {param_name} must be >= {param_config['min']}"
                        if 'max' in param_config and num_value > float(param_config['max']):
                            return False, f"Parameter {param_name} must be <= {param_config['max']}"
                    except (ValueError, TypeError):
                        return False, f"Parameter {param_name} must be a number"

        return True, ""

    def create_sandbox_environment(self, execution_id: str) -> Path:
        """Create isolated execution environment"""
        sandbox_dir = Path(f"/app/temp/sandbox_{execution_id}")
        sandbox_dir.mkdir(parents=True, exist_ok=True)
        
        # Create restricted environment structure
        (sandbox_dir / "input").mkdir(exist_ok=True)
        (sandbox_dir / "output").mkdir(exist_ok=True)
        (sandbox_dir / "logs").mkdir(exist_ok=True)
        
        return sandbox_dir
    
    def set_resource_limits(self):
        """Set resource limits for script execution"""
        # Memory limit: 512MB
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
        
        # CPU time limit: 5 minutes
        resource.setrlimit(resource.RLIMIT_CPU, (300, 300))
        
        # File size limit: 100MB
        resource.setrlimit(resource.RLIMIT_FSIZE, (100 * 1024 * 1024, 100 * 1024 * 1024))
    
    def execute_script_async(self, execution_id: str, user_id: int, module: str, 
                           script_name: str, parameters: Dict[str, Any]):
        """Execute script asynchronously"""
        start_time = time.time()
        
        try:
            # Get script configuration
            config = self.get_script_config(module, script_name)
            if not config:
                self.db.update_execution(execution_id, "error", 
                                      error_message="Script configuration not found")
                return
            
            # Validate parameters
            valid, error_msg = self.validate_parameters(config, parameters)
            if not valid:
                self.db.update_execution(execution_id, "error", error_message=error_msg)
                return
            
            # Get script file
            script_file = self.get_script_file(module, script_name)
            if not script_file:
                self.db.update_execution(execution_id, "error", 
                                      error_message="Script file not found")
                return
            
            # Create sandbox
            sandbox = self.create_sandbox_environment(execution_id)
            
            # Prepare execution environment
            env = os.environ.copy()
            env.update({
                'BOFA_EXECUTION_ID': execution_id,
                'BOFA_SANDBOX_DIR': str(sandbox),
                'BOFA_USER_ID': str(user_id),
                'PYTHONPATH': '/app'
            })
            
            # Add API keys from database
            api_keys = ['shodan_key', 'virustotal_key', 'hibp_key']
            for key_name in api_keys:
                api_key = self.db.get_api_key(user_id, key_name)
                if api_key:
                    env[f'BOFA_{key_name.upper()}'] = api_key
            
            # Prepare script arguments
            args = [sys.executable, str(script_file)]
            
            # Add parameters as JSON
            param_file = sandbox / "parameters.json"
            with open(param_file, 'w') as f:
                json.dump(parameters, f)
            args.extend(['--params', str(param_file)])
            
            logger.info(f"🔧 Executing {module}/{script_name} (ID: {execution_id})")
            
            # Execute with timeout
            timeout = config.get('execution', {}).get('timeout', 300)
            
            process = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(sandbox),
                env=env,
                text=True,
                preexec_fn=self.set_resource_limits
            )
            
            # Store process for potential termination
            self.active_executions[execution_id] = process
            
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                return_code = process.returncode
                
                execution_time = time.time() - start_time
                
                if return_code == 0:
                    # Success
                    output = stdout
                    if stderr:
                        output += f"\n\nWarnings:\n{stderr}"
                    
                    self.db.update_execution(execution_id, "success", 
                                          output=output, execution_time=execution_time)
                    logger.info(f"✅ Script completed successfully: {execution_id}")
                else:
                    # Error
                    error_output = stderr if stderr else stdout
                    self.db.update_execution(execution_id, "error", 
                                          error_message=error_output, execution_time=execution_time)
                    logger.error(f"❌ Script failed: {execution_id} - {error_output}")
                
            except subprocess.TimeoutExpired:
                process.kill()
                self.db.update_execution(execution_id, "error", 
                                      error_message=f"Script timeout after {timeout} seconds")
                logger.warning(f"⏰ Script timeout: {execution_id}")
            
        except Exception as e:
            execution_time = time.time() - start_time
            self.db.update_execution(execution_id, "error", 
                                  error_message=str(e), execution_time=execution_time)
            logger.error(f"💥 Script execution error {execution_id}: {e}")
        
        finally:
            # Cleanup
            if execution_id in self.active_executions:
                del self.active_executions[execution_id]
    
    def execute_script(self, user_id: int, module: str, script_name: str, 
                      parameters: Dict[str, Any]) -> str:
        """Start script execution"""
        execution_id = f"exec_{int(time.time() * 1000)}_{user_id}"
        
        # Create execution record
        self.db.create_execution(execution_id, user_id, module, script_name, parameters)
        
        # Start execution in background thread
        thread = threading.Thread(
            target=self.execute_script_async,
            args=(execution_id, user_id, module, script_name, parameters)
        )
        thread.daemon = True
        thread.start()
        
        return execution_id
    
    def stop_execution(self, execution_id: str, user_id: int) -> bool:
        """Stop running execution"""
        if execution_id in self.active_executions:
            process = self.active_executions[execution_id]
            try:
                # Send SIGTERM first
                process.terminate()
                time.sleep(2)
                
                # Force kill if still running
                if process.poll() is None:
                    process.kill()
                
                self.db.update_execution(execution_id, "cancelled", 
                                      error_message="Execution stopped by user")
                
                logger.info(f"🛑 Execution stopped: {execution_id}")
                return True
            except Exception as e:
                logger.error(f"Error stopping execution {execution_id}: {e}")
                return False
        
        return False
    
    def get_execution_status(self, execution_id: str) -> Optional[Dict[str, Any]]:
        """Get execution status"""
        executions = self.db.get_execution_history(limit=1000)
        for execution in executions:
            if execution['id'] == execution_id:
                return execution
        return None
    
    def cleanup_sandbox(self, execution_id: str):
        """Clean up sandbox directory"""
        sandbox_dir = Path(f"/app/temp/sandbox_{execution_id}")
        if sandbox_dir.exists():
            try:
                import shutil
                shutil.rmtree(sandbox_dir)
                logger.debug(f"🧹 Cleaned up sandbox: {execution_id}")
            except Exception as e:
                logger.error(f"Error cleaning sandbox {execution_id}: {e}")
    
    def get_system_stats(self) -> Dict[str, Any]:
        """Get system performance stats"""
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        stats = {
            "cpu_percent": cpu_percent,
            "memory_percent": memory.percent,
            "memory_available_gb": memory.available / (1024**3),
            "disk_free_gb": disk.free / (1024**3),
            "active_executions": len(self.active_executions),
            "timestamp": datetime.now().isoformat()
        }
        
        # Store metrics in database
        self.db.add_metric("cpu_usage", cpu_percent)
        self.db.add_metric("memory_usage", memory.percent)
        self.db.add_metric("active_executions", len(self.active_executions))
        
        return stats