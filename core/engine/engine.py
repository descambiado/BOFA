"""
BOFAEngine - Motor Central de BOFA
==================================

Motor central que gestiona modulos, scripts y ejecuciones.
"""

import os
import subprocess
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..cancellation import check_cancelled
from ..config import get_config
from ..errors import ExecutionError, ScriptNotFoundError, ValidationError
from ..logger import get_logger
from ..utils import ModuleLoader, ScriptValidator, get_script_path

logger = get_logger(__name__)


@dataclass
class ExecutionResult:
    """Resultado de una ejecucion de script."""

    execution_id: str
    script_name: str
    module_name: str
    status: str
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    duration: float = 0.0
    timestamp: str = ""
    error: Optional[str] = None

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat()


class BOFAEngine:
    """Motor central de BOFA."""

    def __init__(self, config=None):
        self.config = config or get_config()
        self.module_loader = ModuleLoader(self.config.base_path)
        self._modules: Dict[str, Any] = {}
        self._initialized = False
        logger.info("BOFA Engine inicializado", base_path=str(self.config.base_path))

    def initialize(self) -> None:
        if self._initialized:
            return

        try:
            if self.config.auto_discover_modules:
                logger.info("Descubriendo modulos...")
                self._modules = self.module_loader.discover_modules()
                logger.info(f"Modulos cargados: {len(self._modules)}", modules=list(self._modules.keys()))
            self._initialized = True
        except Exception as exc:
            logger.error(f"Error inicializando motor: {exc}")
            raise

    def get_module(self, module_name: str) -> Any:
        return self.module_loader.get_module(module_name)

    def get_script(self, module_name: str, script_name: str) -> Any:
        return self.module_loader.get_script(module_name, script_name)

    def list_modules(self) -> List[str]:
        if not self._modules:
            self.initialize()
        return self.module_loader.list_modules()

    def list_scripts(self, module_name: Optional[str] = None) -> Dict[str, List[str]]:
        return self.module_loader.list_scripts(module_name)

    def validate_script(self, module_name: str, script_name: str, parameters: Optional[Dict[str, Any]] = None) -> bool:
        script_info = self.get_script(module_name, script_name)
        script_path = get_script_path(self.config.base_path, module_name, script_name)
        validator = ScriptValidator(script_path)
        validator.validate_all(parameters, script_info.parameters)
        logger.debug(f"Script validado: {module_name}/{script_name}", module=module_name, script=script_name)
        return True

    def execute_script(
        self,
        module_name: str,
        script_name: str,
        parameters: Optional[Dict[str, Any]] = None,
        execution_id: Optional[str] = None,
        timeout: Optional[int] = None,
        extra_env: Optional[Dict[str, str]] = None,
        cancel_file: Optional[str] = None,
        cancel_check_interval: float = 0.5,
    ) -> ExecutionResult:
        import uuid

        execution_id = execution_id or str(uuid.uuid4())
        parameters = parameters or {}
        timeout = timeout or self.config.execution_timeout

        logger.info(
            f"Ejecutando script: {module_name}/{script_name}",
            execution_id=execution_id,
            module=module_name,
            script=script_name,
            parameters=parameters,
        )

        try:
            self.validate_script(module_name, script_name, parameters)
        except (ScriptNotFoundError, ValidationError):
            logger.error("Validacion fallida", module=module_name, script=script_name)
            raise

        script_path = get_script_path(self.config.base_path, module_name, script_name)
        cmd = ["python3", str(script_path)]
        for key, value in parameters.items():
            if isinstance(value, bool):
                if value:
                    cmd.append(f"--{key}")
            else:
                cmd.extend([f"--{key}", str(value)])

        start_time = datetime.utcnow()
        env = self._get_execution_env()
        if extra_env:
            env.update({key: str(value) for key, value in extra_env.items() if value is not None})
        if cancel_file:
            env["BOFA_CANCEL_FILE"] = str(cancel_file)
            env["BOFA_CANCEL_CHECK_INTERVAL"] = str(cancel_check_interval)

        if cancel_file and check_cancelled(cancel_file):
            duration = (datetime.utcnow() - start_time).total_seconds()
            return ExecutionResult(
                execution_id=execution_id,
                script_name=script_name,
                module_name=module_name,
                status="cancelled",
                exit_code=130,
                duration=duration,
                error="Execution cancelled before start",
            )

        process = None
        stdout = ""
        stderr = ""
        cancellation_requested = False
        forced = False

        try:
            process = subprocess.Popen(
                cmd,
                cwd=script_path.parent,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )

            while True:
                elapsed = (datetime.utcnow() - start_time).total_seconds()
                if timeout and elapsed >= timeout:
                    process.kill()
                    stdout, stderr = process.communicate()
                    duration = (datetime.utcnow() - start_time).total_seconds()
                    logger.error(f"Timeout ejecutando script: {module_name}/{script_name}", timeout=timeout)
                    raise ExecutionError(
                        f"Timeout ejecutando script despues de {timeout} segundos",
                        script_name=script_name,
                        details={"timeout": timeout, "duration": duration},
                    )

                if cancel_file and check_cancelled(cancel_file):
                    cancellation_requested = True
                    process.terminate()
                    try:
                        stdout, stderr = process.communicate(timeout=max(cancel_check_interval * 4, 1.0))
                    except subprocess.TimeoutExpired:
                        forced = True
                        process.kill()
                        stdout, stderr = process.communicate()
                    break

                try:
                    stdout, stderr = process.communicate(timeout=cancel_check_interval)
                    break
                except subprocess.TimeoutExpired:
                    continue

            duration = (datetime.utcnow() - start_time).total_seconds()

            if cancellation_requested:
                return ExecutionResult(
                    execution_id=execution_id,
                    script_name=script_name,
                    module_name=module_name,
                    status="cancelled",
                    exit_code=process.returncode if process and process.returncode is not None else 130,
                    stdout=stdout,
                    stderr=stderr,
                    duration=duration,
                    error="Execution cancelled" + (" (forced)" if forced else ""),
                )

            if process.returncode == 0:
                logger.info(f"Script ejecutado exitosamente: {module_name}/{script_name}", duration=duration)
            else:
                logger.warning(
                    f"Script fallo: {module_name}/{script_name}",
                    exit_code=process.returncode,
                    error=stderr or "Script failed",
                )

            return ExecutionResult(
                execution_id=execution_id,
                script_name=script_name,
                module_name=module_name,
                status="success" if process.returncode == 0 else "error",
                exit_code=process.returncode,
                stdout=stdout,
                stderr=stderr,
                duration=duration,
                error=stderr or "Script failed" if process.returncode != 0 else None,
            )

        except subprocess.TimeoutExpired:
            if process:
                process.kill()
            duration = (datetime.utcnow() - start_time).total_seconds()
            logger.error(f"Timeout ejecutando script: {module_name}/{script_name}", timeout=timeout)
            raise ExecutionError(
                f"Timeout ejecutando script despues de {timeout} segundos",
                script_name=script_name,
                details={"timeout": timeout, "duration": duration},
            )
        except ExecutionError:
            raise
        except Exception as exc:
            duration = (datetime.utcnow() - start_time).total_seconds()
            logger.exception(
                "Error ejecutando script (traceback abajo)",
                extra={"module": module_name, "script": script_name, "error": str(exc)},
            )
            raise ExecutionError(
                f"Error ejecutando script: {str(exc)}",
                script_name=script_name,
                details={"error": str(exc), "duration": duration},
            )

    def _get_execution_env(self) -> Dict[str, str]:
        env = os.environ.copy()
        env["BOFA_BASE_PATH"] = str(self.config.base_path)
        env["BOFA_SCRIPTS_PATH"] = str(self.config.scripts_path)
        env["BOFA_OUTPUT_PATH"] = str(self.config.output_path)
        env["BOFA_LOGS_PATH"] = str(self.config.logs_path)
        return env


_engine: Optional[BOFAEngine] = None


def get_engine(config=None) -> BOFAEngine:
    global _engine
    if _engine is None:
        _engine = BOFAEngine(config)
        _engine.initialize()
    return _engine
