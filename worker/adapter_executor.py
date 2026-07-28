"""Bounded subprocess adapter used by the locked-down OCI worker."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import threading
from typing import Any, Dict, Mapping


_CHUNK_BYTES = 8192


class OCIAdapterExecutor:
    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()

    def __call__(
        self,
        module: str,
        script: str,
        parameters: Mapping[str, Any],
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> Dict[str, Any]:
        script_path = (self.root / "scripts" / module / f"{script}.py").resolve()
        expected_parent = (self.root / "scripts" / module).resolve()
        if script_path.parent != expected_parent or not script_path.is_file():
            raise ValueError("Adapter path is outside the worker catalog")

        command = [sys.executable, str(script_path)]
        for key, value in parameters.items():
            if not isinstance(key, str) or not key.replace("_", "").isalnum():
                raise ValueError("Adapter parameter name is invalid")
            if isinstance(value, bool):
                if value:
                    command.append(f"--{key}")
            elif isinstance(value, (str, int, float)):
                command.extend((f"--{key}", str(value)))
            else:
                raise ValueError(f"Adapter parameter '{key}' must be a scalar")

        process = subprocess.Popen(
            command,
            cwd=script_path.parent,
            env=self._execution_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        state = {"total": 0, "limit_exceeded": False}
        state_lock = threading.Lock()

        def read_stream(name: str, stream) -> None:
            while True:
                chunk = stream.read(_CHUNK_BYTES)
                if not chunk:
                    return
                with state_lock:
                    state["total"] += len(chunk)
                    remaining = max(0, max_output_bytes - sum(len(value) for value in buffers.values()))
                    if remaining:
                        buffers[name].extend(chunk[:remaining])
                    if state["total"] > max_output_bytes:
                        state["limit_exceeded"] = True
                if state["limit_exceeded"]:
                    try:
                        process.kill()
                    except OSError:
                        pass
                    return

        readers = [
            threading.Thread(target=read_stream, args=("stdout", process.stdout), daemon=True),
            threading.Thread(target=read_stream, args=("stderr", process.stderr), daemon=True),
        ]
        for reader in readers:
            reader.start()

        timed_out = False
        try:
            process.wait(timeout=max(0.001, timeout_seconds))
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            process.wait()
        finally:
            for reader in readers:
                reader.join(timeout=2)
            if process.stdout:
                process.stdout.close()
            if process.stderr:
                process.stderr.close()

        stdout = bytes(buffers["stdout"]).decode("utf-8", errors="replace")
        stderr = bytes(buffers["stderr"]).decode("utf-8", errors="replace")
        if timed_out:
            return {
                "status": "failed",
                "exit_code": process.returncode,
                "stdout": stdout,
                "stderr": stderr,
                "error": "execution_timeout_exceeded",
            }
        if state["limit_exceeded"]:
            return {
                "status": "failed",
                "exit_code": process.returncode,
                "stdout": stdout,
                "stderr": stderr,
                "error": "output_limit_exceeded",
            }
        return {
            "status": "success" if process.returncode == 0 else "failed",
            "exit_code": process.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "error": None if process.returncode == 0 else "adapter_failed",
        }

    def _execution_environment(self) -> Dict[str, str]:
        environment = {
            "PATH": os.getenv("PATH", ""),
            "PYTHONPATH": str(self.root),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUNBUFFERED": "1",
            "BOFA_BASE_PATH": str(self.root),
            "BOFA_SCRIPTS_PATH": str(self.root / "scripts"),
            "BOFA_OUTPUT_PATH": str(self.root / "output"),
            "BOFA_LOGS_PATH": str(self.root / "logs"),
        }
        for name in ("LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR"):
            if os.getenv(name):
                environment[name] = os.environ[name]
        return environment
