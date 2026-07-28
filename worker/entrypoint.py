"""Strict one-job entrypoint for the BOFA OCI worker image."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Dict, Mapping

from worker.adapter_executor import OCIAdapterExecutor
from worker.catalog import load_worker_catalog
from worker.runtime import WorkerRuntime


RECEIPT_SCHEMA = "bofa.worker-receipt/v1"
_WORKER_ID_PATTERN = re.compile(r"[A-Za-z0-9_.-]{1,128}")
_IMAGE_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
_MAX_JOB_BYTES = 1024 * 1024
_MAX_KEY_BYTES = 64 * 1024


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _required_file(path: Path, label: str, max_bytes: int) -> Path:
    if not path.is_file():
        raise ValueError(f"{label} is not a regular file")
    size = path.stat().st_size
    if size <= 0 or size > max_bytes:
        raise ValueError(f"{label} size is outside the accepted range")
    return path


def _observed_network_mode() -> str:
    interfaces_path = Path("/sys/class/net")
    if not interfaces_path.is_dir():
        return "unknown"
    interfaces = {entry.name for entry in interfaces_path.iterdir()}
    return "none" if interfaces.issubset({"lo"}) else "connected"


def _write_receipt(path: Path, receipt: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(receipt, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def _configuration() -> Dict[str, Any]:
    worker_id = os.getenv("BOFA_WORKER_ID", "bofa-oci-worker").strip()
    image_reference = os.getenv("BOFA_IMAGE_REFERENCE", "").strip()
    image_digest = os.getenv("BOFA_IMAGE_DIGEST", "").strip()
    mode = os.getenv("BOFA_WORKER_MODE", "inspect").strip().lower()
    if not _WORKER_ID_PATTERN.fullmatch(worker_id):
        raise ValueError("BOFA_WORKER_ID is invalid")
    if not image_reference or "@" in image_reference:
        raise ValueError("BOFA_IMAGE_REFERENCE must be a repository or tag without a digest")
    if not _IMAGE_DIGEST_PATTERN.fullmatch(image_digest):
        raise ValueError("BOFA_IMAGE_DIGEST must be an exact lowercase sha256 digest")
    if mode not in {"inspect", "execute"}:
        raise ValueError("BOFA_WORKER_MODE must be inspect or execute")
    return {
        "worker_id": worker_id,
        "image_reference": image_reference,
        "image_digest": image_digest,
        "mode": mode,
        "job_path": Path(os.getenv("BOFA_JOB_ENVELOPE", "/run/bofa/job.json")),
        "key_path": Path(
            os.getenv("BOFA_TRUSTED_PUBLIC_KEY", "/run/secrets/bofa-control-plane.pem")
        ),
        "receipt_path": Path(os.getenv("BOFA_RECEIPT_PATH", "/run/bofa-out/receipt.json")),
        "replay_store": Path(
            os.getenv("BOFA_REPLAY_STORE", "/var/lib/bofa-worker/claims")
        ),
    }


def main() -> int:
    receipt_path = Path(os.getenv("BOFA_RECEIPT_PATH", "/run/bofa-out/receipt.json"))
    try:
        config = _configuration()
        catalog = load_worker_catalog(Path(__file__).with_name("catalog.json"))
        observed_network_mode = _observed_network_mode()
        if observed_network_mode not in catalog.network_modes:
            raise ValueError(
                f"Observed network mode '{observed_network_mode}' is not allowed by this image"
            )
        job_path = _required_file(config["job_path"], "job envelope", _MAX_JOB_BYTES)
        key_path = _required_file(config["key_path"], "trusted public key", _MAX_KEY_BYTES)
        envelope = json.loads(job_path.read_text(encoding="utf-8"))
        if not isinstance(envelope, Mapping):
            raise ValueError("Job envelope must be a JSON object")

        runtime = WorkerRuntime(
            worker_id=config["worker_id"],
            trusted_public_key_pem=key_path.read_bytes(),
            capabilities=catalog.capabilities,
            image_reference=config["image_reference"],
            image_digest=config["image_digest"],
            runtime_network_mode=observed_network_mode,
            allowed_scripts=catalog.scripts,
            allowed_flows=catalog.flows,
            script_executor=OCIAdapterExecutor(Path(os.getenv("BOFA_BASE_PATH", "/opt/bofa"))),
            replay_store_path=config["replay_store"],
        )
        result = (
            runtime.execute(envelope)
            if config["mode"] == "execute"
            else runtime.inspect(envelope)
        )
        receipt = {
            **result,
            "receipt_schema": RECEIPT_SCHEMA,
            "worker_id": config["worker_id"],
            "worker_image": config["image_reference"],
            "worker_image_digest": config["image_digest"],
            "runtime_network_mode": observed_network_mode,
            "mode": config["mode"],
            "receipt_created_at": _utc_timestamp(),
        }
        _write_receipt(config["receipt_path"], receipt)
        print(json.dumps(receipt, ensure_ascii=False))
        accepted = result.get("accepted", result.get("status") not in {"denied", "failed"})
        return 0 if accepted else 1
    except Exception as exc:
        failure = {
            "receipt_schema": RECEIPT_SCHEMA,
            "status": "worker_error",
            "executed": False,
            "error": str(exc),
            "receipt_created_at": _utc_timestamp(),
        }
        try:
            _write_receipt(receipt_path, failure)
        except Exception:
            pass
        print(json.dumps(failure, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
