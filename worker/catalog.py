"""Load the immutable adapter and capability catalog baked into a worker image."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any, Mapping, Tuple

from core.execution import ExecutionCapability


CATALOG_SCHEMA = "bofa.worker-catalog/v1"
_ADAPTER_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,128}/[A-Za-z0-9_-]{1,128}")
_FLOW_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,128}")
_BLOCKED_CAPABILITIES = {
    ExecutionCapability.PRIVILEGED,
    ExecutionCapability.CLOUD_MUTATION,
}


@dataclass(frozen=True)
class WorkerCatalog:
    capabilities: Tuple[ExecutionCapability, ...]
    network_modes: Tuple[str, ...]
    scripts: Tuple[str, ...]
    flows: Tuple[str, ...]


def _string_list(payload: Mapping[str, Any], key: str) -> Tuple[str, ...]:
    values = payload.get(key)
    if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
        raise ValueError(f"Worker catalog field '{key}' must be a string list")
    if any(not value or value != value.strip() for value in values):
        raise ValueError(f"Worker catalog field '{key}' contains an empty or padded value")
    normalized = tuple(sorted({value.strip() for value in values if value.strip()}))
    if len(normalized) != len(values):
        raise ValueError(f"Worker catalog field '{key}' contains empty or duplicate values")
    return normalized


def load_worker_catalog(path: str | Path) -> WorkerCatalog:
    catalog_path = Path(path)
    payload = json.loads(catalog_path.read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping) or payload.get("schema") != CATALOG_SCHEMA:
        raise ValueError(f"Worker catalog must use schema {CATALOG_SCHEMA}")

    capabilities = tuple(ExecutionCapability(value) for value in _string_list(payload, "capabilities"))
    if not capabilities or set(capabilities) & _BLOCKED_CAPABILITIES:
        raise ValueError("Worker catalog must declare safe capabilities")

    network_modes = _string_list(payload, "network_modes")
    if not network_modes or any(value not in {"none", "restricted"} for value in network_modes):
        raise ValueError("Worker catalog has an unsupported network mode")

    scripts = _string_list(payload, "scripts")
    flows = _string_list(payload, "flows")
    if any(not _ADAPTER_PATTERN.fullmatch(value) for value in scripts):
        raise ValueError("Worker catalog has an invalid script adapter")
    if any(not _FLOW_PATTERN.fullmatch(value) for value in flows):
        raise ValueError("Worker catalog has an invalid flow adapter")
    if not scripts and not flows:
        raise ValueError("Worker catalog must allow at least one adapter")

    return WorkerCatalog(
        capabilities=capabilities,
        network_modes=network_modes,
        scripts=scripts,
        flows=flows,
    )
