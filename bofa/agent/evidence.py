"""JSONL evidence recorder for deterministic agent runs."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional


@dataclass(frozen=True)
class EvidenceEvent:
    event_id: int
    event_type: str
    timestamp: str
    data: Dict[str, Any]
    previous_hash: str
    event_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "event_hash": self.event_hash,
        }


class EvidenceRecorder:
    _GENESIS_HASH = "0" * 64

    def __init__(self, path: Path, timestamp: str, overwrite: bool = False) -> None:
        self.path = path
        self.timestamp = timestamp
        self._next_id = 1
        self._previous_hash = self._GENESIS_HASH
        self.path.parent.mkdir(parents=True, exist_ok=True)
        mode = "w" if overwrite else "x"
        with self.path.open(mode, encoding="utf-8"):
            pass

    def append(self, event_type: str, data: Mapping[str, Any]) -> EvidenceEvent:
        payload = {
            "event_id": self._next_id,
            "event_type": event_type,
            "timestamp": self.timestamp,
            "data": dict(data),
            "previous_hash": self._previous_hash,
        }
        event_hash = _hash_event(payload)
        event = EvidenceEvent(**payload, event_hash=event_hash)
        self._next_id += 1
        self._previous_hash = event_hash
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event.to_dict(), sort_keys=True) + "\n")
        return event


def read_evidence(path: Path) -> List[EvidenceEvent]:
    events: List[EvidenceEvent] = []
    if not path.exists():
        return events

    previous_hash = EvidenceRecorder._GENESIS_HASH
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            row = json.loads(line)
            payload = {
                "event_id": int(row["event_id"]),
                "event_type": str(row["event_type"]),
                "timestamp": str(row["timestamp"]),
                "data": dict(row.get("data", {})),
                "previous_hash": str(row["previous_hash"]),
            }
            expected_hash = _hash_event(payload)
            if (
                payload["event_id"] != len(events) + 1
                or not hmac.compare_digest(payload["previous_hash"], previous_hash)
                or not hmac.compare_digest(str(row.get("event_hash", "")), expected_hash)
            ):
                raise ValueError(f"Evidence integrity check failed at line {line_number}.")
            event = EvidenceEvent(**payload, event_hash=expected_hash)
            events.append(event)
            previous_hash = expected_hash
    return events


def _hash_event(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def summarize_evidence(events: Iterable[EvidenceEvent]) -> Dict[str, int]:
    summary: Dict[str, int] = {}
    for event in events:
        summary[event.event_type] = summary.get(event.event_type, 0) + 1
    return summary
