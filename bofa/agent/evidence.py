"""JSONL evidence recorder for deterministic agent runs."""

from __future__ import annotations

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

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "data": self.data,
        }


class EvidenceRecorder:
    def __init__(self, path: Path, timestamp: str) -> None:
        self.path = path
        self.timestamp = timestamp
        self._next_id = 1
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("", encoding="utf-8")

    def append(self, event_type: str, data: Mapping[str, Any]) -> EvidenceEvent:
        event = EvidenceEvent(
            event_id=self._next_id,
            event_type=event_type,
            timestamp=self.timestamp,
            data=dict(data),
        )
        self._next_id += 1
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event.to_dict(), sort_keys=True) + "\n")
        return event


def read_evidence(path: Path) -> List[EvidenceEvent]:
    events: List[EvidenceEvent] = []
    if not path.exists():
        return events

    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            events.append(
                EvidenceEvent(
                    event_id=int(row["event_id"]),
                    event_type=str(row["event_type"]),
                    timestamp=str(row["timestamp"]),
                    data=dict(row.get("data", {})),
                )
            )
    return events


def summarize_evidence(events: Iterable[EvidenceEvent]) -> Dict[str, int]:
    summary: Dict[str, int] = {}
    for event in events:
        summary[event.event_type] = summary.get(event.event_type, 0) + 1
    return summary

