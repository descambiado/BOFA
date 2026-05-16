"""Example SotyHub-style consumer for BOFA agent reports."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict


def load_report(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        report = json.load(handle)
    required = ["schema_version", "mission_id", "classification", "sotyhub"]
    missing = [key for key in required if key not in report]
    if missing:
        raise ValueError("report is missing required fields: " + ", ".join(missing))
    return report


def to_sotyhub_event(report: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "type": report["sotyhub"]["ingestion_type"],
        "dedupe_key": report["sotyhub"]["dedupe_key"],
        "severity": report["classification"]["severity"],
        "risk_score": report["classification"]["risk_score"],
        "subject": report["subject"],
        "findings_count": len(report.get("findings", [])),
        "blocked_tools_count": len(report.get("blocked_tools", [])),
    }


def main(argv: Any = None) -> None:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        raise SystemExit("usage: python examples/sotyhub_consumer.py path/to/report.json")
    event = to_sotyhub_event(load_report(Path(args[0])))
    print(json.dumps(event, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

