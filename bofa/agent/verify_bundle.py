"""Offline consistency checks for a BOFA report and its JSONL evidence."""

from __future__ import annotations

import argparse
import hmac
import json
import sys
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence

from bofa.agent.evidence import read_evidence


def verify_report_evidence(report_path: Path, evidence_path: Path) -> Dict[str, Any]:
    if not report_path.is_file():
        raise ValueError("report file does not exist")
    if not evidence_path.is_file():
        raise ValueError("evidence file does not exist")

    with report_path.open("r", encoding="utf-8") as handle:
        report = json.load(handle)
    if not isinstance(report, Mapping):
        raise ValueError("report must be a JSON object")

    integrity = report.get("evidence_integrity")
    if not isinstance(integrity, Mapping):
        raise ValueError("report is missing evidence_integrity metadata")
    if integrity.get("algorithm") != "sha256-chain":
        raise ValueError("report declares an unsupported evidence algorithm")
    signature_state = integrity.get("signature")
    if not isinstance(signature_state, str) or not signature_state:
        raise ValueError("report evidence signature state is missing")

    events = read_evidence(evidence_path)
    if not events:
        raise ValueError("evidence file contains no events")
    declared_count = integrity.get("event_count")
    if isinstance(declared_count, bool) or not isinstance(declared_count, int):
        raise ValueError("report evidence event_count must be an integer")
    if declared_count != len(events):
        raise ValueError("report and evidence event counts do not match")

    actual_head = events[-1].event_hash if events else None
    declared_head = integrity.get("chain_head")
    if actual_head is None or not isinstance(declared_head, str):
        if actual_head != declared_head:
            raise ValueError("report and evidence chain heads do not match")
    elif not hmac.compare_digest(actual_head, declared_head):
        raise ValueError("report and evidence chain heads do not match")

    return {
        "verified": True,
        "event_count": len(events),
        "chain_head": actual_head,
        "evidence_verified_on_report_creation": integrity.get("verified_on_read") is True,
        "signature_state": signature_state,
        "signature_verified": False,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify a BOFA report against its hash-chained JSONL evidence."
    )
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args(argv)

    try:
        result = verify_report_evidence(args.report, args.evidence)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Bundle verification failed: {error}", file=sys.stderr)
        return 1

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
