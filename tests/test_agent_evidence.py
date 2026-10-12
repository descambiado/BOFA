import json
import tempfile
import unittest
from pathlib import Path

from bofa.agent.evidence import EvidenceRecorder, read_evidence, summarize_evidence


class EvidenceTests(unittest.TestCase):
    def test_evidence_recorder_writes_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "evidence.jsonl"
            recorder = EvidenceRecorder(path, timestamp="2026-05-16T21:30:00Z")

            recorder.append("tool.allowed", {"tool": "inspect_oauth_metadata"})
            recorder.append("tool.blocked", {"tool": "fetch_live_tenant_users"})

            events = read_evidence(path)
            self.assertEqual([event.event_id for event in events], [1, 2])
            self.assertEqual(
                summarize_evidence(events), {"tool.allowed": 1, "tool.blocked": 1}
            )
            self.assertEqual(events[0].previous_hash, "0" * 64)
            self.assertEqual(events[1].previous_hash, events[0].event_hash)

    def test_evidence_reader_rejects_tampered_event_data(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "evidence.jsonl"
            recorder = EvidenceRecorder(path, timestamp="2026-05-16T21:30:00Z")
            recorder.append("tool.allowed", {"tool": "inspect_oauth_metadata"})
            row = json.loads(path.read_text(encoding="utf-8"))
            row["data"]["tool"] = "different_tool"
            path.write_text(json.dumps(row) + "\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "integrity check failed"):
                read_evidence(path)


if __name__ == "__main__":
    unittest.main()
