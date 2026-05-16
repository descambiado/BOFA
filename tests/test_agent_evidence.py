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


if __name__ == "__main__":
    unittest.main()
