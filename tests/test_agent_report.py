import tempfile
import unittest
from pathlib import Path

from bofa.agent.evidence import EvidenceRecorder, read_evidence
from bofa.agent.report import build_report
from bofa.agent.scope import load_scope


class ReportTests(unittest.TestCase):
    def test_report_includes_blocked_tools_and_sotyhub_shape(self) -> None:
        scope = load_scope(Path("bofa/agent/demo/scope.oauth_triage.json"))
        input_data = {
            "run_id": "demo",
            "observed_at": "2026-05-16T21:30:00Z",
            "application": {
                "application_id": "app-1",
                "display_name": "Synthetic App",
                "publisher": "Unknown Publisher",
            },
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            evidence_path = Path(temp_dir) / "evidence.jsonl"
            recorder = EvidenceRecorder(evidence_path, input_data["observed_at"])
            recorder.append(
                "tool.result",
                {
                    "tool": "inspect_oauth_metadata",
                    "risk_delta": 50,
                    "findings": [{"title": "Finding", "summary": "Summary"}],
                },
            )
            recorder.append(
                "tool.blocked",
                {"tool": "fetch_live_tenant_users", "reason": "tool is explicitly blocked"},
            )

            report = build_report(scope, input_data, read_evidence(evidence_path))

        self.assertEqual(report["classification"]["severity"], "medium")
        self.assertEqual(report["blocked_tools"][0]["tool"], "fetch_live_tenant_users")
        self.assertEqual(
            report["sotyhub"]["ingestion_type"], "passive_oauth_triage_report"
        )


if __name__ == "__main__":
    unittest.main()
