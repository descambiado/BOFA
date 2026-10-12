import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from bofa.agent.demo.oauth_app_triage import DEMO_DIR
from bofa.agent.runner import run_agent_demo


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


class AgentIntegrationTests(unittest.TestCase):
    def test_synthetic_run_matches_golden_consumer_contract(self) -> None:
        scope_path = DEMO_DIR / "scope.oauth_triage.json"
        input_path = DEMO_DIR / "input.sample.json"
        golden_path = DEMO_DIR / "golden_output.json"

        with tempfile.TemporaryDirectory() as temp_dir:
            outputs = run_agent_demo(scope_path, input_path, Path(temp_dir) / "run")
            command = [
                sys.executable,
                str(REPOSITORY_ROOT / "examples" / "sotyhub_consumer.py"),
                str(outputs["report_json"]),
            ]
            result = subprocess.run(
                command,
                cwd=REPOSITORY_ROOT,
                capture_output=True,
                check=True,
                text=True,
            )
            verification = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "bofa.agent.verify_bundle",
                    "--report",
                    str(outputs["report_json"]),
                    "--evidence",
                    str(outputs["evidence"]),
                ],
                cwd=REPOSITORY_ROOT,
                capture_output=True,
                check=True,
                text=True,
            )

        actual = json.loads(result.stdout)
        self.assertTrue(json.loads(verification.stdout)["verified"])
        expected = json.loads(golden_path.read_text(encoding="utf-8"))
        self.assertEqual(
            actual,
            {
                "blocked_tools_count": expected["blocked_tools_count"],
                "dedupe_key": "bofa-agent-oauth-triage-v1:synthetic-app-001",
                "findings_count": expected["findings_count"],
                "risk_score": expected["classification"]["risk_score"],
                "severity": expected["classification"]["severity"],
                "subject": {
                    "application_id": "synthetic-app-001",
                    "display_name": "Contoso Docs Sync Preview",
                    "publisher": "Unknown Publisher",
                },
                "type": expected["sotyhub_ingestion_type"],
            },
        )


if __name__ == "__main__":
    unittest.main()
