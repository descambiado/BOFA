import json
import tempfile
import unittest
from pathlib import Path
from typing import Tuple
from unittest.mock import patch

from bofa.agent.demo.oauth_app_triage import DEMO_DIR
from bofa.agent.evidence import read_evidence
from bofa.agent.runner import DEMO_TOOLS, run_agent_demo


class AgentRunnerTests(unittest.TestCase):
    def _write_inputs(self, directory: Path, extra_allowed_tool: str = "") -> Tuple[Path, Path]:
        scope = json.loads((DEMO_DIR / "scope.oauth_triage.json").read_text(encoding="utf-8"))
        if extra_allowed_tool:
            scope["allowed_tools"].append(extra_allowed_tool)
        scope_path = directory / "scope.json"
        scope_path.write_text(json.dumps(scope), encoding="utf-8")
        input_data = json.loads((DEMO_DIR / "input.sample.json").read_text(encoding="utf-8"))
        if extra_allowed_tool:
            input_data["planned_tool_calls"].insert(0, extra_allowed_tool)
        input_path = directory / "input.json"
        input_path.write_text(json.dumps(input_data), encoding="utf-8")
        return scope_path, input_path

    def test_allowed_name_without_reviewed_implementation_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            scope_path, input_path = self._write_inputs(directory, "unimplemented_tool")
            paths = run_agent_demo(scope_path, input_path, directory / "run")

            report = json.loads(paths["report_json"].read_text(encoding="utf-8"))
            blocked = {item["tool"]: item["reason"] for item in report["blocked_tools"]}

        self.assertEqual(blocked["unimplemented_tool"], "tool has no reviewed implementation")
        self.assertEqual(blocked["fetch_live_tenant_users"], "tool is explicitly blocked")
        self.assertEqual(report["run_status"], "completed")

    def test_tool_exception_produces_partial_failure_report_without_exception_text(self) -> None:
        def fail(_input_data):
            raise RuntimeError("sensitive exception detail")

        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            scope_path, input_path = self._write_inputs(directory)
            with patch.dict(DEMO_TOOLS, {"inspect_oauth_metadata": fail}):
                paths = run_agent_demo(scope_path, input_path, directory / "run")

            report_text = paths["report_markdown"].read_text(encoding="utf-8")
            report = json.loads(paths["report_json"].read_text(encoding="utf-8"))

        self.assertEqual(report["run_status"], "partial_failed")
        self.assertEqual(report["failed_tools"][0]["error_type"], "RuntimeError")
        self.assertNotIn("sensitive exception detail", report_text)

    def test_invalid_tool_result_produces_partial_failure_report(self) -> None:
        invalid_result = {
            "tool": "inspect_oauth_metadata",
            "risk_delta": "critical",
            "findings": [],
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            scope_path, input_path = self._write_inputs(directory)
            with patch.dict(DEMO_TOOLS, {"inspect_oauth_metadata": lambda _data: invalid_result}):
                paths = run_agent_demo(scope_path, input_path, directory / "run")
            report = json.loads(paths["report_json"].read_text(encoding="utf-8"))

        self.assertEqual(report["run_status"], "partial_failed")
        self.assertEqual(report["failed_tools"][0]["error_type"], "ValueError")

    def test_malformed_input_fails_before_creating_run_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            scope_path, input_path = self._write_inputs(directory)
            input_data = json.loads(input_path.read_text(encoding="utf-8"))
            input_data["application"]["permissions"] = "Mail.Read"
            input_path.write_text(json.dumps(input_data), encoding="utf-8")
            output_dir = directory / "run"

            with self.assertRaisesRegex(ValueError, "application.permissions"):
                run_agent_demo(scope_path, input_path, output_dir)

        self.assertFalse(output_dir.exists())

    def test_existing_run_artifacts_are_preserved_unless_overwrite_is_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            scope_path, input_path = self._write_inputs(directory)
            output_dir = directory / "run"
            paths = run_agent_demo(scope_path, input_path, output_dir)
            paths["evidence"].write_text("modified evidence\n", encoding="utf-8")

            with self.assertRaises(FileExistsError):
                run_agent_demo(scope_path, input_path, output_dir)
            self.assertEqual(paths["evidence"].read_text(encoding="utf-8"), "modified evidence\n")

            run_agent_demo(scope_path, input_path, output_dir, overwrite=True)
            events = read_evidence(paths["evidence"])

        self.assertGreater(len(events), 0)
        self.assertEqual(events[-1].event_type, "run.complete")

    def test_report_records_hash_chain_head_and_explicit_unsigned_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            scope_path, input_path = self._write_inputs(directory)
            paths = run_agent_demo(scope_path, input_path, directory / "run")
            report = json.loads(paths["report_json"].read_text(encoding="utf-8"))
            events = read_evidence(paths["evidence"])

        integrity = report["evidence_integrity"]
        self.assertEqual(integrity["algorithm"], "sha256-chain")
        self.assertEqual(integrity["event_count"], len(events))
        self.assertEqual(integrity["chain_head"], events[-1].event_hash)
        self.assertTrue(integrity["verified_on_read"])
        self.assertEqual(integrity["signature"], "not_signed")


if __name__ == "__main__":
    unittest.main()
