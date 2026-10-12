import json
import tempfile
import unittest
from pathlib import Path

from bofa.agent.demo.oauth_app_triage import DEMO_DIR
from bofa.agent.runner import run_agent_demo
from bofa.agent.verify_bundle import verify_report_evidence


class BundleVerificationTests(unittest.TestCase):
    def _run_demo(self, directory: Path):
        return run_agent_demo(
            DEMO_DIR / "scope.oauth_triage.json",
            DEMO_DIR / "input.sample.json",
            directory / "run",
        )

    def test_report_and_evidence_bundle_verify(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            outputs = self._run_demo(Path(temp_dir))
            result = verify_report_evidence(outputs["report_json"], outputs["evidence"])

        self.assertTrue(result["verified"])
        self.assertEqual(result["event_count"], 9)
        self.assertTrue(result["evidence_verified_on_report_creation"])
        self.assertEqual(result["signature_state"], "not_signed")
        self.assertFalse(result["signature_verified"])

    def test_verifier_rejects_tampered_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            outputs = self._run_demo(Path(temp_dir))
            rows = outputs["evidence"].read_text(encoding="utf-8").splitlines()
            row = json.loads(rows[0])
            row["data"]["run_id"] = "changed"
            rows[0] = json.dumps(row)
            outputs["evidence"].write_text("\n".join(rows) + "\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "integrity check failed"):
                verify_report_evidence(outputs["report_json"], outputs["evidence"])

    def test_verifier_rejects_report_chain_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            outputs = self._run_demo(Path(temp_dir))
            report = json.loads(outputs["report_json"].read_text(encoding="utf-8"))
            report["evidence_integrity"]["event_count"] += 1
            outputs["report_json"].write_text(
                json.dumps(report), encoding="utf-8"
            )

            with self.assertRaisesRegex(ValueError, "event counts do not match"):
                verify_report_evidence(outputs["report_json"], outputs["evidence"])

    def test_verifier_rejects_unimplemented_hash_algorithm(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            outputs = self._run_demo(Path(temp_dir))
            report = json.loads(outputs["report_json"].read_text(encoding="utf-8"))
            report["evidence_integrity"]["algorithm"] = "sha512-chain"
            outputs["report_json"].write_text(json.dumps(report), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "unsupported evidence algorithm"):
                verify_report_evidence(outputs["report_json"], outputs["evidence"])


if __name__ == "__main__":
    unittest.main()
