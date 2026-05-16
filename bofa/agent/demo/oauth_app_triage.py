"""Run the deterministic passive OAuth application triage demo."""

from __future__ import annotations

from pathlib import Path

from bofa.agent.runner import run_agent_demo


DEMO_DIR = Path(__file__).resolve().parent


def main() -> None:
    outputs = run_agent_demo(
        scope_path=DEMO_DIR / "scope.oauth_triage.json",
        input_path=DEMO_DIR / "input.sample.json",
        output_dir=DEMO_DIR / "output",
    )
    print("BOFA OAuth triage demo complete")
    for label, path in outputs.items():
        print(f"{label}: {path}")


if __name__ == "__main__":
    main()

