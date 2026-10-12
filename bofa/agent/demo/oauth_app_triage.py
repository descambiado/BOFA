"""Run the deterministic passive OAuth application triage demo."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Optional, Sequence

from bofa.agent.runner import run_agent_demo


DEMO_DIR = Path(__file__).resolve().parent


def main(argv: Optional[Sequence[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Run the passive synthetic OAuth triage demo.")
    parser.add_argument("--scope", type=Path, default=DEMO_DIR / "scope.oauth_triage.json")
    parser.add_argument("--input", type=Path, default=DEMO_DIR / "input.sample.json")
    parser.add_argument("--output-dir", type=Path, default=DEMO_DIR / "output")
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="replace existing evidence and report artifacts in the output directory",
    )
    args = parser.parse_args(argv)
    outputs = run_agent_demo(
        scope_path=args.scope,
        input_path=args.input,
        output_dir=args.output_dir,
        overwrite=args.overwrite,
    )
    print("BOFA OAuth triage demo complete")
    for label, path in outputs.items():
        print(f"{label}: {path}")


if __name__ == "__main__":
    main()
