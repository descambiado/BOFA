#!/usr/bin/env python3
"""Build and execute the harmless BOFA OCI worker proof locally."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid


_ROOT = Path(__file__).resolve().parent.parent
_IMAGE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}")
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")


def _run(command, capture: bool = False) -> str:
    result = subprocess.run(
        command,
        cwd=_ROOT,
        check=False,
        text=True,
        capture_output=capture,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(f"Command failed ({result.returncode}): {detail}")
    return (result.stdout or "").strip()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run BOFA's locked-down OCI worker proof")
    parser.add_argument("--image", default="bofa-worker:dev")
    parser.add_argument("--build", action="store_true", help="Build the local image before the proof")
    args = parser.parse_args()
    if not _IMAGE_PATTERN.fullmatch(args.image) or "@" in args.image:
        parser.error("--image must be a local repository or tag without a digest")

    try:
        _run(["docker", "version"], capture=True)
        if args.build:
            _run(
                [
                    "docker",
                    "build",
                    "--file",
                    "worker/Dockerfile",
                    "--tag",
                    args.image,
                    ".",
                ]
            )
        image_digest = _run(
            ["docker", "image", "inspect", "--format={{.Id}}", args.image],
            capture=True,
        )
        if not _DIGEST_PATTERN.fullmatch(image_digest):
            raise RuntimeError("Docker returned an invalid local image identity")

        run_name = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
        run_dir = _ROOT / "data" / "demo_worker_oci" / run_name
        claims_dir = run_dir / "claims"
        receipt_dir = run_dir / "receipt"
        claims_dir.mkdir(parents=True)
        receipt_dir.mkdir()
        if os.name != "nt":
            claims_dir.chmod(0o777)
            receipt_dir.chmod(0o777)

        _run(
            [
                sys.executable,
                "tools/create_worker_fixture.py",
                str(run_dir),
                "--image-reference",
                args.image,
                "--image-digest",
                image_digest,
            ]
        )
        _run(
            [
                "docker",
                "run",
                "--rm",
                "--read-only",
                "--network",
                "none",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges=true",
                "--pids-limit",
                "64",
                "--memory",
                "256m",
                "--cpus",
                "1",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size=16m",
                "--tmpfs",
                "/opt/bofa/logs:rw,noexec,nosuid,nodev,size=8m",
                "--tmpfs",
                "/opt/bofa/output:rw,noexec,nosuid,nodev,size=8m",
                "--tmpfs",
                "/opt/bofa/reports:rw,noexec,nosuid,nodev,size=8m",
                "--mount",
                f"type=bind,src={run_dir / 'job.json'},dst=/run/bofa/job.json,readonly",
                "--mount",
                (
                    f"type=bind,src={run_dir / 'control-plane-public.pem'},"
                    "dst=/run/secrets/bofa-control-plane.pem,readonly"
                ),
                "--mount",
                f"type=bind,src={claims_dir},dst=/var/lib/bofa-worker/claims",
                "--mount",
                f"type=bind,src={receipt_dir},dst=/run/bofa-out",
                "--env",
                "BOFA_WORKER_MODE=execute",
                "--env",
                "BOFA_WORKER_ID=local-proof",
                "--env",
                f"BOFA_IMAGE_REFERENCE={args.image}",
                "--env",
                f"BOFA_IMAGE_DIGEST={image_digest}",
                args.image,
            ]
        )
        receipt_path = receipt_dir / "receipt.json"
        _run(
            [
                sys.executable,
                "tools/verify_worker_oci.py",
                "--receipt",
                str(receipt_path),
                "--job",
                str(run_dir / "job.json"),
                "--expected-image-reference",
                args.image,
                "--expected-image-digest",
                image_digest,
            ]
        )
        print(f"Verified receipt: {receipt_path}")
        return 0
    except (FileNotFoundError, RuntimeError) as exc:
        print(f"BOFA OCI proof failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
