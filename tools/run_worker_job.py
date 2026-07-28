#!/usr/bin/env python3
"""Verify and execute one signed BOFA job on an ephemeral worker."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from worker import WorkerRuntime
from worker.catalog import load_worker_catalog


def main() -> int:
    parser = argparse.ArgumentParser(description="Run one signed BOFA worker job")
    parser.add_argument("envelope", help="Signed job envelope JSON")
    parser.add_argument("--trusted-key", required=True, help="Pinned control-plane Ed25519 public key")
    parser.add_argument("--worker-id", default="worker-local")
    parser.add_argument(
        "--catalog",
        default=str(_ROOT / "worker" / "catalog.json"),
        help="Immutable worker capability and adapter catalog",
    )
    parser.add_argument("--image-reference", required=True, help="Launched worker image repository or tag")
    parser.add_argument("--image-digest", required=True, help="Launched worker image sha256 digest")
    parser.add_argument(
        "--runtime-network-mode",
        required=True,
        choices=("none", "restricted"),
        help="Network isolation mode enforced by the surrounding runtime",
    )
    parser.add_argument(
        "--replay-store",
        help="Persistent directory for atomic one-use job claims",
    )
    parser.add_argument(
        "--capability",
        action="append",
        dest="capabilities",
        default=[],
        help="Worker capability; repeat for each allowed capability",
    )
    parser.add_argument("--execute", action="store_true", help="Execute after verification; otherwise inspect only")
    args = parser.parse_args()

    envelope = json.loads(Path(args.envelope).read_text(encoding="utf-8"))
    catalog = load_worker_catalog(args.catalog)
    capabilities = args.capabilities or [item.value for item in catalog.capabilities]
    if not set(capabilities).issubset({item.value for item in catalog.capabilities}):
        parser.error("--capability cannot exceed the immutable worker catalog")
    if args.runtime_network_mode not in catalog.network_modes:
        parser.error("--runtime-network-mode is not supported by the immutable worker catalog")
    runtime = WorkerRuntime(
        worker_id=args.worker_id,
        trusted_public_key_pem=Path(args.trusted_key).read_bytes(),
        capabilities=capabilities,
        image_reference=args.image_reference,
        image_digest=args.image_digest,
        runtime_network_mode=args.runtime_network_mode,
        allowed_scripts=catalog.scripts,
        allowed_flows=catalog.flows,
        replay_store_path=args.replay_store or (_ROOT / "data" / "worker_state" / args.worker_id),
    )
    result = runtime.execute(envelope) if args.execute else runtime.inspect(envelope)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result.get("accepted", result.get("status") not in {"denied", "failed"}) else 1


if __name__ == "__main__":
    raise SystemExit(main())
