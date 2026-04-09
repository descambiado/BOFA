#!/usr/bin/env python3
"""
BOFA signed evidence bundle verification.
"""

import argparse
import base64
import json
import sys
import zipfile
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key


REQUIRED_FILES = {
    "manifest.json",
    "manifest.sig",
    "public_key.pem",
    "run.json",
    "timeline.json",
    "steps.json",
    "labs.json",
    "README.txt",
}


def _sha256_bytes(content: bytes) -> str:
    import hashlib

    return hashlib.sha256(content).hexdigest()


def _canonical_json_bytes(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _manifest_signature_payload(manifest: Dict[str, Any]) -> Dict[str, Any]:
    payload = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    canonical_files = payload.get("canonical_files")
    if canonical_files:
        payload["canonical_files"] = {
            name: value for name, value in canonical_files.items() if name not in {"manifest.json", "manifest.sig"}
        }
    return payload


def _verify_bundle(bundle_path: Path, public_key_override: Optional[Path] = None) -> Dict[str, Any]:
    with zipfile.ZipFile(bundle_path, "r") as archive:
        names = set(archive.namelist())
        missing_canonical_files = sorted(REQUIRED_FILES - names)
        if "manifest.json" not in names:
            raise RuntimeError("manifest.json missing from evidence bundle")

        manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
        canonical_definition = manifest.get("canonical_files") or {}
        manifest_payload = _canonical_json_bytes(_manifest_signature_payload(manifest))
        manifest_sha256 = manifest.get("manifest_sha256")
        manifest_sha_valid = bool(manifest_sha256) and manifest_sha256 == _sha256_bytes(manifest_payload)

        if public_key_override:
            public_key_bytes = public_key_override.read_bytes()
            trust_mode = "provided_public_key"
        elif "public_key.pem" in names:
            public_key_bytes = archive.read("public_key.pem")
            trust_mode = "bundle_embedded_public_key"
        else:
            raise RuntimeError("No public key available for verification")

        signature_text = archive.read("manifest.sig").decode("utf-8") if "manifest.sig" in names else ""
        signature_valid = False
        signature_error = None
        try:
            public_key = load_pem_public_key(public_key_bytes)
            signature_bytes = base64.b64decode(signature_text.strip())
            public_key.verify(signature_bytes, manifest_payload)
            signature_valid = True
        except (InvalidSignature, ValueError, TypeError) as exc:
            signature_error = str(exc) or "invalid_signature"

        canonical_file_checks = []
        for name in sorted(REQUIRED_FILES):
            expected = canonical_definition.get(name) or {}
            if name not in names:
                canonical_file_checks.append(
                    {
                        "name": name,
                        "verified": False,
                        "reason": "missing_from_bundle",
                        "expected_sha256": expected.get("sha256"),
                        "expected_size_bytes": expected.get("size_bytes"),
                        "actual_sha256": None,
                        "actual_size_bytes": None,
                    }
                )
                continue

            entry_bytes = archive.read(name)
            if name == "manifest.json":
                actual_sha256 = _sha256_bytes(manifest_payload)
                actual_size_bytes = len(manifest_payload)
            else:
                actual_sha256 = _sha256_bytes(entry_bytes)
                actual_size_bytes = len(entry_bytes)

            expected_sha256 = expected.get("sha256")
            expected_size_bytes = expected.get("size_bytes")
            verified = bool(expected_sha256) and actual_sha256 == expected_sha256 and (
                expected_size_bytes is None or expected_size_bytes == actual_size_bytes
            )
            canonical_file_checks.append(
                {
                    "name": name,
                    "verified": verified,
                    "reason": None if verified else "canonical_mismatch",
                    "expected_sha256": expected_sha256,
                    "expected_size_bytes": expected_size_bytes,
                    "actual_sha256": actual_sha256,
                    "actual_size_bytes": actual_size_bytes,
                }
            )

        artifact_checks = []
        verified_artifacts = 0
        for artifact in manifest.get("artifacts", []):
            if not artifact.get("included"):
                artifact_checks.append(
                    {
                        "artifact_id": artifact.get("artifact_id"),
                        "artifact_type": artifact.get("artifact_type"),
                        "included": False,
                        "verified": True,
                        "reason": artifact.get("reason"),
                    }
                )
                continue

            relative_path = artifact.get("relative_path")
            if not relative_path or relative_path not in names:
                artifact_checks.append(
                    {
                        "artifact_id": artifact.get("artifact_id"),
                        "artifact_type": artifact.get("artifact_type"),
                        "included": True,
                        "verified": False,
                        "reason": "missing_from_bundle",
                    }
                )
                continue

            actual_sha256 = _sha256_bytes(archive.read(relative_path))
            expected_sha256 = artifact.get("sha256")
            verified = bool(expected_sha256) and actual_sha256 == expected_sha256
            if verified:
                verified_artifacts += 1
            artifact_checks.append(
                {
                    "artifact_id": artifact.get("artifact_id"),
                    "artifact_type": artifact.get("artifact_type"),
                    "included": True,
                    "verified": verified,
                    "reason": None if verified else "artifact_checksum_mismatch",
                    "relative_path": relative_path,
                    "expected_sha256": expected_sha256,
                    "actual_sha256": actual_sha256,
                }
            )

    bundle_public_key_fingerprint = manifest.get("public_key_fingerprint")
    verification_key_fingerprint = _sha256_bytes(public_key_bytes)
    public_key_matches_bundle = verification_key_fingerprint == bundle_public_key_fingerprint
    integrity_valid = (
        manifest_sha_valid
        and len(missing_canonical_files) == 0
        and all(item.get("verified") for item in canonical_file_checks)
        and all(item.get("verified") for item in artifact_checks)
    )

    return {
        "bundle_path": str(bundle_path),
        "verified": signature_valid and integrity_valid,
        "signature_valid": signature_valid,
        "integrity_valid": integrity_valid,
        "trust_mode": trust_mode,
        "signing_algorithm": manifest.get("signing_algorithm"),
        "bundle_version": manifest.get("bundle_version"),
        "manifest_sha256": manifest_sha256,
        "manifest_sha_valid": manifest_sha_valid,
        "public_key_fingerprint": bundle_public_key_fingerprint,
        "verification_key_fingerprint": verification_key_fingerprint,
        "public_key_matches_bundle": public_key_matches_bundle,
        "missing_canonical_files": missing_canonical_files,
        "canonical_file_checks": canonical_file_checks,
        "artifact_checks": artifact_checks,
        "included_count": len([artifact for artifact in manifest.get("artifacts", []) if artifact.get("included")]),
        "verified_artifact_count": verified_artifacts,
        "warning_count": manifest.get("warning_count", 0),
        "signature_error": signature_error,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a BOFA signed evidence bundle")
    parser.add_argument("bundle", help="Path to the BOFA evidence ZIP bundle")
    parser.add_argument("--public-key", dest="public_key", help="Optional public key PEM to use instead of the embedded one")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON output")
    args = parser.parse_args()

    bundle_path = Path(args.bundle).expanduser().resolve()
    if not bundle_path.exists() or not bundle_path.is_file():
        parser.error(f"Bundle not found: {bundle_path}")

    public_key_override = None
    if args.public_key:
        public_key_override = Path(args.public_key).expanduser().resolve()
        if not public_key_override.exists() or not public_key_override.is_file():
            parser.error(f"Public key not found: {public_key_override}")

    try:
        result = _verify_bundle(bundle_path, public_key_override)
    except Exception as exc:
        error_payload = {"bundle_path": str(bundle_path), "verified": False, "error": str(exc)}
        if args.json:
            print(json.dumps(error_payload, indent=2, ensure_ascii=False))
        else:
            print(f"[ERROR] {exc}")
        return 2

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print("BOFA Evidence Verification")
        print("=" * 32)
        print(f"Bundle: {result['bundle_path']}")
        print(f"Verified: {'yes' if result['verified'] else 'no'}")
        print(f"Signature valid: {'yes' if result['signature_valid'] else 'no'}")
        print(f"Integrity valid: {'yes' if result['integrity_valid'] else 'no'}")
        print(f"Trust mode: {result['trust_mode']}")
        print(f"Signing algorithm: {result.get('signing_algorithm') or 'n/a'}")
        print(f"Fingerprint: {result.get('public_key_fingerprint') or 'n/a'}")
        if result["missing_canonical_files"]:
            print(f"Missing canonical files: {', '.join(result['missing_canonical_files'])}")
        if result.get("signature_error"):
            print(f"Signature error: {result['signature_error']}")

    return 0 if result["verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
