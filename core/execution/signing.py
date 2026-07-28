"""Ed25519 signatures for BOFA job envelopes."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Mapping, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


SIGNING_ALGORITHM = "Ed25519"
SIGNATURE_SCOPE = "manifest_sha256"


def canonical_manifest_payload(manifest: Mapping[str, Any]) -> bytes:
    return json.dumps(
        {key: value for key, value in manifest.items() if key != "sha256"},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def manifest_digest(manifest: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_manifest_payload(manifest)).hexdigest()


def verify_manifest_digest(manifest: Mapping[str, Any]) -> bool:
    claimed = str(manifest.get("sha256", ""))
    return len(claimed) == 64 and claimed == manifest_digest(manifest)


def load_or_create_signing_key(private_key_path: Path, public_key_path: Path) -> Ed25519PrivateKey:
    private_key_path.parent.mkdir(parents=True, exist_ok=True)
    public_key_path.parent.mkdir(parents=True, exist_ok=True)
    if private_key_path.exists():
        key = serialization.load_pem_private_key(private_key_path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("Execution signing key must be Ed25519")
        return key

    key = Ed25519PrivateKey.generate()
    private_key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_key_path.write_bytes(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    try:
        private_key_path.chmod(0o600)
    except OSError:
        pass
    return key


def public_key_pem(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def public_key_id(public_pem: bytes) -> str:
    public_key = serialization.load_pem_public_key(public_pem)
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("Execution verification key must be Ed25519")
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return f"ed25519:{hashlib.sha256(raw).hexdigest()[:24]}"


def sign_manifest(manifest: Mapping[str, Any], private_key: Ed25519PrivateKey) -> Dict[str, Any]:
    if not verify_manifest_digest(manifest):
        raise ValueError("Manifest digest does not match canonical payload")
    public_pem = public_key_pem(private_key)
    signature = private_key.sign(str(manifest["sha256"]).encode("ascii"))
    return {
        "manifest": dict(manifest),
        "signature": base64.b64encode(signature).decode("ascii"),
        "algorithm": SIGNING_ALGORITHM,
        "signature_scope": SIGNATURE_SCOPE,
        "key_id": public_key_id(public_pem),
    }


def verify_envelope(envelope: Mapping[str, Any], trusted_public_key_pem: bytes) -> Tuple[bool, str]:
    manifest = envelope.get("manifest")
    if not isinstance(manifest, Mapping) or not verify_manifest_digest(manifest):
        return False, "manifest_digest_invalid"
    if envelope.get("algorithm") != SIGNING_ALGORITHM:
        return False, "algorithm_invalid"
    if envelope.get("signature_scope") != SIGNATURE_SCOPE:
        return False, "signature_scope_invalid"
    try:
        public_key = serialization.load_pem_public_key(trusted_public_key_pem)
        if not isinstance(public_key, Ed25519PublicKey):
            return False, "trusted_key_invalid"
        if envelope.get("key_id") != public_key_id(trusted_public_key_pem):
            return False, "key_id_mismatch"
        signature = base64.b64decode(str(envelope.get("signature", "")), validate=True)
        public_key.verify(signature, str(manifest["sha256"]).encode("ascii"))
        return True, "verified"
    except (InvalidSignature, TypeError, ValueError):
        return False, "signature_invalid"
