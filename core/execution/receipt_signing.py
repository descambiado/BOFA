"""Ed25519 signatures for one-job worker receipts."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Dict, Mapping, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .signing import public_key_id, public_key_pem


RECEIPT_SIGNING_ALGORITHM = "Ed25519"
RECEIPT_SIGNATURE_SCOPE = "receipt_sha256"
_SIGNATURE_FIELDS = {
    "receipt_sha256",
    "receipt_signature",
    "receipt_signature_algorithm",
    "receipt_signature_scope",
    "receipt_key_id",
}


def canonical_receipt_payload(receipt: Mapping[str, Any]) -> bytes:
    return json.dumps(
        {key: value for key, value in receipt.items() if key not in _SIGNATURE_FIELDS},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def receipt_digest(receipt: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_receipt_payload(receipt)).hexdigest()


def sign_receipt(
    receipt: Mapping[str, Any], private_key: Ed25519PrivateKey
) -> Dict[str, Any]:
    digest = receipt_digest(receipt)
    signature = private_key.sign(digest.encode("ascii"))
    return {
        **dict(receipt),
        "receipt_sha256": digest,
        "receipt_signature": base64.b64encode(signature).decode("ascii"),
        "receipt_signature_algorithm": RECEIPT_SIGNING_ALGORITHM,
        "receipt_signature_scope": RECEIPT_SIGNATURE_SCOPE,
        "receipt_key_id": public_key_id(public_key_pem(private_key)),
    }


def verify_receipt(
    receipt: Mapping[str, Any], trusted_public_key_pem: bytes
) -> Tuple[bool, str]:
    if receipt.get("receipt_sha256") != receipt_digest(receipt):
        return False, "receipt_digest_invalid"
    if receipt.get("receipt_signature_algorithm") != RECEIPT_SIGNING_ALGORITHM:
        return False, "receipt_algorithm_invalid"
    if receipt.get("receipt_signature_scope") != RECEIPT_SIGNATURE_SCOPE:
        return False, "receipt_scope_invalid"
    try:
        public_key = serialization.load_pem_public_key(trusted_public_key_pem)
        if not isinstance(public_key, Ed25519PublicKey):
            return False, "receipt_key_invalid"
        if receipt.get("receipt_key_id") != public_key_id(trusted_public_key_pem):
            return False, "receipt_key_id_mismatch"
        signature = base64.b64decode(
            str(receipt.get("receipt_signature", "")), validate=True
        )
        public_key.verify(signature, str(receipt["receipt_sha256"]).encode("ascii"))
        return True, "verified"
    except (InvalidSignature, TypeError, ValueError):
        return False, "receipt_signature_invalid"
