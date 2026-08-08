#!/usr/bin/env python3
"""Verify the fail-closed SotyHub workload identity and offline canary lane."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.execution import (
    ExecutionBackend,
    ExecutionCapability,
    ExecutionLimits,
    ExecutionProfile,
)
from core.execution.receipt_signing import sign_receipt, verify_receipt
from core.execution.service_identity import (
    DISPATCH_SCHEMA,
    GOOGLE_ISSUERS,
    OFFLINE_ACTION,
    OFFLINE_NETWORK_MODE,
    OFFLINE_PROFILE_ID,
    SERVICE_PREFLIGHT_PATHS,
    SERVICE_PATHS,
    GoogleOidcServiceIdentityVerifier,
    ManifestClaimStore,
    ServiceDispatchError,
    ServiceIdentityError,
    ServiceIdentityPolicy,
    SotyHubOfflineCanaryRequest,
    build_sotyhub_offline_canary_envelope,
    evaluate_service_identity_claims,
)
from core.execution.signing import (
    public_key_id,
    public_key_pem,
    verify_envelope,
)
from worker import WorkerRuntime


AUDIENCE = "https://bofa-api.sotyhub.com"
SERVICE_EMAIL = "sotyhub-bofa-dispatch@sotyhub-staging.iam.gserviceaccount.com"
SERVICE_SUBJECT = "102432411719700000001"
IMAGE_REFERENCE = "ghcr.io/descambiado/bofa-worker"
IMAGE_DIGEST = f"sha256:{'7' * 64}"
SOURCE_MANIFEST_SHA256 = hashlib.sha256(
    b"sotyhub approved offline canary manifest"
).hexdigest()
INPUT_TEXT = "SotyHub BOFA workload identity canary"
EXPECTED_HASH = hashlib.sha256(INPUT_TEXT.encode("utf-8")).hexdigest()


def _expect_error(expected: str, callback) -> None:
    try:
        callback()
    except (ServiceIdentityError, ServiceDispatchError) as exc:
        assert exc.code == expected, (exc.code, expected)
    else:
        raise AssertionError(f"Expected {expected}")


def _identity_fixture():
    now = datetime.now(timezone.utc).replace(microsecond=0)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    policy = ServiceIdentityPolicy(
        enabled=True,
        audience=AUDIENCE,
        service_account_email=SERVICE_EMAIL,
        service_account_subject=SERVICE_SUBJECT,
        sender_project_id="sotyhub-staging",
        job_issuance_enabled=True,
        allowed_paths=SERVICE_PATHS,
    )
    verifier = GoogleOidcServiceIdentityVerifier(
        policy,
        key_resolver=lambda _token: public_key,
    )

    def signed_token(**overrides):
        claims = {
            "iss": GOOGLE_ISSUERS[0],
            "aud": AUDIENCE,
            "sub": SERVICE_SUBJECT,
            "email": SERVICE_EMAIL,
            "email_verified": True,
            "iat": int((now - timedelta(seconds=5)).timestamp()),
            "exp": int((now + timedelta(minutes=5)).timestamp()),
        }
        claims.update(overrides)
        return jwt.encode(
            claims,
            private_key,
            algorithm="RS256",
            headers={"kid": "google-test-key"},
        )

    return now, policy, verifier, signed_token


def _verify_identity_boundary() -> None:
    now, policy, verifier, signed_token = _identity_fixture()
    valid_token = signed_token()
    header, payload, signature = valid_token.split(".")
    signature_index = len(signature) // 2
    invalid_signature = (
        f"{header}.{payload}.{signature[:signature_index]}"
        f"{'A' if signature[signature_index] != 'A' else 'B'}"
        f"{signature[signature_index + 1:]}"
    )
    unsigned_token = jwt.encode(
        jwt.decode(valid_token, options={"verify_signature": False}),
        key="",
        algorithm="none",
        headers={"kid": "google-test-key"},
    )
    identity = verifier.verify(
        valid_token,
        "/execution/service/jobs",
        now=now,
    )
    audit = identity.to_audit_dict()
    assert audit["email"] == SERVICE_EMAIL
    assert audit["subject"] == SERVICE_SUBJECT
    assert audit["raw_token_persisted"] is False
    assert valid_token not in json.dumps(audit)

    cases = (
        (
            "identity_claims_invalid",
            lambda: verifier.verify(
                signed_token(aud="https://wrong.example"),
                SERVICE_PATHS[2],
                now=now,
            ),
        ),
        (
            "identity_claims_invalid",
            lambda: verifier.verify(
                signed_token(iss="https://securetoken.google.com/sotyhub-staging"),
                SERVICE_PATHS[2],
                now=now,
            ),
        ),
        (
            "identity_claims_invalid",
            lambda: verifier.verify(
                signed_token(email="other@example.com"),
                SERVICE_PATHS[2],
                now=now,
            ),
        ),
        (
            "identity_claims_invalid",
            lambda: verifier.verify(
                signed_token(sub="999999999999999999999"),
                SERVICE_PATHS[2],
                now=now,
            ),
        ),
        (
            "identity_claims_invalid",
            lambda: verifier.verify(
                signed_token(email_verified=False),
                SERVICE_PATHS[2],
                now=now,
            ),
        ),
        (
            "identity_time_invalid",
            lambda: verifier.verify(
                signed_token(
                    iat=int((now - timedelta(minutes=10)).timestamp()),
                    exp=int((now - timedelta(minutes=5)).timestamp()),
                ),
                SERVICE_PATHS[2],
                now=now,
            ),
        ),
        (
            "identity_time_invalid",
            lambda: verifier.verify(
                signed_token(
                    iat=int((now + timedelta(minutes=2)).timestamp()),
                    exp=int((now + timedelta(minutes=7)).timestamp()),
                ),
                SERVICE_PATHS[2],
                now=now,
            ),
        ),
        (
            "identity_time_invalid",
            lambda: verifier.verify(
                signed_token(
                    iat=int((now - timedelta(seconds=5)).timestamp()),
                    exp=int((now + timedelta(hours=2)).timestamp()),
                ),
                SERVICE_PATHS[2],
                now=now,
            ),
        ),
        (
            "identity_path_forbidden",
            lambda: verifier.verify(valid_token, "/execution/jobs", now=now),
        ),
        (
            "identity_signature_invalid",
            lambda: verifier.verify(
                invalid_signature,
                SERVICE_PATHS[2],
                now=now,
            ),
        ),
        (
            "identity_header_invalid",
            lambda: verifier.verify(
                unsigned_token,
                SERVICE_PATHS[2],
                now=now,
            ),
        ),
    )
    for expected, callback in cases:
        _expect_error(expected, callback)

    disabled = GoogleOidcServiceIdentityVerifier(
        ServiceIdentityPolicy(
            enabled=False,
            audience=policy.audience,
            service_account_email=policy.service_account_email,
            service_account_subject=policy.service_account_subject,
        ),
        key_resolver=lambda _token: None,
    )
    _expect_error(
        "service_identity_not_configured",
        lambda: disabled.verify(valid_token, SERVICE_PATHS[2], now=now),
    )

    preflight_policy = ServiceIdentityPolicy(
        enabled=True,
        audience=policy.audience,
        service_account_email=policy.service_account_email,
        service_account_subject=policy.service_account_subject,
        allowed_paths=SERVICE_PREFLIGHT_PATHS,
    )
    claims = jwt.decode(valid_token, options={"verify_signature": False})
    _expect_error(
        "identity_path_forbidden",
        lambda: evaluate_service_identity_claims(
            claims,
            signature_verified=True,
            policy=preflight_policy,
            path=SERVICE_PATHS[2],
            now=now,
        ),
    )


def _verify_receiver_phase_configuration() -> None:
    base_env = {
        "BOFA_SOTYHUB_OIDC_ENABLED": "true",
        "BOFA_SOTYHUB_OIDC_AUDIENCE": AUDIENCE,
        "BOFA_SOTYHUB_SERVICE_ACCOUNT_EMAIL": SERVICE_EMAIL,
        "BOFA_SOTYHUB_SERVICE_ACCOUNT_SUBJECT": SERVICE_SUBJECT,
        "BOFA_SOTYHUB_SENDER_PROJECT_ID": "sotyhub-staging",
    }
    with patch.dict(os.environ, base_env, clear=True):
        policy = ServiceIdentityPolicy.from_env()
        assert policy.configured()
        assert policy.job_issuance_enabled is False
        assert policy.allowed_paths == SERVICE_PREFLIGHT_PATHS

    with patch.dict(
        os.environ,
        {**base_env, "BOFA_SOTYHUB_JOB_ISSUANCE_ENABLED": "true"},
        clear=True,
    ):
        policy = ServiceIdentityPolicy.from_env()
        assert policy.configured()
        assert policy.job_issuance_enabled is True
        assert policy.allowed_paths == SERVICE_PATHS

    compose = (_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    template = (_ROOT / ".env.template").read_text(encoding="utf-8")
    for name in (
        "BOFA_SOTYHUB_OIDC_ENABLED",
        "BOFA_SOTYHUB_JOB_ISSUANCE_ENABLED",
        "BOFA_SOTYHUB_OIDC_AUDIENCE",
        "BOFA_SOTYHUB_SERVICE_ACCOUNT_EMAIL",
        "BOFA_SOTYHUB_SERVICE_ACCOUNT_SUBJECT",
        "BOFA_SOTYHUB_SENDER_PROJECT_ID",
        "BOFA_SOTYHUB_OIDC_MAX_LIFETIME_SECONDS",
        "BOFA_SOTYHUB_OIDC_MAX_CLOCK_SKEW_SECONDS",
    ):
        assert name in compose, f"docker-compose.yml does not pass {name}"
        assert name in template, f".env.template does not document {name}"


def _dispatch_payload(key_id: str) -> dict:
    return {
        "schema_version": DISPATCH_SCHEMA,
        "request_id": "request:session-0",
        "operation_id": "operation:offline-canary",
        "authorization_id": "authorization:human-reviewed",
        "usage_scope_id": "usage:user-dpmYb3h3",
        "manifest_sha256": SOURCE_MANIFEST_SHA256,
        "key_id": key_id,
        "profile_id": OFFLINE_PROFILE_ID,
        "worker_image_digest": IMAGE_DIGEST,
        "action": OFFLINE_ACTION,
        "network_mode": OFFLINE_NETWORK_MODE,
        "required_capabilities": ["evidence_read"],
        "parameters": {
            "input": INPUT_TEXT,
            "algorithm": "sha256",
            "file": False,
            "json": True,
        },
    }


def _verify_dispatch_and_offline_canary() -> None:
    now, _policy, verifier, signed_token = _identity_fixture()
    identity = verifier.verify(
        signed_token(),
        "/execution/service/jobs",
        now=now,
    )
    control_key = ed25519.Ed25519PrivateKey.generate()
    receipt_key = ed25519.Ed25519PrivateKey.generate()
    key_id = public_key_id(public_key_pem(control_key))
    payload = _dispatch_payload(key_id)
    dispatch = SotyHubOfflineCanaryRequest.from_mapping(payload)
    profile = ExecutionProfile(
        id=OFFLINE_PROFILE_ID,
        backend=ExecutionBackend.OCI,
        capabilities=(ExecutionCapability.EVIDENCE_READ,),
        limits=ExecutionLimits(
            max_duration_seconds=60,
            max_output_bytes=64 * 1024,
            max_steps=1,
            cpu_cores=1,
            memory_mb=256,
        ),
        network_mode=OFFLINE_NETWORK_MODE,
        image=IMAGE_REFERENCE,
        image_digest=IMAGE_DIGEST,
        ephemeral=True,
        enabled=True,
    )
    built = build_sotyhub_offline_canary_envelope(
        dispatch,
        identity,
        profile,
        control_key,
        "sotyhub-staging",
        now=now,
    )
    envelope = built["envelope"]
    verified, reason = verify_envelope(envelope, public_key_pem(control_key))
    assert verified, reason
    binding = envelope["manifest"]["request"]["metadata"]["sotyhub_binding"]
    assert binding["source_manifest_sha256"] == SOURCE_MANIFEST_SHA256
    assert binding["worker_image_digest"] == IMAGE_DIGEST
    assert envelope["manifest"]["profile"]["network_mode"] == "none"

    with tempfile.TemporaryDirectory(prefix="bofa-sotyhub-claim-") as claim_root:
        source_claims = ManifestClaimStore(Path(claim_root) / "source")
        assert source_claims.claim(dispatch)
        assert not source_claims.claim(dispatch)

        def executor(module, script, parameters, timeout_seconds, max_output_bytes):
            assert f"{module}/{script}" == "forensics/hash_calculator"
            assert parameters == {
                "input": INPUT_TEXT,
                "algorithm": "sha256",
                "file": False,
                "json": True,
            }
            assert timeout_seconds > 0
            assert max_output_bytes == 64 * 1024
            return {
                "status": "success",
                "exit_code": 0,
                "stdout": f"{EXPECTED_HASH}\n",
                "stderr": "",
            }

        runtime = WorkerRuntime(
            worker_id="sotyhub-offline-canary",
            trusted_public_key_pem=public_key_pem(control_key),
            capabilities=(ExecutionCapability.EVIDENCE_READ,),
            image_reference=IMAGE_REFERENCE,
            image_digest=IMAGE_DIGEST,
            runtime_network_mode="none",
            allowed_scripts=("forensics/hash_calculator",),
            allowed_flows=(),
            script_executor=executor,
            replay_store_path=Path(claim_root) / "worker",
        )
        result = runtime.execute(envelope)
        assert result["status"] == "success"
        assert result["executed"] is True
        assert EXPECTED_HASH in result["stdout_preview"]
        replay = runtime.execute(envelope)
        assert replay["status"] == "denied"
        assert replay["reason"] == "replay_detected"

    receipt = sign_receipt(
        {
            **result,
            "receipt_schema": "bofa.worker-receipt/v1",
            "source_manifest_sha256": SOURCE_MANIFEST_SHA256,
        },
        receipt_key,
    )
    receipt_public_key = receipt_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    verified, reason = verify_receipt(receipt, receipt_public_key)
    assert verified, reason
    tampered = {**receipt, "source_manifest_sha256": "0" * 64}
    verified, reason = verify_receipt(tampered, receipt_public_key)
    assert not verified
    assert reason == "receipt_digest_invalid"

    invalid_payloads = (
        (
            {**payload, "worker_image_digest": f"sha256:{'8' * 64}"},
            "dispatch_profile_mismatch",
        ),
        ({**payload, "key_id": f"ed25519:{'0' * 24}"}, "dispatch_key_id_mismatch"),
        (
            {**payload, "action": "run_script:red/scan"},
            "dispatch_canary_boundary_invalid",
        ),
        ({**payload, "network_mode": "restricted"}, "dispatch_canary_boundary_invalid"),
        (
            {**payload, "required_capabilities": ["network_active"]},
            "dispatch_parameters_invalid",
        ),
    )

    def build_invalid(invalid_payload):
        parsed = SotyHubOfflineCanaryRequest.from_mapping(invalid_payload)
        return build_sotyhub_offline_canary_envelope(
            parsed,
            identity,
            profile,
            control_key,
            "sotyhub-staging",
            now=now,
        )

    for invalid_payload, expected in invalid_payloads:
        _expect_error(
            expected,
            lambda invalid_payload=invalid_payload: build_invalid(invalid_payload),
        )


def main() -> int:
    checks = (
        (
            "Google OIDC identity is signature-first and exactly pinned",
            _verify_identity_boundary,
        ),
        (
            "SotyHub receiver phases keep JobSpec issuance disabled by default",
            _verify_receiver_phase_configuration,
        ),
        (
            "SotyHub offline canary is bound, one-use and receipt-signed",
            _verify_dispatch_and_offline_canary,
        ),
    )
    print("BOFA SotyHub Service Identity Verification")
    print("=" * 48)
    for label, check in checks:
        check()
        print(f"[OK] {label}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
