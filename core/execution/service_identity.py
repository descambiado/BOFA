"""Fail-closed SotyHub workload identity and offline dispatch contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import math
import os
from pathlib import Path
import re
import threading
from typing import Any, Callable, Dict, Mapping, Optional, Tuple

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .models import (
    AuthorizationGrant,
    ExecutionBackend,
    ExecutionCapability,
    ExecutionLimits,
    ExecutionManifest,
    ExecutionProfile,
    ExecutionRequest,
)
from .policy import ExecutionPolicyEngine
from .signing import public_key_id, public_key_pem, sign_manifest


SERVICE_IDENTITY_SCHEMA = "bofa.service-identity/v1"
DISPATCH_SCHEMA = "sotyhub_bofa_dispatch/v1"
GOOGLE_ISSUERS = ("https://accounts.google.com", "accounts.google.com")
GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
SERVICE_PATHS = (
    "/execution/service/trust",
    "/execution/service/preflight",
    "/execution/service/jobs",
)
OFFLINE_PROFILE_ID = "oci-ephemeral"
OFFLINE_ACTION = "run_script:forensics/hash_calculator"
OFFLINE_CAPABILITIES = (ExecutionCapability.EVIDENCE_READ,)
OFFLINE_NETWORK_MODE = "none"
_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_SUBJECT_PATTERN = re.compile(r"[0-9]{6,32}")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_IMAGE_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
_KEY_ID_PATTERN = re.compile(r"ed25519:[0-9a-f]{24}")
_JWT_KID_PATTERN = re.compile(r"[A-Za-z0-9_.:-]{1,256}")


class ServiceIdentityError(ValueError):
    """Stable authentication failure without token or claim disclosure."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class ServiceDispatchError(ValueError):
    """Stable dispatch contract failure."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return -1


@dataclass(frozen=True)
class ServiceIdentityPolicy:
    enabled: bool
    audience: str
    service_account_email: str
    service_account_subject: str
    sender_project_id: str = "sotyhub-staging"
    accepted_issuers: Tuple[str, ...] = GOOGLE_ISSUERS
    allowed_paths: Tuple[str, ...] = SERVICE_PATHS
    max_token_lifetime_seconds: int = 3600
    max_clock_skew_seconds: int = 60
    jwks_url: str = GOOGLE_JWKS_URL

    @classmethod
    def from_env(cls) -> "ServiceIdentityPolicy":
        return cls(
            enabled=os.getenv("BOFA_SOTYHUB_OIDC_ENABLED", "false").strip().lower()
            == "true",
            audience=os.getenv("BOFA_SOTYHUB_OIDC_AUDIENCE", "").strip(),
            service_account_email=os.getenv(
                "BOFA_SOTYHUB_SERVICE_ACCOUNT_EMAIL", ""
            ).strip(),
            service_account_subject=os.getenv(
                "BOFA_SOTYHUB_SERVICE_ACCOUNT_SUBJECT", ""
            ).strip(),
            sender_project_id=os.getenv(
                "BOFA_SOTYHUB_SENDER_PROJECT_ID", "sotyhub-staging"
            ).strip(),
            max_token_lifetime_seconds=_env_int(
                "BOFA_SOTYHUB_OIDC_MAX_LIFETIME_SECONDS",
                3600,
            ),
            max_clock_skew_seconds=_env_int(
                "BOFA_SOTYHUB_OIDC_MAX_CLOCK_SKEW_SECONDS",
                60,
            ),
            jwks_url=os.getenv("BOFA_SOTYHUB_OIDC_JWKS_URL", GOOGLE_JWKS_URL).strip(),
        )

    def configured(self) -> bool:
        return bool(
            self.enabled
            and self.audience
            and self.audience.startswith("https://")
            and self.service_account_email
            and _SUBJECT_PATTERN.fullmatch(self.service_account_subject)
            and _IDENTIFIER_PATTERN.fullmatch(self.sender_project_id)
            and self.max_token_lifetime_seconds > 0
            and 0 <= self.max_clock_skew_seconds <= 300
            and self.jwks_url.startswith("https://")
        )


@dataclass(frozen=True)
class VerifiedServiceIdentity:
    issuer: str
    audience: str
    email: str
    subject: str
    issued_at: int
    expires_at: int

    def to_audit_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": SERVICE_IDENTITY_SCHEMA,
            "issuer": self.issuer,
            "audience": self.audience,
            "email": self.email,
            "subject": self.subject,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "raw_token_persisted": False,
        }


def _numeric_claim(claims: Mapping[str, Any], key: str) -> float:
    value = claims.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ServiceIdentityError("identity_claims_invalid")
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ServiceIdentityError("identity_claims_invalid")
    return parsed


def evaluate_service_identity_claims(
    claims: Mapping[str, Any],
    signature_verified: bool,
    policy: ServiceIdentityPolicy,
    path: str,
    now: Optional[datetime] = None,
) -> VerifiedServiceIdentity:
    if not policy.configured():
        raise ServiceIdentityError("service_identity_not_configured")
    if not signature_verified:
        raise ServiceIdentityError("identity_signature_invalid")
    if path not in policy.allowed_paths:
        raise ServiceIdentityError("identity_path_forbidden")

    issuer = claims.get("iss")
    audience = claims.get("aud")
    email = claims.get("email")
    subject = claims.get("sub")
    if (
        issuer not in policy.accepted_issuers
        or audience != policy.audience
        or email != policy.service_account_email
        or subject != policy.service_account_subject
        or claims.get("email_verified") is not True
    ):
        raise ServiceIdentityError("identity_claims_invalid")

    issued_at = _numeric_claim(claims, "iat")
    expires_at = _numeric_claim(claims, "exp")
    current = (now or datetime.now(timezone.utc)).timestamp()
    skew = policy.max_clock_skew_seconds
    if (
        expires_at <= issued_at
        or expires_at - issued_at > policy.max_token_lifetime_seconds
        or issued_at > current + skew
        or expires_at <= current - skew
    ):
        raise ServiceIdentityError("identity_time_invalid")
    if claims.get("nbf") is not None and _numeric_claim(claims, "nbf") > current + skew:
        raise ServiceIdentityError("identity_time_invalid")

    return VerifiedServiceIdentity(
        issuer=str(issuer),
        audience=str(audience),
        email=str(email),
        subject=str(subject),
        issued_at=int(issued_at),
        expires_at=int(expires_at),
    )


class GoogleOidcServiceIdentityVerifier:
    """Verify Google OIDC signatures before evaluating pinned workload claims."""

    def __init__(
        self,
        policy: ServiceIdentityPolicy,
        key_resolver: Optional[Callable[[str], Any]] = None,
    ):
        self.policy = policy
        self._jwk_client = None if key_resolver else jwt.PyJWKClient(policy.jwks_url)
        self._key_resolver = key_resolver

    def verify(
        self,
        token: str,
        path: str,
        now: Optional[datetime] = None,
    ) -> VerifiedServiceIdentity:
        if not self.policy.configured():
            raise ServiceIdentityError("service_identity_not_configured")
        if (
            not isinstance(token, str)
            or not token
            or len(token) > 16384
            or any(char.isspace() for char in token)
        ):
            raise ServiceIdentityError("identity_token_invalid")
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") != "RS256" or not _JWT_KID_PATTERN.fullmatch(
                str(header.get("kid", ""))
            ):
                raise ServiceIdentityError("identity_header_invalid")
            key = (
                self._key_resolver(token)
                if self._key_resolver
                else self._jwk_client.get_signing_key_from_jwt(token).key
            )
            claims = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                options={
                    "require": [
                        "iss",
                        "aud",
                        "sub",
                        "email",
                        "email_verified",
                        "iat",
                        "exp",
                    ],
                    "verify_aud": False,
                    "verify_iss": False,
                    "verify_iat": False,
                    "verify_exp": False,
                    "verify_nbf": False,
                },
            )
        except ServiceIdentityError:
            raise
        except (jwt.PyJWTError, OSError, ValueError, TypeError):
            raise ServiceIdentityError("identity_signature_invalid") from None
        return evaluate_service_identity_claims(
            claims,
            signature_verified=True,
            policy=self.policy,
            path=path,
            now=now,
        )


@dataclass(frozen=True)
class SotyHubOfflineCanaryRequest:
    request_id: str
    operation_id: str
    authorization_id: str
    usage_scope_id: str
    manifest_sha256: str
    key_id: str
    profile_id: str
    worker_image_digest: str
    action: str
    network_mode: str
    required_capabilities: Tuple[str, ...]
    input_text: str

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "SotyHubOfflineCanaryRequest":
        if payload.get("schema_version") != DISPATCH_SCHEMA:
            raise ServiceDispatchError("dispatch_schema_invalid")
        identifiers = {}
        for key in (
            "request_id",
            "operation_id",
            "authorization_id",
            "usage_scope_id",
        ):
            value = payload.get(key)
            if not isinstance(value, str) or not _IDENTIFIER_PATTERN.fullmatch(value):
                raise ServiceDispatchError("dispatch_identifier_invalid")
            identifiers[key] = value

        capabilities = payload.get("required_capabilities")
        parameters = payload.get("parameters")
        if (
            not isinstance(capabilities, list)
            or capabilities != [ExecutionCapability.EVIDENCE_READ.value]
            or not isinstance(parameters, Mapping)
            or set(parameters) != {"input", "algorithm", "file", "json"}
            or parameters.get("algorithm") != "sha256"
            or parameters.get("file") is not False
            or parameters.get("json") is not True
            or not isinstance(parameters.get("input"), str)
            or not 1 <= len(parameters["input"]) <= 4096
        ):
            raise ServiceDispatchError("dispatch_parameters_invalid")

        manifest_sha256 = payload.get("manifest_sha256")
        key_id = payload.get("key_id")
        image_digest = payload.get("worker_image_digest")
        if (
            not isinstance(manifest_sha256, str)
            or not _SHA256_PATTERN.fullmatch(manifest_sha256)
            or not isinstance(key_id, str)
            or not _KEY_ID_PATTERN.fullmatch(key_id)
            or not isinstance(image_digest, str)
            or not _IMAGE_DIGEST_PATTERN.fullmatch(image_digest)
        ):
            raise ServiceDispatchError("dispatch_cryptographic_binding_invalid")
        if (
            payload.get("profile_id") != OFFLINE_PROFILE_ID
            or payload.get("action") != OFFLINE_ACTION
            or payload.get("network_mode") != OFFLINE_NETWORK_MODE
        ):
            raise ServiceDispatchError("dispatch_canary_boundary_invalid")

        return cls(
            **identifiers,
            manifest_sha256=manifest_sha256,
            key_id=key_id,
            profile_id=OFFLINE_PROFILE_ID,
            worker_image_digest=image_digest,
            action=OFFLINE_ACTION,
            network_mode=OFFLINE_NETWORK_MODE,
            required_capabilities=tuple(capabilities),
            input_text=parameters["input"],
        )

    def binding_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": DISPATCH_SCHEMA,
            "request_id": self.request_id,
            "operation_id": self.operation_id,
            "authorization_id": self.authorization_id,
            "usage_scope_id": self.usage_scope_id,
            "source_manifest_sha256": self.manifest_sha256,
            "key_id": self.key_id,
            "profile_id": self.profile_id,
            "worker_image_digest": self.worker_image_digest,
            "action": self.action,
            "network_mode": self.network_mode,
            "required_capabilities": list(self.required_capabilities),
        }


def build_sotyhub_offline_canary_envelope(
    dispatch: SotyHubOfflineCanaryRequest,
    identity: VerifiedServiceIdentity,
    profile: ExecutionProfile,
    signing_key: Ed25519PrivateKey,
    sender_project_id: str,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    current = now or datetime.now(timezone.utc)
    expected_key_id = public_key_id(public_key_pem(signing_key))
    if dispatch.key_id != expected_key_id:
        raise ServiceDispatchError("dispatch_key_id_mismatch")
    if (
        profile.id != OFFLINE_PROFILE_ID
        or profile.backend != ExecutionBackend.OCI
        or not profile.enabled
        or not profile.ephemeral
        or profile.network_mode != OFFLINE_NETWORK_MODE
        or profile.image_digest != dispatch.worker_image_digest
        or set(profile.capabilities) < set(OFFLINE_CAPABILITIES)
    ):
        raise ServiceDispatchError("dispatch_profile_mismatch")

    limits = ExecutionLimits(
        max_duration_seconds=60,
        max_output_bytes=64 * 1024,
        max_steps=1,
        cpu_cores=1,
        memory_mb=256,
    )
    grant = AuthorizationGrant.from_dict(
        {
            "id": dispatch.authorization_id,
            "subject_id": identity.subject,
            "project_id": sender_project_id,
            "environment_id": "sotyhub-offline-canary",
            "issued_at": (current - timedelta(seconds=60)).isoformat(),
            "expires_at": (current + timedelta(minutes=5)).isoformat(),
            "scopes": [],
            "capabilities": [ExecutionCapability.EVIDENCE_READ.value],
            "limits": limits.to_dict(),
            "require_human_approval": True,
            "approval_id": dispatch.authorization_id,
            "approved_by": "sotyhub-control-plane",
            "metadata": {
                "source": "sotyhub_oidc",
                "request_id": dispatch.request_id,
                "operation_id": dispatch.operation_id,
                "usage_scope_id": dispatch.usage_scope_id,
            },
        }
    )
    request = ExecutionRequest.from_dict(
        {
            "subject_id": identity.subject,
            "action": dispatch.action,
            "profile_id": dispatch.profile_id,
            "required_capabilities": list(dispatch.required_capabilities),
            "project_id": sender_project_id,
            "environment_id": "sotyhub-offline-canary",
            "target": None,
            "approval_id": dispatch.authorization_id,
            "requested_duration_seconds": 30,
            "requested_steps": 1,
            "metadata": {
                "run_type": "script",
                "module": "forensics",
                "script": "hash_calculator",
                "parameters": {
                    "input": dispatch.input_text,
                    "algorithm": "sha256",
                    "file": False,
                    "json": True,
                },
                "sotyhub_binding": dispatch.binding_dict(),
                "service_identity": identity.to_audit_dict(),
            },
        }
    )
    decision = ExecutionPolicyEngine().evaluate(request, grant, profile, now=current)
    if not decision.allowed:
        raise ServiceDispatchError("dispatch_policy_denied")
    manifest = ExecutionManifest.build(
        request,
        grant,
        profile,
        decision.policy_version,
        now=current,
    )
    return {
        "decision": decision.to_dict(),
        "manifest": manifest.to_dict(),
        "envelope": sign_manifest(manifest.to_dict(), signing_key),
        "binding": dispatch.binding_dict(),
    }


class ManifestClaimStore:
    """Atomic, durable one-use claims for SotyHub source manifest hashes."""

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self._lock = threading.Lock()

    def claim(self, dispatch: SotyHubOfflineCanaryRequest) -> bool:
        if not _SHA256_PATTERN.fullmatch(dispatch.manifest_sha256):
            return False
        with self._lock:
            self.root.mkdir(parents=True, exist_ok=True)
            marker = self.root / f"{dispatch.manifest_sha256}.claimed"
            try:
                descriptor = os.open(
                    marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600
                )
            except FileExistsError:
                return False
            payload = {
                "schema_version": "bofa.service-job-claim/v1",
                "manifest_sha256": dispatch.manifest_sha256,
                "request_id": dispatch.request_id,
                "operation_id": dispatch.operation_id,
                "claimed_at": datetime.now(timezone.utc).isoformat(),
                "raw_token_persisted": False,
            }
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                    json.dump(payload, output, sort_keys=True, separators=(",", ":"))
                    output.flush()
                    os.fsync(output.fileno())
            except Exception:
                marker.unlink(missing_ok=True)
                raise
            return True
