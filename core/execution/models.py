"""Serializable contracts shared by local, OCI and remote BOFA runners."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple
import uuid


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_timestamp(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


class ExecutionBackend(str, Enum):
    LOCAL = "local"
    OCI = "oci"
    REMOTE = "remote"


class ExecutionCapability(str, Enum):
    EVIDENCE_READ = "evidence_read"
    FILESYSTEM_READ = "filesystem_read"
    NETWORK_PASSIVE = "network_passive"
    NETWORK_ACTIVE = "network_active"
    CONTAINER = "container"
    PRIVILEGED = "privileged"
    CLOUD_MUTATION = "cloud_mutation"


def _capabilities(values: Iterable[str | ExecutionCapability]) -> Tuple[ExecutionCapability, ...]:
    return tuple(sorted({ExecutionCapability(value) for value in values}, key=lambda item: item.value))


@dataclass(frozen=True)
class ScopeRule:
    kind: str
    value: str
    include_subdomains: bool = False

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ScopeRule":
        return cls(
            kind=str(payload.get("kind", "")).strip().lower(),
            value=str(payload.get("value", "")).strip(),
            include_subdomains=bool(payload.get("include_subdomains", False)),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "value": self.value,
            "include_subdomains": self.include_subdomains,
        }


@dataclass(frozen=True)
class ExecutionLimits:
    max_duration_seconds: int = 300
    max_output_bytes: int = 10 * 1024 * 1024
    max_steps: int = 20
    cpu_cores: float = 1.0
    memory_mb: int = 512

    def __post_init__(self) -> None:
        if self.max_duration_seconds <= 0:
            raise ValueError("max_duration_seconds must be positive")
        if self.max_output_bytes <= 0:
            raise ValueError("max_output_bytes must be positive")
        if self.max_steps <= 0:
            raise ValueError("max_steps must be positive")
        if self.cpu_cores <= 0:
            raise ValueError("cpu_cores must be positive")
        if self.memory_mb < 64:
            raise ValueError("memory_mb must be at least 64")

    @classmethod
    def from_dict(cls, payload: Optional[Mapping[str, Any]]) -> "ExecutionLimits":
        values = payload or {}
        return cls(
            max_duration_seconds=int(values.get("max_duration_seconds", 300)),
            max_output_bytes=int(values.get("max_output_bytes", 10 * 1024 * 1024)),
            max_steps=int(values.get("max_steps", 20)),
            cpu_cores=float(values.get("cpu_cores", 1.0)),
            memory_mb=int(values.get("memory_mb", 512)),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "max_duration_seconds": self.max_duration_seconds,
            "max_output_bytes": self.max_output_bytes,
            "max_steps": self.max_steps,
            "cpu_cores": self.cpu_cores,
            "memory_mb": self.memory_mb,
        }


@dataclass(frozen=True)
class AuthorizationGrant:
    id: str
    subject_id: str
    project_id: str
    environment_id: str
    issued_at: datetime
    expires_at: datetime
    scopes: Tuple[ScopeRule, ...]
    capabilities: Tuple[ExecutionCapability, ...]
    limits: ExecutionLimits = field(default_factory=ExecutionLimits)
    require_human_approval: bool = True
    approval_id: Optional[str] = None
    approved_by: Optional[str] = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "AuthorizationGrant":
        return cls(
            id=str(payload.get("id", "")).strip(),
            subject_id=str(payload.get("subject_id", "")).strip(),
            project_id=str(payload.get("project_id", "")).strip(),
            environment_id=str(payload.get("environment_id", "")).strip(),
            issued_at=parse_timestamp(payload["issued_at"]),
            expires_at=parse_timestamp(payload["expires_at"]),
            scopes=tuple(ScopeRule.from_dict(item) for item in payload.get("scopes", [])),
            capabilities=_capabilities(payload.get("capabilities", [])),
            limits=ExecutionLimits.from_dict(payload.get("limits")),
            require_human_approval=bool(payload.get("require_human_approval", True)),
            approval_id=str(payload["approval_id"]).strip() if payload.get("approval_id") else None,
            approved_by=str(payload["approved_by"]).strip() if payload.get("approved_by") else None,
            metadata=dict(payload.get("metadata") or {}),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "subject_id": self.subject_id,
            "project_id": self.project_id,
            "environment_id": self.environment_id,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "scopes": [scope.to_dict() for scope in self.scopes],
            "capabilities": [capability.value for capability in self.capabilities],
            "limits": self.limits.to_dict(),
            "require_human_approval": self.require_human_approval,
            "approval_id": self.approval_id,
            "approved_by": self.approved_by,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class ExecutionProfile:
    id: str
    backend: ExecutionBackend
    capabilities: Tuple[ExecutionCapability, ...]
    limits: ExecutionLimits = field(default_factory=ExecutionLimits)
    network_mode: str = "restricted"
    image: Optional[str] = None
    image_digest: Optional[str] = None
    ephemeral: bool = True
    enabled: bool = True
    availability_reason: Optional[str] = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ExecutionProfile":
        return cls(
            id=str(payload.get("id", "")).strip(),
            backend=ExecutionBackend(payload.get("backend", ExecutionBackend.LOCAL.value)),
            capabilities=_capabilities(payload.get("capabilities", [])),
            limits=ExecutionLimits.from_dict(payload.get("limits")),
            network_mode=str(payload.get("network_mode", "restricted")).strip().lower(),
            image=str(payload["image"]).strip() if payload.get("image") else None,
            image_digest=str(payload["image_digest"]).strip() if payload.get("image_digest") else None,
            ephemeral=bool(payload.get("ephemeral", True)),
            enabled=bool(payload.get("enabled", True)),
            availability_reason=(
                str(payload["availability_reason"]).strip() if payload.get("availability_reason") else None
            ),
            metadata=dict(payload.get("metadata") or {}),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "backend": self.backend.value,
            "capabilities": [capability.value for capability in self.capabilities],
            "limits": self.limits.to_dict(),
            "network_mode": self.network_mode,
            "image": self.image,
            "image_digest": self.image_digest,
            "ephemeral": self.ephemeral,
            "enabled": self.enabled,
            "availability_reason": self.availability_reason,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class ExecutionRequest:
    subject_id: str
    action: str
    profile_id: str
    required_capabilities: Tuple[ExecutionCapability, ...]
    project_id: str
    environment_id: str
    target: Optional[str] = None
    approval_id: Optional[str] = None
    requested_duration_seconds: Optional[int] = None
    requested_steps: Optional[int] = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ExecutionRequest":
        return cls(
            subject_id=str(payload.get("subject_id", "")).strip(),
            action=str(payload.get("action", "")).strip(),
            profile_id=str(payload.get("profile_id", "")).strip(),
            required_capabilities=_capabilities(payload.get("required_capabilities", [])),
            project_id=str(payload.get("project_id", "")).strip(),
            environment_id=str(payload.get("environment_id", "")).strip(),
            target=str(payload["target"]).strip() if payload.get("target") else None,
            approval_id=str(payload["approval_id"]).strip() if payload.get("approval_id") else None,
            requested_duration_seconds=(
                int(payload["requested_duration_seconds"])
                if payload.get("requested_duration_seconds") is not None
                else None
            ),
            requested_steps=int(payload["requested_steps"]) if payload.get("requested_steps") is not None else None,
            metadata=dict(payload.get("metadata") or {}),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "subject_id": self.subject_id,
            "action": self.action,
            "profile_id": self.profile_id,
            "required_capabilities": [capability.value for capability in self.required_capabilities],
            "project_id": self.project_id,
            "environment_id": self.environment_id,
            "target": self.target,
            "approval_id": self.approval_id,
            "requested_duration_seconds": self.requested_duration_seconds,
            "requested_steps": self.requested_steps,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    code: str
    reasons: Tuple[str, ...]
    checks: Mapping[str, bool]
    effective_limits: ExecutionLimits
    policy_version: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "code": self.code,
            "reasons": list(self.reasons),
            "checks": dict(self.checks),
            "effective_limits": self.effective_limits.to_dict(),
            "policy_version": self.policy_version,
        }


@dataclass(frozen=True)
class ExecutionManifest:
    id: str
    created_at: datetime
    expires_at: datetime
    request: ExecutionRequest
    grant_id: str
    profile: ExecutionProfile
    effective_limits: ExecutionLimits
    policy_version: str
    sha256: str

    @classmethod
    def build(
        cls,
        request: ExecutionRequest,
        grant: AuthorizationGrant,
        profile: ExecutionProfile,
        policy_version: str,
        now: Optional[datetime] = None,
    ) -> "ExecutionManifest":
        created_at = now or utc_now()
        duration = min(
            request.requested_duration_seconds or grant.limits.max_duration_seconds,
            grant.limits.max_duration_seconds,
            profile.limits.max_duration_seconds,
        )
        expires_at = min(grant.expires_at, created_at.replace(microsecond=0) + _seconds(duration))
        effective_limits = ExecutionLimits(
            max_duration_seconds=min(grant.limits.max_duration_seconds, profile.limits.max_duration_seconds),
            max_output_bytes=min(grant.limits.max_output_bytes, profile.limits.max_output_bytes),
            max_steps=min(grant.limits.max_steps, profile.limits.max_steps),
            cpu_cores=min(grant.limits.cpu_cores, profile.limits.cpu_cores),
            memory_mb=min(grant.limits.memory_mb, profile.limits.memory_mb),
        )
        manifest_id = f"job_{uuid.uuid4().hex}"
        canonical = {
            "id": manifest_id,
            "created_at": created_at.isoformat(),
            "expires_at": expires_at.isoformat(),
            "request": request.to_dict(),
            "grant_id": grant.id,
            "profile": profile.to_dict(),
            "effective_limits": effective_limits.to_dict(),
            "policy_version": policy_version,
        }
        digest = hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        ).hexdigest()
        return cls(
            id=manifest_id,
            created_at=created_at,
            expires_at=expires_at,
            request=request,
            grant_id=grant.id,
            profile=profile,
            effective_limits=effective_limits,
            policy_version=policy_version,
            sha256=digest,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "request": self.request.to_dict(),
            "grant_id": self.grant_id,
            "profile": self.profile.to_dict(),
            "effective_limits": self.effective_limits.to_dict(),
            "policy_version": self.policy_version,
            "sha256": self.sha256,
        }


def _seconds(value: int):
    from datetime import timedelta

    return timedelta(seconds=value)
