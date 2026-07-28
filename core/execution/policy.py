"""Deny-by-default authorization and scope checks for BOFA jobs."""

from __future__ import annotations

from datetime import datetime
import ipaddress
from pathlib import Path
from typing import Dict, Iterable, Optional, Tuple
from urllib.parse import urlsplit

from .models import (
    AuthorizationGrant,
    ExecutionBackend,
    ExecutionCapability,
    ExecutionLimits,
    ExecutionProfile,
    ExecutionRequest,
    PolicyDecision,
    ScopeRule,
    utc_now,
)


POLICY_VERSION = "2026-07-28.2"
BLOCKED_CAPABILITIES = {
    ExecutionCapability.PRIVILEGED,
    ExecutionCapability.CLOUD_MUTATION,
}
NETWORK_CAPABILITIES = {
    ExecutionCapability.NETWORK_PASSIVE,
    ExecutionCapability.NETWORK_ACTIVE,
}


def _minimum_limits(grant: ExecutionLimits, profile: ExecutionLimits) -> ExecutionLimits:
    return ExecutionLimits(
        max_duration_seconds=min(grant.max_duration_seconds, profile.max_duration_seconds),
        max_output_bytes=min(grant.max_output_bytes, profile.max_output_bytes),
        max_steps=min(grant.max_steps, profile.max_steps),
        cpu_cores=min(grant.cpu_cores, profile.cpu_cores),
        memory_mb=min(grant.memory_mb, profile.memory_mb),
    )


def _normalized_host(value: str) -> str:
    return value.strip().rstrip(".").lower().encode("idna").decode("ascii")


def _target_parts(target: str):
    candidate = target.strip()
    parsed = urlsplit(candidate)
    if parsed.scheme:
        return parsed
    return urlsplit(f"//{candidate}")


def _match_host(target: str, rule: ScopeRule) -> bool:
    parsed = _target_parts(target)
    if parsed.username or parsed.password or not parsed.hostname:
        return False
    expected = _normalized_host(rule.value)
    actual = _normalized_host(parsed.hostname)
    return actual == expected or (rule.include_subdomains and actual.endswith(f".{expected}"))


def _match_url_prefix(target: str, rule: ScopeRule) -> bool:
    target_url = urlsplit(target)
    scope_url = urlsplit(rule.value)
    if target_url.scheme not in {"http", "https"} or scope_url.scheme not in {"http", "https"}:
        return False
    if target_url.username or target_url.password or scope_url.username or scope_url.password:
        return False
    if _normalized_host(target_url.hostname or "") != _normalized_host(scope_url.hostname or ""):
        return False
    if target_url.port != scope_url.port:
        return False
    scope_path = scope_url.path.rstrip("/") or "/"
    target_path = target_url.path or "/"
    return target_path == scope_path or target_path.startswith(f"{scope_path.rstrip('/')}/")


def _match_cidr(target: str, rule: ScopeRule) -> bool:
    parsed = _target_parts(target)
    if not parsed.hostname:
        return False
    try:
        return ipaddress.ip_address(parsed.hostname) in ipaddress.ip_network(rule.value, strict=False)
    except ValueError:
        return False


def _match_path(target: str, rule: ScopeRule) -> bool:
    try:
        target_path = Path(target).expanduser().resolve(strict=False)
        scope_path = Path(rule.value).expanduser().resolve(strict=False)
        return target_path == scope_path or scope_path in target_path.parents
    except (OSError, RuntimeError):
        return False


def scope_matches(target: Optional[str], rules: Iterable[ScopeRule]) -> bool:
    if not target:
        return False
    for rule in rules:
        if not rule.value or rule.value == "*":
            continue
        if rule.kind == "host" and _match_host(target, rule):
            return True
        if rule.kind == "url_prefix" and _match_url_prefix(target, rule):
            return True
        if rule.kind == "cidr" and _match_cidr(target, rule):
            return True
        if rule.kind == "path" and _match_path(target, rule):
            return True
        if rule.kind == "opaque" and target == rule.value:
            return True
    return False


class ExecutionPolicyEngine:
    def __init__(self, blocked_capabilities: Optional[Iterable[ExecutionCapability]] = None):
        self.blocked_capabilities = set(blocked_capabilities or BLOCKED_CAPABILITIES)
        self.version = POLICY_VERSION

    def evaluate(
        self,
        request: ExecutionRequest,
        grant: AuthorizationGrant,
        profile: ExecutionProfile,
        now: Optional[datetime] = None,
    ) -> PolicyDecision:
        current = now or utc_now()
        requested = set(request.required_capabilities)
        grant_capabilities = set(grant.capabilities)
        profile_capabilities = set(profile.capabilities)
        effective_limits = _minimum_limits(grant.limits, profile.limits)
        checks: Dict[str, bool] = {}
        reasons = []

        checks["identity"] = bool(request.subject_id) and request.subject_id == grant.subject_id
        checks["project"] = bool(request.project_id) and request.project_id == grant.project_id
        checks["environment"] = bool(request.environment_id) and request.environment_id == grant.environment_id
        checks["grant_id"] = bool(grant.id)
        checks["grant_time"] = grant.issued_at <= current < grant.expires_at
        checks["profile_enabled"] = profile.enabled
        checks["profile_id"] = bool(profile.id) and request.profile_id == profile.id
        checks["capability_declared"] = bool(requested)
        checks["capability_grant"] = requested.issubset(grant_capabilities)
        checks["capability_profile"] = requested.issubset(profile_capabilities)
        checks["blocked_capability"] = not bool(requested & self.blocked_capabilities)
        checks["approval"] = (
            not grant.require_human_approval
            or (
                bool(request.approval_id)
                and request.approval_id == grant.approval_id
                and bool(grant.approved_by)
            )
        )

        needs_scope = bool(requested & (NETWORK_CAPABILITIES | {ExecutionCapability.FILESYSTEM_READ}))
        checks["scope"] = not needs_scope or scope_matches(request.target, grant.scopes)
        checks["duration"] = (
            request.requested_duration_seconds is None
            or 0 < request.requested_duration_seconds <= effective_limits.max_duration_seconds
        )
        checks["steps"] = (
            request.requested_steps is None or 0 < request.requested_steps <= effective_limits.max_steps
        )
        checks["ephemeral"] = profile.backend == ExecutionBackend.LOCAL or profile.ephemeral
        checks["network_mode"] = profile.network_mode in {"none", "restricted"}
        checks["image_digest"] = (
            profile.backend == ExecutionBackend.LOCAL
            or bool(profile.image and profile.image_digest and profile.image_digest.startswith("sha256:"))
        )

        messages: Tuple[Tuple[str, str], ...] = (
            ("identity", "Request subject does not match the authorization grant"),
            ("project", "Request project does not match the authorization grant"),
            ("environment", "Request environment does not match the authorization grant"),
            ("grant_id", "Authorization grant id is required"),
            ("grant_time", "Authorization grant is not active"),
            ("profile_enabled", profile.availability_reason or "Execution profile is disabled"),
            ("profile_id", "Request profile does not match the selected execution profile"),
            ("capability_declared", "At least one execution capability must be declared"),
            ("capability_grant", "Authorization grant does not permit every requested capability"),
            ("capability_profile", "Execution profile does not support every requested capability"),
            ("blocked_capability", "A requested capability is blocked by BOFA policy"),
            ("approval", "Matching human approval is required"),
            ("scope", "Target is outside the written authorization scope"),
            ("duration", "Requested duration exceeds the effective limit"),
            ("steps", "Requested step count exceeds the effective limit"),
            ("ephemeral", "OCI and remote profiles must be ephemeral"),
            ("network_mode", "Execution profile must use none or restricted network mode"),
            ("image_digest", "OCI and remote profiles require an image pinned by sha256 digest"),
        )
        for key, message in messages:
            if not checks[key]:
                reasons.append(message)

        allowed = not reasons
        return PolicyDecision(
            allowed=allowed,
            code="allowed" if allowed else "denied",
            reasons=tuple(reasons),
            checks=checks,
            effective_limits=effective_limits,
            policy_version=self.version,
        )
