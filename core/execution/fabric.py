"""Execution profile registry and policy preflight orchestration."""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Dict, Iterable, Mapping, Optional

from .models import (
    AuthorizationGrant,
    ExecutionBackend,
    ExecutionCapability,
    ExecutionLimits,
    ExecutionManifest,
    ExecutionProfile,
    ExecutionRequest,
)
from .policy import BLOCKED_CAPABILITIES, ExecutionPolicyEngine


def _profile_capabilities(*values: ExecutionCapability):
    return tuple(values)


class ExecutionFabric:
    def __init__(
        self,
        profiles: Optional[Iterable[ExecutionProfile]] = None,
        policy: Optional[ExecutionPolicyEngine] = None,
    ):
        self.policy = policy or ExecutionPolicyEngine()
        configured_profiles = tuple(profiles) if profiles is not None else self._default_profiles()
        self.profiles = {profile.id: profile for profile in configured_profiles}

    def _default_profiles(self):
        oci_image = os.getenv("BOFA_OCI_WORKER_IMAGE")
        oci_digest = os.getenv("BOFA_OCI_WORKER_IMAGE_DIGEST")
        remote_url = os.getenv("BOFA_REMOTE_WORKER_URL")
        remote_image = os.getenv("BOFA_REMOTE_WORKER_IMAGE")
        remote_digest = os.getenv("BOFA_REMOTE_WORKER_IMAGE_DIGEST")
        safe_capabilities = _profile_capabilities(
            ExecutionCapability.EVIDENCE_READ,
            ExecutionCapability.FILESYSTEM_READ,
            ExecutionCapability.NETWORK_PASSIVE,
            ExecutionCapability.NETWORK_ACTIVE,
        )
        return (
            ExecutionProfile(
                id="local-controlled",
                backend=ExecutionBackend.LOCAL,
                capabilities=safe_capabilities,
                limits=ExecutionLimits(
                    max_duration_seconds=900,
                    max_output_bytes=25 * 1024 * 1024,
                    max_steps=30,
                    cpu_cores=2.0,
                    memory_mb=1024,
                ),
                network_mode="restricted",
                ephemeral=False,
                metadata={"runner": "bofa-engine", "data_residency": "local"},
            ),
            ExecutionProfile(
                id="oci-ephemeral",
                backend=ExecutionBackend.OCI,
                capabilities=safe_capabilities + (ExecutionCapability.CONTAINER,),
                limits=ExecutionLimits(
                    max_duration_seconds=1800,
                    max_output_bytes=50 * 1024 * 1024,
                    max_steps=50,
                    cpu_cores=2.0,
                    memory_mb=2048,
                ),
                network_mode="none",
                image=oci_image,
                image_digest=oci_digest,
                ephemeral=True,
                enabled=bool(oci_image and oci_digest),
                availability_reason=None if oci_image and oci_digest else "OCI worker image is not configured",
                metadata={"runner": "oci", "cleanup": "always"},
            ),
            ExecutionProfile(
                id="remote-ephemeral",
                backend=ExecutionBackend.REMOTE,
                capabilities=safe_capabilities + (ExecutionCapability.CONTAINER,),
                limits=ExecutionLimits(
                    max_duration_seconds=1800,
                    max_output_bytes=50 * 1024 * 1024,
                    max_steps=50,
                    cpu_cores=2.0,
                    memory_mb=4096,
                ),
                network_mode="restricted",
                image=remote_image,
                image_digest=remote_digest,
                ephemeral=True,
                enabled=bool(remote_url and remote_image and remote_digest),
                availability_reason=(
                    None
                    if remote_url and remote_image and remote_digest
                    else "Remote worker endpoint and pinned image are not configured"
                ),
                metadata={"runner": "remote-worker", "endpoint_configured": bool(remote_url), "cleanup": "always"},
            ),
        )

    def list_profiles(self) -> list[Dict[str, Any]]:
        return [profile.to_dict() for profile in self.profiles.values()]

    def capabilities(self) -> Dict[str, Any]:
        return {
            "policy_version": self.policy.version,
            "profiles": self.list_profiles(),
            "blocked_capabilities": sorted(capability.value for capability in BLOCKED_CAPABILITIES),
            "invariants": {
                "scope_required": True,
                "human_approval_supported": True,
                "remote_execution_requires_pinned_image": True,
                "oci_and_remote_are_ephemeral": True,
                "network_modes": ["none", "restricted"],
                "llm_has_operational_authority": False,
            },
        }

    def preflight(
        self,
        request_payload: Mapping[str, Any],
        grant_payload: Mapping[str, Any],
        now: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        request = ExecutionRequest.from_dict(request_payload)
        grant = AuthorizationGrant.from_dict(grant_payload)
        profile = self.profiles.get(request.profile_id)
        if not profile:
            return {
                "decision": {
                    "allowed": False,
                    "code": "unknown_profile",
                    "reasons": ["Execution profile is not registered"],
                    "checks": {"profile_exists": False},
                    "effective_limits": grant.limits.to_dict(),
                    "policy_version": self.policy.version,
                },
                "manifest": None,
            }
        decision = self.policy.evaluate(request, grant, profile, now=now)
        manifest = (
            ExecutionManifest.build(request, grant, profile, decision.policy_version, now=now)
            if decision.allowed
            else None
        )
        return {
            "decision": decision.to_dict(),
            "manifest": manifest.to_dict() if manifest else None,
        }
