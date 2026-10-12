"""Scope loading and tool allowlist enforcement for BOFA agent demos."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping


@dataclass(frozen=True)
class ToolDecision:
    tool: str
    allowed: bool
    reason: str


@dataclass(frozen=True)
class AgentScope:
    mission_id: str
    title: str
    allowed_tools: List[str]
    blocked_tools: List[str]
    constraints: List[str]
    report_profile: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "AgentScope":
        if not isinstance(data, Mapping):
            raise ValueError("scope must be a JSON object")

        required = ["mission_id", "title", "allowed_tools", "blocked_tools"]
        missing = [key for key in required if key not in data]
        if missing:
            raise ValueError("scope is missing required fields: " + ", ".join(missing))

        mission_id = _required_string(data, "mission_id")
        title = _required_string(data, "title")
        allowed_tools = _string_list(data, "allowed_tools")
        blocked_tools = _string_list(data, "blocked_tools")
        constraints = _string_list(data, "constraints", default=[])
        report_profile = _required_string(
            data, "report_profile", default="passive-oauth-triage"
        )

        overlap = sorted(set(allowed_tools).intersection(blocked_tools))
        if overlap:
            raise ValueError(
                "scope tools cannot be both allowed and blocked: " + ", ".join(overlap)
            )

        return cls(
            mission_id=mission_id,
            title=title,
            allowed_tools=allowed_tools,
            blocked_tools=blocked_tools,
            constraints=constraints,
            report_profile=report_profile,
        )

    def decide_tool(self, tool: str) -> ToolDecision:
        if tool in self.blocked_tools:
            return ToolDecision(tool=tool, allowed=False, reason="tool is explicitly blocked")
        if tool in self.allowed_tools:
            return ToolDecision(tool=tool, allowed=True, reason="tool is in allowlist")
        return ToolDecision(tool=tool, allowed=False, reason="tool is outside allowlist")

    def validate_plan(self, tools: Iterable[str]) -> List[ToolDecision]:
        return [self.decide_tool(tool) for tool in tools]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mission_id": self.mission_id,
            "title": self.title,
            "allowed_tools": self.allowed_tools,
            "blocked_tools": self.blocked_tools,
            "constraints": self.constraints,
            "report_profile": self.report_profile,
        }


def load_scope(path: Path) -> AgentScope:
    with path.open("r", encoding="utf-8") as handle:
        return AgentScope.from_mapping(json.load(handle))


def _required_string(
    data: Mapping[str, Any], key: str, default: Any = None
) -> str:
    value = data.get(key, default)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"scope field {key} must be a non-empty string")
    return value.strip()


def _string_list(
    data: Mapping[str, Any], key: str, default: Any = None
) -> List[str]:
    value = data.get(key, default)
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        raise ValueError(f"scope field {key} must be a list of non-empty strings")
    normalized = [item.strip() for item in value]
    if len(normalized) != len(set(normalized)):
        raise ValueError(f"scope field {key} must not contain duplicates")
    return normalized
