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
        required = ["mission_id", "title", "allowed_tools", "blocked_tools"]
        missing = [key for key in required if key not in data]
        if missing:
            raise ValueError("scope is missing required fields: " + ", ".join(missing))

        return cls(
            mission_id=str(data["mission_id"]),
            title=str(data["title"]),
            allowed_tools=list(data["allowed_tools"]),
            blocked_tools=list(data["blocked_tools"]),
            constraints=list(data.get("constraints", [])),
            report_profile=str(data.get("report_profile", "passive-oauth-triage")),
        )

    def decide_tool(self, tool: str) -> ToolDecision:
        if tool in self.allowed_tools:
            return ToolDecision(tool=tool, allowed=True, reason="tool is in allowlist")
        if tool in self.blocked_tools:
            return ToolDecision(tool=tool, allowed=False, reason="tool is explicitly blocked")
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

