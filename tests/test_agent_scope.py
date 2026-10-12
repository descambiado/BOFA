import unittest
from pathlib import Path

from bofa.agent.scope import AgentScope, load_scope


class AgentScopeTests(unittest.TestCase):
    def test_scope_allows_and_blocks_tools(self) -> None:
        scope = load_scope(Path("bofa/agent/demo/scope.oauth_triage.json"))

        self.assertTrue(scope.decide_tool("inspect_oauth_metadata").allowed)

        blocked = scope.decide_tool("fetch_live_tenant_users")
        self.assertFalse(blocked.allowed)
        self.assertEqual(blocked.reason, "tool is explicitly blocked")

        unknown = scope.decide_tool("unknown_tool")
        self.assertFalse(unknown.allowed)
        self.assertEqual(unknown.reason, "tool is outside allowlist")

    def test_scope_rejects_conflicting_allow_and_block_lists(self) -> None:
        with self.assertRaisesRegex(ValueError, "both allowed and blocked"):
            AgentScope.from_mapping(
                {
                    "mission_id": "mission",
                    "title": "Test",
                    "allowed_tools": ["safe_tool"],
                    "blocked_tools": ["safe_tool"],
                }
            )

    def test_blocked_list_wins_for_defense_in_depth(self) -> None:
        contradictory_scope = AgentScope(
            mission_id="mission",
            title="Test",
            allowed_tools=["blocked_tool"],
            blocked_tools=["blocked_tool"],
            constraints=[],
            report_profile="test",
        )

        decision = contradictory_scope.decide_tool("blocked_tool")

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "tool is explicitly blocked")

    def test_scope_rejects_malformed_tool_lists(self) -> None:
        with self.assertRaisesRegex(ValueError, "list of non-empty strings"):
            AgentScope.from_mapping(
                {
                    "mission_id": "mission",
                    "title": "Test",
                    "allowed_tools": "safe_tool",
                    "blocked_tools": [],
                }
            )


if __name__ == "__main__":
    unittest.main()
