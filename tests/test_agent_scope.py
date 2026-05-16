import unittest
from pathlib import Path

from bofa.agent.scope import load_scope


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


if __name__ == "__main__":
    unittest.main()
