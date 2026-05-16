# Daily Handoff

## Current State

Branch: `bofa-agent-v1`

Mission scope is implemented as a small local Python package under `bofa/agent/`.
The demo performs passive OAuth application triage using synthetic data and deterministic mock tool calls.

## What Exists

- Scope enforcement: `bofa/agent/scope.py`
- Evidence JSONL writer: `bofa/agent/evidence.py`
- Report JSON/Markdown builder: `bofa/agent/report.py`
- Deterministic runner: `bofa/agent/runner.py`
- Executable demo module: `bofa/agent/demo/oauth_app_triage.py`
- SotyHub adapter example: `examples/sotyhub_consumer.py`
- Minimum docs and tests for a 3 minute demo.

## Known Repo Context

- Before this mission, the worktree already had an unrelated deletion:
  `scripts/red/reverse_shell_polyglot.py`.
- No `bofa/` package or `tests/` directory existed before this mission.
- MCP exists in `mcp/`, but this demo does not depend on MCP.

## Next Validation

Run:

```bash
python -m bofa.agent.demo.oauth_app_triage
python examples/sotyhub_consumer.py bofa/agent/demo/output/report.json
python -m unittest discover -s tests
```

`pytest` can also discover these tests when the optional dev dependency is installed.
