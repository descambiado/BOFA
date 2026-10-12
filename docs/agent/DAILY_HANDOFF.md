# Daily Handoff

## Current State

Branch: `bofa-agent-v1`

Mission scope is implemented as a small local Python package under `bofa/agent/`.
The demo performs passive OAuth application triage using synthetic data and deterministic mock tool calls.

## What Exists

- Scope enforcement: `bofa/agent/scope.py`
- Hash-chained JSONL evidence writer and integrity-verifying reader: `bofa/agent/evidence.py`
- Report JSON/Markdown builder: `bofa/agent/report.py`
- Offline report/evidence bundle verifier: `bofa/agent/verify_bundle.py`
- Deterministic runner: `bofa/agent/runner.py`
- Executable demo module: `bofa/agent/demo/oauth_app_triage.py`
- SotyHub adapter example: `examples/sotyhub_consumer.py`
- Minimum docs and tests for a 3 minute demo.
- Runner blocks scope entries without a reviewed implementation, records bounded tool failures, and preserves existing artifacts unless overwrite is explicit.
- Scope loading rejects malformed lists, duplicate entries, and allow/block conflicts; explicit blocks also take precedence in the decision function.
- Demo input is validated before output creation, plan size is capped, and malformed tool results fail the run visibly as `partial_failed`.
- Reports expose the SHA-256 chain head and state plainly that evidence is not signed.
- Bundle verification independently checks the JSONL chain and report event-count/head references; it does not authenticate the author.

## Known Repo Context

- Before this mission, the worktree already had an unrelated deletion:
  `scripts/red/reverse_shell_polyglot.py`.
- No `bofa/` package or `tests/` directory existed before this mission.
- MCP exists in `mcp/`, but this demo does not depend on MCP.

## Next Validation

Run:

```bash
python -m bofa.agent.demo.oauth_app_triage
python -m bofa.agent.verify_bundle --report bofa/agent/demo/output/report.json --evidence bofa/agent/demo/output/evidence.jsonl
python examples/sotyhub_consumer.py bofa/agent/demo/output/report.json
python -m unittest discover -s tests -p "test_agent_*.py"
```

Use `--output-dir` for a fresh run or add `--overwrite` only when replacing the existing local artifacts is intended.

The targeted command runs the offline agent suite. Full test discovery also loads `tests/test_auth.py`, which requires optional `pytest`.
