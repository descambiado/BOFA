# BOFA Agent Demo Mission Rules

Mission: BOFA Agent Demo, passive triage of a suspicious OAuth application.

Working rules:

- Work on local branch `bofa-agent-v1`.
- Keep the demo deterministic and local-first.
- Use synthetic inputs only; do not touch real targets, tenants, credentials, or APIs.
- Scope is `Scope -> Evidence -> Report -> SotyHub adapter`.
- Do not touch SotyHub except the example adapter in `examples/sotyhub_consumer.py`.
- Do not touch OpenClaw.
- Do not add offensive tools, cloud infrastructure, tokens, or economy features.
- If external integration blocks the demo, use deterministic mocks.
- If end-to-end scope grows, reduce scope before failing.
- Do not push, publish, or create PRs without explicit approval.
- Preserve unrelated user changes in the worktree.

Definition of done:

- `python -m bofa.agent.demo.oauth_app_triage` runs locally.
- The demo loads `bofa/agent/demo/scope.oauth_triage.json`.
- The demo uses `bofa/agent/demo/input.sample.json`.
- The runner executes allowlisted deterministic tool calls.
- At least one non-allowlisted tool call is blocked and recorded.
- The run emits `evidence.jsonl`, `report.json`, and `report.md`.
- `examples/sotyhub_consumer.py` reads `report.json`.
- Minimal tests cover scope, evidence, and report behavior.

