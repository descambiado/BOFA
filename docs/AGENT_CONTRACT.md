# BOFA Agent Contract

The BOFA agent demo is a deterministic local workflow with four boundaries:

1. Scope: load an explicit mission scope and tool allowlist.
2. Evidence: write every decision and tool result as JSONL evidence.
3. Report: convert evidence into `report.json` and `report.md`.
4. Adapter: let downstream consumers read the report without coupling to agent internals.

The demo must not call real OAuth providers, tenant APIs, external scanners, or cloud services.
Blocked tool calls are expected behavior and prove that scope enforcement works.

## Report Contract

`report.json` includes:

- `schema_version`
- `mission_id`
- `run_id`
- `subject`
- `classification`
- `findings`
- `blocked_tools`
- `evidence_summary`
- `sotyhub`

Consumers should treat unknown fields as additive.

