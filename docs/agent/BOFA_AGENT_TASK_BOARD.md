# BOFA Agent Task Board

## Mission

BOFA Agent Demo: passive triage of a suspicious OAuth application.

## Board

| Phase | Task | Status | Notes |
| --- | --- | --- | --- |
| 0 | Verify repository reality | Done | No `bofa/` package or `tests/` directory existed. MCP exists as optional integration. No indexed SotyHub/OpenClaw references found. Existing unrelated deletion: `scripts/red/reverse_shell_polyglot.py`. |
| 0 | Create local branch | Done | Created `bofa-agent-v1`. |
| 1 | Add mission governance docs | Done | Root `AGENTS.md`, task board, and handoff created. |
| 2 | Implement scoped agent demo core | Done | Added scope, evidence, report, runner modules. |
| 3 | Add OAuth triage demo assets | Done | Added deterministic scope, synthetic input, golden report. |
| 4 | Add SotyHub consumer example | Done | Reads `report.json` and prints a safe summary. |
| 5 | Add minimal tests | Done | Scope, evidence, and report tests added. |
| 6 | Validate commands | Done | Demo run OK, adapter OK, unittest OK, golden compact comparison OK. `pytest` was unavailable in the bundled runtime, so tests use stdlib `unittest`. |

## Scope Decisions

- Use deterministic mock tool functions instead of external APIs.
- Treat tool allowlisting as the main safety boundary for the demo.
- Store demo outputs under `bofa/agent/demo/output/` so the run is easy to record.
- Keep report schema compact and adapter-friendly.

## Non-Goals

- No real OAuth tenant inspection.
- No offensive tooling.
- No cloud deployment.
- No SotyHub or OpenClaw integration beyond the adapter example.
