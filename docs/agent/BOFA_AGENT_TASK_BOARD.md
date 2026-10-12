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
| 5 | Add minimal tests | Done | Scope, evidence, runner, report, and end-to-end adapter contract covered by stdlib `unittest`. |
| 6 | Validate commands | Done | Demo run OK, adapter OK, 9 targeted agent tests pass, and adapter output matches the compact golden contract. |
| 7 | Harden execution and evidence lifecycle | Done | Unknown/unimplemented tools fail closed, exceptions produce partial-failure reports without exception text, JSONL evidence is SHA-256 hash chained and verified on read, and outputs require explicit overwrite. |
| 8 | Guard report-to-adapter compatibility | Done | Automated integration test runs the synthetic workflow, invokes the consumer as a separate process, and checks its JSON event against `golden_output.json`. |
| 9 | Verify report/evidence bundle offline | Done | Standalone CLI checks the SHA-256 JSONL chain and report count/head; tests cover valid, tampered, mismatched, and unsupported-algorithm bundles. It explicitly does not verify signatures. |
| 10 | Reject ambiguous or malformed scopes | Done | Scope parsing now validates string/list shapes, rejects duplicates and allow/block overlap, and explicitly prioritizes blocked tools as defense in depth. |
| 11 | Validate demo inputs and tool results | Done | Rejects malformed application data, duplicate/oversized execution plans, and invalid tool output before it can be misreported; tool failures remain visible as `partial_failed`. |

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
