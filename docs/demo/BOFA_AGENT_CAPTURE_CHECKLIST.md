# BOFA Agent Capture Checklist

## Preflight

- Branch is `bofa-agent-v1`.
- No real credentials visible in terminal history.
- No browser tabs with private accounts visible.
- Do not show `scripts/`, `docs/ORCHESTRATION_AND_CHAINING.md`, or exploit/red-team material.
- Use a clean terminal at repo root.
- Use large enough terminal font for video.

## Commands

Preferred:

```powershell
py -m bofa.agent.demo.oauth_app_triage
py examples/sotyhub_consumer.py bofa/agent/demo/output/report.json
py -m unittest discover -s tests
```

Fallback:

```powershell
python -m bofa.agent.demo.oauth_app_triage
python examples/sotyhub_consumer.py bofa/agent/demo/output/report.json
python -m unittest discover -s tests
```

## Captures

| Capture | File or Surface | Required Point |
| --- | --- | --- |
| Scope | `docs/AGENT_SCOPE.md` | synthetic, no real targets, no credentials, no external APIs |
| Allowlist | `bofa/agent/demo/scope.oauth_triage.json` | allowed tools and blocked tools |
| Execution | terminal | demo command and generated paths |
| Evidence | `bofa/agent/demo/output/evidence.jsonl` | `tool.blocked` for `fetch_live_tenant_users` |
| Report | `bofa/agent/demo/output/report.md` | executive summary and risk decision |
| Adapter | terminal | SotyHub-style JSON event |
| Tests | terminal | `unittest` passing |

## Assets Directory

Use `docs/demo-assets/bofa-agent/` for clean screenshots if generated.

Do not commit raw recordings, drafts with personal data, terminal history dumps, or generated output files unless explicitly approved.

## Pass Criteria

- Evidence contains exactly one blocked tool call.
- Report says synthetic/local/no external APIs.
- Adapter reads `report.json` successfully.
- Tests pass with stdlib `unittest`.

