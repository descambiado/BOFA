# Risk Review

## Global Rules

- No push without approval.
- No deploy without approval.
- No publication without approval.
- No real credentials in video, logs, screenshots, or docs.
- No real targets.
- No offensive public demo actions.
- BOFA executes.
- SotyHub governs.
- OpenClaw remains optional/manual.

## BOFA Agent OAuth Triage

Publication status: ready after fresh local validation.

Known safe properties:

- Synthetic input only.
- Uses `.invalid` domains and example identities.
- No external APIs.
- No credentials.
- `fetch_live_tenant_users` is blocked and recorded.
- SotyHub is represented only as an adapter shape.

Required validation:

```powershell
py -m bofa.agent.demo.oauth_app_triage
py examples/sotyhub_consumer.py bofa/agent/demo/output/report.json
py -m unittest discover -s tests
```

## SotyHub Authorized Lab Control Plane

Publication status: blocked until staging rehearsal.

Risks:

- This repo does not contain a verified SotyHub app surface.
- BOFA lab UI can be shown as local control-plane rehearsal, but not as live SotyHub staging.
- Docker or backend availability can affect capture.
- Any cost, quota, TTL, or kill-switch claim must be visible in staging or labeled as storyboard/fallback.

## Repo Presentation Risk

Do not record broad repo search or file-tree browsing. The repository contains offensive/security-research modules outside the narrow demo path. Keep recording focused on:

- `docs/demo`
- `docs/AGENT_SCOPE.md`
- `docs/AGENT_CONTRACT.md`
- `docs/DEMO_OAUTH_TRIAGE.md`
- `bofa/agent/demo`
- `examples/sotyhub_consumer.py`
- `tests/test_agent_*.py`
- `/labs` UI only if staging/local rehearsal is intentional

## Current Blockers

- `scripts/red/reverse_shell_polyglot.py` is AV-sensitive in this Windows environment and may reappear as deleted after Defender action. It is unrelated to the demo and must not enter any demo commit or screen capture.
- Full SotyHub staging evidence is not present in this workspace.
- Final YouTube chapters require actual recording timestamps.

## Release Gate

Before publishing:

- Review final diff.
- Confirm `git status` does not include unrelated deletes.
- Re-run local demo gates.
- Review final screenshots for private data.
- Confirm no OpenClaw claim.
- Confirm no live SotyHub claim unless staging proof exists.

