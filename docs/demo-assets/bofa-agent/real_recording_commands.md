# BOFA Agent Real Recording Commands

Run these from the repository root.

## Preferred

```powershell
py -m bofa.agent.demo.oauth_app_triage
py examples/sotyhub_consumer.py bofa/agent/demo/output/report.json
py -m unittest discover -s tests
```

## Fallback

```powershell
python -m bofa.agent.demo.oauth_app_triage
python examples/sotyhub_consumer.py bofa/agent/demo/output/report.json
python -m unittest discover -s tests
```

## Files To Open In Editor

```text
docs/AGENT_SCOPE.md
bofa/agent/demo/scope.oauth_triage.json
bofa/agent/demo/output/evidence.jsonl
bofa/agent/demo/output/report.md
```

## Exact Evidence Search

In the editor search box, search:

```text
fetch_live_tenant_users
```

or:

```text
tool.blocked
```

