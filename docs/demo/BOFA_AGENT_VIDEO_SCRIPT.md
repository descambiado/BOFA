# BOFA Agent Video Script

Target length: 3 minutes.

## Title

BOFA Agent Demo: Scoped OAuth Triage With Evidence

## Voiceover Script

### 0:00-0:20 Opening

This is a local BOFA Agent demo for passive triage of a suspicious OAuth application. The important part is not that an agent can call tools. The important part is that scope decides what the agent is allowed to do before anything runs.

### 0:20-0:45 Scope

Here is the scope file. The demo allowlists three deterministic checks: OAuth metadata inspection, permission evaluation, and risk scoring. It also explicitly blocks live tenant lookup and external API behavior. The input is synthetic, and the constraints say no real targets, no credentials, and no external APIs.

### 0:45-1:10 Run

Now I run the demo locally.

```powershell
py -m bofa.agent.demo.oauth_app_triage
```

It loads the scope, reads the synthetic OAuth application, records evidence, and generates three local outputs: `evidence.jsonl`, `report.json`, and `report.md`.

### 1:10-1:45 Evidence

The evidence log is append-only JSONL. You can see each tool decision. The key line is the blocked call: `fetch_live_tenant_users`. That call was in the planned tool sequence, but it was outside the allowed scope, so the runner blocked it and recorded why.

### 1:45-2:20 Report

The Markdown report is the human-readable output. It includes the executive summary, scope, actions executed, evidence counts, risk decision, findings, limitations, and next steps. In this synthetic case the result is high risk, score 80, because the app has an unverified publisher, an insecure redirect URI, broad permissions, and an existing sample consent.

### 2:20-2:45 SotyHub Adapter Shape

Finally, the SotyHub-style adapter reads `report.json` and converts it into a compact ingestion event. This is not a live SotyHub integration. It is the adapter shape: report in, governance-friendly event out.

```powershell
py examples/sotyhub_consumer.py bofa/agent/demo/output/report.json
```

### 2:45-3:00 Close

That is the demo: scope first, deterministic local execution, evidence for each step, an auditable report, and a clean adapter boundary. No tenant, no credentials, no external APIs.

## Shots

1. `docs/AGENT_SCOPE.md`
2. `bofa/agent/demo/scope.oauth_triage.json`
3. terminal demo command
4. `bofa/agent/demo/output/evidence.jsonl`
5. `bofa/agent/demo/output/report.md`
6. SotyHub adapter command output
7. `py -m unittest discover -s tests`

## Terminal Transcript

```powershell
PS C:\Users\davyd\Documents\GitHub\BOFA> py -m bofa.agent.demo.oauth_app_triage
BOFA OAuth triage demo complete
evidence: C:\Users\davyd\Documents\GitHub\BOFA\bofa\agent\demo\output\evidence.jsonl
report_json: C:\Users\davyd\Documents\GitHub\BOFA\bofa\agent\demo\output\report.json
report_markdown: C:\Users\davyd\Documents\GitHub\BOFA\bofa\agent\demo\output\report.md

PS C:\Users\davyd\Documents\GitHub\BOFA> py examples\sotyhub_consumer.py bofa\agent\demo\output\report.json
{
  "blocked_tools_count": 1,
  "dedupe_key": "bofa-agent-oauth-triage-v1:synthetic-app-001",
  "findings_count": 4,
  "risk_score": 80,
  "severity": "high",
  "type": "passive_oauth_triage_report"
}

PS C:\Users\davyd\Documents\GitHub\BOFA> py -m unittest discover -s tests
...
----------------------------------------------------------------------
Ran 3 tests in 0.01s

OK
```

