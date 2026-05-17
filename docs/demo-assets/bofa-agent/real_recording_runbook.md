# BOFA Agent Real Recording Runbook

Goal: record a raw, technical, credible demo in terminal/editor format.

Central message:

> BOFA Agent runs a deterministic OAuth triage demo with explicit scope, evidence logging, blocked out-of-scope action, report output, and SotyHub adapter shape.

Maximum length: 3 minutes.

## Window Layout

Use two windows only:

1. Editor on the left or full screen.
2. Terminal on the right or full screen when running commands.

Recommended setup:

- Open the repo root in your editor.
- Open a clean PowerShell terminal at repo root.
- Increase font size enough for video.
- Close unrelated tabs and terminals.
- Do not show the full repo tree longer than necessary.
- Do not open `scripts/`, `.env`, browser accounts, or private dashboards.

## Files To Show

Show only these files:

1. `docs/AGENT_SCOPE.md`
2. `bofa/agent/demo/scope.oauth_triage.json`
3. `bofa/agent/demo/output/evidence.jsonl`
4. `bofa/agent/demo/output/report.md`

Optional if you need a quick adapter context:

5. `examples/sotyhub_consumer.py`

Do not browse the repo broadly.

## Commands To Run

Preferred Windows commands:

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

If neither `py` nor `python` is available, use the explicit Python interpreter available on the machine.

## Shot-By-Shot Plan

### 0:00-0:20 Scope Doc

Open `docs/AGENT_SCOPE.md`.

Point to:

- synthetic data
- no real targets
- no credentials
- no external APIs

Say:

> This is a local BOFA Agent demo. The first thing I want to show is the boundary: this run is synthetic, passive, and local. No real OAuth tenant, no credentials, and no external APIs.

### 0:20-0:45 Scope JSON

Open `bofa/agent/demo/scope.oauth_triage.json`.

Point to:

- `allowed_tools`
- `blocked_tools`
- `fetch_live_tenant_users`

Say:

> The scope file is the contract. Three deterministic checks are allowed. Live tenant lookup is explicitly blocked. So the demo is not just about what the agent does, it is also about what it refuses to do.

### 0:45-1:10 Run Demo

Switch to terminal and run:

```powershell
py -m bofa.agent.demo.oauth_app_triage
```

Point to generated paths:

- `evidence.jsonl`
- `report.json`
- `report.md`

Say:

> Now I run the demo. It loads the scope, reads the synthetic OAuth app, executes only allowed checks, and writes evidence plus reports locally.

### 1:10-1:40 Evidence

Open `bofa/agent/demo/output/evidence.jsonl`.

Point to the event:

```json
"event_type": "tool.blocked"
```

and:

```json
"tool": "fetch_live_tenant_users"
```

Say:

> This is the key proof. The planned call to `fetch_live_tenant_users` was outside scope, so BOFA Agent blocked it and logged the decision. That is the behavior I want in an auditable agent demo.

### 1:40-2:15 Report

Open `bofa/agent/demo/output/report.md`.

Point to:

- Executive Summary
- Scope
- Actions Executed
- Risk Decision
- Limitations

Say:

> The report turns the run into something a human can review. It shows what ran, what was blocked, the evidence summary, and the risk decision. The app is synthetic, but the workflow is real and repeatable.

### 2:15-2:35 Adapter

Switch to terminal and run:

```powershell
py examples/sotyhub_consumer.py bofa/agent/demo/output/report.json
```

Point to:

- `type`
- `dedupe_key`
- `risk_score`
- `blocked_tools_count`

Say:

> This is the SotyHub adapter shape. It reads `report.json` and emits a compact governance event. This is not a live SotyHub integration; it is the handoff shape.

### 2:35-2:55 Tests

Run:

```powershell
py -m unittest discover -s tests
```

Point to:

```text
OK
```

Say:

> Finally, the basic tests pass with standard `unittest`, so the demo stays reproducible without extra test tooling.

### 2:55-3:00 Close

Say:

> That is BOFA Agent OAuth triage: explicit scope, evidence logging, blocked out-of-scope action, report output, and adapter shape over synthetic input.

## Lines To Highlight

In `evidence.jsonl`, highlight the line containing:

```text
"event_type": "tool.blocked"
```

and:

```text
"tool": "fetch_live_tenant_users"
```

In `report.md`, highlight:

```text
## Executive Summary
## Actions Executed
## Risk Decision
## Limitations
```

## Keep Out Of Frame

- Full repo tree browsing.
- `scripts/`
- exploit/red-team tooling.
- `.env`
- credentials.
- personal browser sessions.
- unrelated SotyHub pages.
- OpenClaw.

