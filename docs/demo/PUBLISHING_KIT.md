# Publishing Kit

## BOFA Agent OAuth Triage

### LinkedIn Draft

I’ve been tightening a BOFA agent demo around a simple rule: the interesting part is not that an agent can call tools, it is that scope decides what it cannot do.

This local demo triages a synthetic suspicious OAuth app, records every step as JSONL evidence, blocks a non-allowlisted live tenant lookup, then emits `report.json` and `report.md`.

A tiny SotyHub-style adapter reads the report shape without coupling to agent internals.

No tenant, no credentials, no external APIs. Just scope -> evidence -> report -> adapter.

### X Thread Draft

1. Small BOFA demo: passive triage of a suspicious OAuth app, entirely local.
2. The scope file allowlists `inspect_oauth_metadata`, `evaluate_permissions`, and `score_risk`.
3. The planned call `fetch_live_tenant_users` is blocked and recorded.
4. The report marks the synthetic app `high`, score `80`, because of unverified publisher, HTTP redirect URI, risky permissions, and sample consent.
5. The SotyHub example is only an adapter shape: it reads `report.json` and prints an ingestion event.
6. The point: agent demos should prove boundaries, not just action.

### YouTube Description Draft

In this BOFA Agent demo, a local deterministic agent triages a synthetic suspicious OAuth application.

The demo shows:

- explicit scope before action
- allowlisted deterministic tool calls
- a blocked live tenant lookup
- JSONL evidence for every step
- `report.json` and `report.md`
- a SotyHub-style adapter reading the report

No real OAuth tenant, credentials, external APIs, or real targets are used.

## SotyHub Authorized Lab Control Plane

### LinkedIn Draft

The SotyHub lab-control-plane story is about making authorized labs governable.

The demo flow is request -> admin approval -> evidence -> cost estimate -> report -> kill switch.

The important claim is not that a lab can start. It is that the control plane can show who requested it, what scope was approved, how long it can run, what it cost, what evidence it produced, and how it was stopped.

This should be recorded only after staging rehearsal passes.

### X Thread Draft

1. SotyHub Authorized Lab Control Plane demo goal: request, approve, evidence, cost, report, kill switch.
2. A lab request should carry scope, TTL, quota, and use type before anything runs.
3. Admin approval is the governance layer.
4. Evidence and reports make the action auditable.
5. Cost estimate keeps the demo honest about resources.
6. Kill switch proves the control plane can stop what it starts.
7. Final recording waits for staging rehearsal.

### YouTube Description Draft

This demo shows the SotyHub Authorized Lab Control Plane concept: request an authorized lab, review and approve it as admin, capture evidence and estimated cost, generate a report, and stop the lab with a kill switch.

The recording uses staging/demo data only. No real targets, production credentials, or production deployments are used.

## Asset Inventory

- BOFA Agent script: `docs/demo/BOFA_AGENT_VIDEO_SCRIPT.md`
- BOFA Agent capture checklist: `docs/demo/BOFA_AGENT_CAPTURE_CHECKLIST.md`
- SotyHub script: `docs/demo/SOTYHUB_VIDEO_SCRIPT.md`
- Staging rehearsal: `docs/demo/SOTYHUB_STAGING_REHEARSAL.md`
- Risk review: `docs/demo/RISK_REVIEW.md`

## Publication Checklist

- Final video reviewed.
- No credentials or private accounts visible.
- No real targets visible.
- No exploit/red-team file tree shown.
- Claims match what is actually recorded.
- Human approval received for push.
- Human approval received for publication.

