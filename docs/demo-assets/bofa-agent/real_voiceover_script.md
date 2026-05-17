# BOFA Agent Real Demo Voiceover

This is a local BOFA Agent demo. I am using synthetic OAuth data, and the run is intentionally passive: no real tenant, no credentials, and no external APIs.

The first thing to look at is scope. The scope file allows three deterministic checks: inspect OAuth metadata, evaluate permissions, and score risk. It also blocks live tenant lookup.

Now I run the demo from the terminal. BOFA loads the scope, reads the sample OAuth app, executes the allowed checks, and writes three outputs: evidence, report JSON, and a Markdown report.

The important line is here in `evidence.jsonl`: `fetch_live_tenant_users` was planned, but it was blocked because it was outside scope. That is the behavior I want to show. The agent is not just taking action; it is recording boundaries.

Next is the report. This is the human-readable output: executive summary, scope, actions executed, evidence counts, risk decision, findings, limitations, and next steps. The app is synthetic, but the workflow is real and reproducible.

Now I run the SotyHub-style adapter. It reads `report.json` and emits a compact governance event with severity, risk score, dedupe key, findings count, and blocked tool count. This is adapter shape only, not a live SotyHub integration.

Finally, I run the tests. They use Python's standard `unittest`, so the demo does not need extra test tooling.

That is the full flow: explicit scope, deterministic execution, evidence logging, blocked out-of-scope action, report output, and adapter shape over synthetic input.

