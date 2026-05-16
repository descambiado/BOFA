# Demo: Passive OAuth Application Triage

This demo shows a scoped BOFA agent run that triages a suspicious OAuth application without touching real infrastructure.

## Run

On Windows, try these in order from the repository root:

```bash
py -m bofa.agent.demo.oauth_app_triage
```

If the Python launcher is not installed:

```bash
python -m bofa.agent.demo.oauth_app_triage
```

In Codex Desktop or another environment where Python is bundled but not on `PATH`, use the explicit interpreter path shown by the environment. In this workspace validation run, that path was:

```powershell
& 'C:\Users\davyd\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -m bofa.agent.demo.oauth_app_triage
```

Outputs are written to:

- `bofa/agent/demo/output/evidence.jsonl`
- `bofa/agent/demo/output/report.json`
- `bofa/agent/demo/output/report.md`

## SotyHub Adapter Example

```bash
python examples/sotyhub_consumer.py bofa/agent/demo/output/report.json
```

If `python` is not on `PATH`, use the same interpreter that ran the demo.

## Tests

The minimum tests use Python's stdlib `unittest`, so no external test dependency is required:

```bash
python -m unittest discover -s tests
```

`pytest` can also discover the tests if the optional dev dependencies are installed, but it is not required for this demo.

## Three Minute Recording Flow

1. Show `docs/AGENT_SCOPE.md` and explain that the run is synthetic and passive.
2. Run `python -m bofa.agent.demo.oauth_app_triage`.
3. Open `evidence.jsonl` and point out the blocked `fetch_live_tenant_users` call.
4. Open `report.md` and show severity, findings, and blocked tools.
5. Run the SotyHub consumer example to show downstream ingestion shape.

## Expected Result

The report classifies the synthetic app as `high` risk because it has an unverified publisher, an insecure redirect URI, broad or persistent permissions, and an existing sample consent. The attempted live tenant user lookup is blocked because it is outside the allowlist.
