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

The runner refuses to replace any of these artifacts on a repeat run. Choose a new output directory or pass `--overwrite` explicitly:

```powershell
python -m bofa.agent.demo.oauth_app_triage --output-dir .tmp/oauth-run-02
python -m bofa.agent.demo.oauth_app_triage --overwrite
```

Input is checked before artifacts are created: application identity fields and typed permission/redirect lists are required, planned tool calls must be unique, and a run is capped at 32 planned calls. Tool outputs with invalid risk scores, malformed findings, or non-JSON data are recorded as failed and make the report `partial_failed`.

`evidence.jsonl` is a canonical SHA-256 hash chain. The report includes the verified chain head and event count. This detects accidental or partial tampering when the evidence is read; it is not signed, immutable storage, or proof against someone who can rewrite both the chain and report.

Verify the report/evidence pair independently after copying both artifacts:

```bash
python -m bofa.agent.verify_bundle --report .tmp/oauth-run-02/report.json --evidence .tmp/oauth-run-02/evidence.jsonl
```

The verifier checks the SHA-256 event chain and that the report's event count and chain head match it. Its output explicitly marks signature verification as false. A successful result is an integrity consistency check, not a digital signature or proof of who created the files.

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

For this demo's self-contained tests only, use:

```bash
python -m unittest discover -s tests -p "test_agent_*.py"
```

The wider repository test discovery also imports `tests/test_auth.py`, which requires the optional `pytest` dependency.

## Three Minute Recording Flow

1. Show `docs/AGENT_SCOPE.md` and explain that the run is synthetic and passive.
2. Run `python -m bofa.agent.demo.oauth_app_triage --output-dir .tmp/oauth-run-02`.
3. Run `python -m bofa.agent.verify_bundle --report .tmp/oauth-run-02/report.json --evidence .tmp/oauth-run-02/evidence.jsonl`.
4. Open `evidence.jsonl` and point out the blocked `fetch_live_tenant_users` call and linked event hashes.
5. Open `report.md` and show severity, findings, blocked tools, run status, and the explicitly unsigned evidence-integrity state.
6. Run the SotyHub consumer example to show downstream ingestion shape.

## Expected Result

The report classifies the synthetic app as `high` risk because it has an unverified publisher, an insecure redirect URI, broad or persistent permissions, and an existing sample consent. The attempted live tenant user lookup is blocked because it is outside the allowlist.
