# BOFA Agent Scope

This mission is limited to passive triage of a suspicious OAuth application using synthetic data.

Allowed operations:

- Read the local scope JSON.
- Read the local synthetic input JSON.
- Execute deterministic mock tool functions.
- Record evidence locally.
- Produce local reports.
- Demonstrate a SotyHub-style consumer through `examples/sotyhub_consumer.py`.

Forbidden operations:

- Real targets.
- Real OAuth tenants.
- Real credentials.
- External API calls.
- Offensive tooling.
- SotyHub code changes beyond the adapter example.
- OpenClaw code changes.
- Cloud infrastructure.

