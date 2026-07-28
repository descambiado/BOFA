# BOFA release guide

## Current public release

- `v2.9.1` published on 2026-04-29

## Current release candidate direction

`v2.9.2` remains the stable prerequisite. The next feature candidate is:

- `v3.0.0-alpha.1`
- execution fabric and signed worker protocol
- plan-first, local-first AI
- BOFA/SotyHub integration boundary
- no stable v3 tag until a remote provisioner is demonstrated

## Release checklist

### Product truth

- README matches what BOFA can actually do today
- docs do not oversell experimental areas
- flagship workflow is the clearest story in the repo

### Verification

```bash
python tools/verify_runtime_hardening.py
python tools/verify_runtime_catalog.py
python tools/verify_control_plane.py
python tools/verify_bounty_system.py
python tools/verify_auth_security.py
python tools/verify_execution_fabric.py
python tools/verify_worker_protocol.py
python tools/verify_ai_control.py
python tools/verify_execution_api.py
python tools/demo_bounty_workspace.py --fresh
npm run lint
npx tsc --noEmit -p tsconfig.app.json
npm run build
```

### Version alignment

Before tagging, make sure versions are coherent in the main user-facing places:

- `pyproject.toml`
- `package.json`
- `cli/bofa_cli.py`
- `README.md`
- `CHANGELOG.md`

## GitHub metadata checklist

These items matter more than they look:

- repo description aligned with the flagship story
- topics set
- license detected by GitHub
- homepage set if a stable public page exists
- release notes that explain why this version matters

## Suggested release note structure

1. What changed for the flagship workflow
2. What became more credible or easier to try
3. What is still intentionally out of scope
4. Verification performed for the release

## Suggested commands

```bash
git add <reviewed-files>
git status
git commit -m "Add v3 execution fabric alpha"
git push -u origin codex/execution-fabric-v3
```

Do not create a v3 tag from the alpha PR. Merge and release remain separate
decisions.
