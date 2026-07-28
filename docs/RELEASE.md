# BOFA release guide

## Current public release

- `v2.9.1` published on 2026-04-29

## Current release candidate direction

The next useful patch release should package the work that improves:

- public positioning
- offline demo and proof of value
- license detection and repo trust
- snapshot/delta consistency in the bounty workflow

Candidate label:

- `v2.9.2`

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
git add -A
git status
git commit -m "Release v2.9.2: tighten flagship workflow and public signal"
git tag -a v2.9.2 -m "v2.9.2 tighten flagship workflow and public signal"
git push origin main
git push origin v2.9.2
```
