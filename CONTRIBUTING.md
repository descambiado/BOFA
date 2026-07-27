# Contributing to BOFA

Thank you for helping improve BOFA.

BOFA is not trying to be "every security tool in one repo". The current flagship
direction is a local-first runtime for duplicate-aware web/API hunting, evidence,
and AI copilots that work on top of real context.

If you contribute, the best contributions are the ones that make BOFA more real,
more reproducible, and more useful in that flow.

## Best contribution areas

- Bounty workspaces, imports, snapshots, deltas, and review queue
- Runtime, evidence, artifacts, and verification
- Frontend clarity around the flagship workflow
- Honest documentation, examples, and demo material
- Bug fixes and tests that reduce ambiguity or friction

## Before you start

Read these first:

- [README](README.md)
- [docs/STATUS.md](docs/STATUS.md)
- [docs/BUG_BOUNTY_WORKSPACES.md](docs/BUG_BOUNTY_WORKSPACES.md)
- [tools/README.md](tools/README.md)

## Local setup

```bash
git clone https://github.com/yourusername/BOFA
cd BOFA
pip install -r requirements.txt
npm install
```

Quick feel for the flagship workflow:

```bash
python tools/demo_bounty_workspace.py --fresh
```

## Verification before a PR

Run the checks that match your changes. For most BOFA changes, this is the
minimum useful baseline:

```bash
python tools/verify_runtime_hardening.py
python tools/verify_control_plane.py
python tools/verify_bounty_system.py
python tools/demo_bounty_workspace.py --fresh
npm run build
```

If you touch frontend-only code, still run `npm run build`.

If you touch bounty behavior, run `python tools/verify_bounty_system.py` and the
demo workspace.

## Pull request expectations

- Keep the change scoped and explain the user-facing impact
- Prefer improving a real workflow over adding surface area
- Include verification steps and actual results
- Update docs when behavior or positioning changes
- Do not oversell experimental features

## Coding expectations

- Preserve the local-first model
- Prefer explicit artifacts and evidence over hidden magic
- Keep AI features as copilots over real context, not as unsupported claims
- Avoid adding flashy features that weaken the flagship story
- Favor reproducibility, traceability, and useful defaults

## Good first improvements

- Tighten a weak or confusing doc
- Improve demo output or examples
- Fix snapshot, delta, review queue, or evidence edge cases
- Reduce frontend friction in the bounty workflow
- Add or improve verification coverage

## Security and responsible use

Use BOFA only on systems you own or are authorized to assess.

Report vulnerabilities or sensitive security issues to:

- `david@descambiado.com`

For public bugs and feature requests, use:

- [GitHub Issues](https://github.com/descambiado/BOFA/issues)
