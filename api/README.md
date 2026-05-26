# BOFA API

The BOFA API exists to expose the same operational model used by the UI and
runtime:

- runs
- steps
- labs
- events
- artifacts
- bounty workspaces

It is not just a generic wrapper around scripts.

## Current strongest areas

### Runtime and evidence

- unified operational runs
- persistent run history
- artifacts attached to runs
- retry lineage and cancellation handling
- evidence export and verification flows

### Duplicate-aware bounty workflow

- workspace lifecycle
- imports for scope, disclosed reports, URLs, JS endpoints, and notes
- snapshots and surface deltas
- findings, clusters, and review queue
- bounty skills

## Key bounty endpoints

- `POST /bounty/workspaces`
- `GET /bounty/workspaces`
- `GET /bounty/workspaces/{workspace_id}`
- `POST /bounty/workspaces/{workspace_id}/imports`
- `POST /bounty/workspaces/{workspace_id}/analyze`
- `GET /bounty/workspaces/{workspace_id}/graph`
- `GET /bounty/workspaces/{workspace_id}/snapshots`
- `GET /bounty/workspaces/{workspace_id}/diffs?snapshot_id=<snapshot_id>`
- `GET /bounty/workspaces/{workspace_id}/diffs/latest`
- `GET /bounty/workspaces/{workspace_id}/findings`
- `GET /bounty/workspaces/{workspace_id}/review-queue`
- `POST /bounty/workspaces/{workspace_id}/review-queue/export`
- `GET /bounty/skills`
- `POST /bounty/workspaces/{workspace_id}/skills/{skill_key}/run`

## Verification

If you touch API behavior that affects the flagship workflow, run:

```bash
python tools/verify_runtime_hardening.py
python tools/verify_control_plane.py
python tools/verify_bounty_system.py
python tools/demo_bounty_workspace.py --fresh
```

## Notes

- The API is part of the same local-first story as the rest of BOFA
- Some educational or legacy surfaces may still exist, but they should not
  overshadow the flagship workflow
- When in doubt, prefer the runtime/evidence and bounty contracts as the source
  of truth
