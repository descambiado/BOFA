# BOFA at a glance

BOFA is a local-first security runtime for duplicate-aware web/API hunting,
evidence, and AI copilots.

Its strongest story today is simple:

- keep memory per program
- import public intelligence and local notes
- detect what changed between snapshots
- surface novelty and duplicate risk
- turn noisy findings into a short manual review queue
- keep artifacts and evidence tied to the same operational history

## Try the flagship flow fast

```bash
git clone https://github.com/descambiado/BOFA
cd BOFA
pip install -r requirements.txt
python tools/demo_bounty_workspace.py --fresh
```

That generates a real offline workspace with:

- scope imports
- observed URLs and API routes
- disclosed reports
- analyst notes
- snapshots and deltas
- findings and review queue exports

## What BOFA is today

### 1. Runtime and evidence

- unified runs, steps, labs, events, and artifacts
- retry lineage and cancellation handling
- signed evidence bundles and offline verification

### 2. Duplicate-aware bounty workspaces

- workspaces per program
- imports for scope, disclosed reports, URL lists, Burp sitemap, JS endpoints, and notes
- local-first target graph
- novelty scoring and duplicate-risk scoring
- tactical review queue and bounty skills

### 3. Interfaces

- CLI
- FastAPI backend
- React web UI
- MCP-friendly integration

## What BOFA is not pretending to be

- It is not a full replacement for every specialist tool in security
- It is not browser-authenticated crawling at the core today
- It is not auto-reporting to bug bounty platforms
- It is not "AI does everything for you"

## Where BOFA wins

BOFA wins when the problem is not "run recon once", but:

- keep context over time
- compare surface snapshots
- reduce duplicate-heavy manual work
- keep evidence and runtime history attached to the same workflow

## Best next docs

- [README](../README.md)
- [STATUS](STATUS.md)
- [Bounty Workspaces](BUG_BOUNTY_WORKSPACES.md)
- [Tools README](../tools/README.md)
- [Next Steps and Roadmap](NEXT_STEPS_AND_ROADMAP.md)
