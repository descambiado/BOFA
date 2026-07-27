# BOFA

![BOFA](https://github.com/descambiado/BOFA/blob/main/public/bofasuitebanner.png?raw=true)

![CI](https://github.com/descambiado/BOFA/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-green)
![Scripts](https://img.shields.io/badge/scripts-96%2B-orange)
![Flows](https://img.shields.io/badge/flows-25-blue)

BOFA is a local-first security runtime for **duplicate-aware web/API hunting, evidence and AI copilots**.

Its current promise is simple:

**BOFA helps you remember program context, detect what changed, and spend manual time where duplicate risk is lower.**

---

## Try BOFA In 2 Minutes

If you want to feel BOFA before wiring real targets, run the bundled offline demo workspace:

```bash
git clone https://github.com/descambiado/BOFA
cd BOFA
pip install -r requirements.txt
python tools/demo_bounty_workspace.py --fresh
```

That generates a real workspace with:

- scope imports
- observed URLs and API routes
- disclosed reports
- analyst notes
- snapshots and deltas
- findings and review queue exports

The demo leaves human-readable output under `data/demo_bounty_workspace/summary/` plus BOFA runtime artifacts under `data/demo_bounty_workspace/runtime/reports/workspaces/`.

---

## Why BOFA Exists

Most security stacks can run recon.

BOFA is trying to get better at something harder:

- keeping memory per program
- importing public intelligence and local notes
- building a target graph from surface data
- detecting deltas between snapshots
- scoring novelty and duplicate risk
- turning noisy findings into a short manual review queue
- keeping evidence, artifacts and run history attached to the same workflow

If you are tired of collecting obvious duplicates, that is the part of BOFA to care about first.

---

## Flagship Workflow

1. Create a bounty workspace for one program.
2. Import scope, disclosed reports, URL lists, Burp sitemap exports, JS endpoints or manual notes.
3. Analyze the workspace.
4. Review:
   - `What Changed`
   - `Novelty Queue`
   - `Duplicate Risk`
   - `Review Queue`
5. Execute skills like `delta_recon`, `duplicate_risk`, `surface_regression` or `manual_handoff`.
6. Export evidence and keep runtime history tied to the workspace.

Walkthrough:

- [Bounty Workspaces](docs/BUG_BOUNTY_WORKSPACES.md)

---

## AI Without Hand-Waving

BOFA is designed to support AI as a copilot over real evidence, not as a substitute for evidence.

- local or API-backed model providers can sit on top of the same workspace context
- the same runtime can drive CLI, API, web UI and MCP-friendly workflows
- skills are meant to accelerate triage and manual focus, not hide what happened

---

## Quick Start

### Full local stack

```bash
git clone https://github.com/descambiado/BOFA
cd BOFA
pip install -r requirements.txt
npm install
./bofa.sh
```

### Frontend only

```bash
npm run dev
```

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

---

## Main Components

### Duplicate-aware bounty

- bounty workspaces
- imports for scope, disclosed reports, URL lists, Burp sitemap, JS endpoints and notes
- target graph
- snapshots and surface deltas
- novelty findings
- duplicate-risk scoring
- clustered review queue
- bounty skills for tactical analysis

### Runtime and evidence

- unified runs, steps, labs, events and artifacts
- timeline persistence
- runtime cancellation and retry lineage
- evidence export per run
- signed bundles with offline verification

### Interfaces

- CLI for local operation
- FastAPI backend
- React web UI
- MCP server
- security agent with `run_skill` support

---

## What BOFA Is Not Pretending To Be

BOFA already has useful operational pieces, but this is the honest framing:

- the **runtime and evidence layers are the strongest production-facing pieces**
- the **labs and some educational surfaces are still educational-first**
- the **bug bounty system is the flagship growth direction**
- BOFA does **not** auto-report to HackerOne
- BOFA does **not** yet rely on authenticated HackerOne API access
- BOFA does **not** yet center browser-authenticated crawling in the bounty core

That honesty matters more than hype.

---

## Bounty Skills

Current workspace-native bounty skills include:

- `program_intel`
- `disclosed_report_graph`
- `delta_recon`
- `js_api_diff`
- `authz_matrix`
- `duplicate_risk`
- `report_novelty_gate`
- `surface_regression`
- `manual_handoff`

These are designed for a **copilot** workflow, not blind autopilot.

---

## Repository Health

Current direction:

- fewer contradictory claims
- more verification
- more workspace memory
- better evidence
- better novelty and duplicate-aware prioritization
- faster time-to-value for new users

Status page:

- [STATUS](docs/STATUS.md)

Changelog:

- [CHANGELOG](CHANGELOG.md)

---

## Responsible Use

Use BOFA only on systems you own or are authorized to assess.

This project is for:

- bug bounty and security research under program rules
- authorized pentesting
- local security labs and learning
- defensive validation and reproducible evidence workflows

---

## Useful Links

- [Bounty Workspaces](docs/BUG_BOUNTY_WORKSPACES.md)
- [Agent](docs/AGENT.md)
- [MCP Integration](docs/MCP_CURSOR_INTEGRATION.md)
- [Tools README](tools/README.md)
- [Scripts](scripts/README.md)
- [Labs](labs/README.md)
- [API](api/README.md)
