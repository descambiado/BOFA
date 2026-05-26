# BOFA installation

BOFA can be approached in two practical ways today:

1. Try the offline duplicate-aware demo in minutes
2. Run the local stack for API + UI development

## Fastest path: feel BOFA first

This is the best first run if you want to understand the product before wiring
real targets or services.

```bash
git clone https://github.com/descambiado/BOFA
cd BOFA
pip install -r requirements.txt
python tools/demo_bounty_workspace.py --fresh
```

This generates:

- a real demo workspace
- imports, snapshots, deltas, findings, and review queue
- markdown and JSON artifacts under `data/demo_bounty_workspace/`

## Local development stack

### Requirements

- Python 3.8+
- Node.js 18+
- Git

Docker is useful for some labs and deployment scenarios, but it is not required
to feel the flagship workflow.

### Install dependencies

```bash
git clone https://github.com/descambiado/BOFA
cd BOFA
pip install -r requirements.txt
npm install
```

### Run the frontend

```bash
npm run dev
```

### Run verification

```bash
python tools/verify_runtime_hardening.py
python tools/verify_control_plane.py
python tools/verify_bounty_system.py
python tools/demo_bounty_workspace.py --fresh
npm run build
```

## Local stack notes

- Frontend uses Vite
- Backend is FastAPI-based
- BOFA persists runtime and workspace data locally
- Labs exist, but they are not the main reason to try BOFA today

## Recommended reading after install

- [README](../README.md)
- [STATUS](STATUS.md)
- [Bounty Workspaces](BUG_BOUNTY_WORKSPACES.md)
- [Tools README](../tools/README.md)
