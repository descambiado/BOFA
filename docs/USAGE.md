# BOFA usage

The most useful way to think about BOFA today is not "all the tools", but "one
runtime that keeps context, evidence, and tactical review in the same place."

## Core workflow

1. Create or select a workspace
2. Import scope, reports, URLs, JS endpoints, or notes
3. Analyze the workspace
4. Review snapshots, deltas, findings, and review queue
5. Run tactical skills
6. Export artifacts and keep the operational history

## Fastest hands-on path

```bash
python tools/demo_bounty_workspace.py --fresh
```

This is the easiest way to understand what BOFA is trying to solve.

## Main entry points

### 1. Web UI

Use the web UI when you want:

- workspace creation and review
- snapshot and delta visibility
- bounty review queue access
- operational history and artifacts

Start the frontend with:

```bash
npm run dev
```

### 2. CLI

Use the CLI when you want:

- local operation
- direct script and module access
- engine-oriented workflows

Typical entry points:

```bash
./bofa.sh
python3 cli/bofa_cli.py
```

### 3. API

Use the API when you want:

- programmatic access to runs and workspaces
- UI/backend integration
- operational flows over HTTP

See [api/README.md](../api/README.md).

## What to focus on first

If you are evaluating BOFA, focus on these questions:

- Does it keep useful memory per program?
- Does `What Changed` help me notice something worth manual time?
- Does the review queue feel better than a flat list of noisy findings?
- Does the evidence stay attached to the same run history?

If the answer starts becoming "yes", BOFA is working for its intended use case.

## What not to expect yet

- authenticated browser-centric crawling as the core experience
- automatic report submission
- a full replacement for every specialist security tool

## Suggested next docs

- [STATUS](STATUS.md)
- [Bounty Workspaces](BUG_BOUNTY_WORKSPACES.md)
- [Agent](AGENT.md)
- [Tools README](../tools/README.md)
