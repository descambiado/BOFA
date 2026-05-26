# BOFA Scripts

This directory contains the executable script catalog used by the BOFA runtime.

The scripts matter, but they are not the whole product. BOFA becomes more useful when these scripts run through the CLI, API or web workspace so execution, evidence and history stay attached to the same workflow.

## What lives here

- category folders such as `recon/`, `blue/`, `forensics/` and `study/`
- Python entrypoints plus YAML sidecars with metadata
- outputs that can be surfaced in the UI, API and runtime history

## How BOFA uses scripts

1. The runtime discovers script metadata from YAML files.
2. Operators launch scripts through BOFA interfaces instead of treating them as disconnected one-offs.
3. BOFA records parameters, timestamps, output, status and exported artifacts.
4. Results can feed review flows, evidence packages and bounty workspaces.

## Stability expectations

- Scripts that reinforce the flagship web/API hunting workflow are the highest-signal paths.
- Some catalog areas are still educational or experimental.
- When in doubt, improve metadata, parameters and output quality before adding more surface area.

## Running scripts

### CLI

```bash
./bofa.sh
python3 cli/bofa_cli.py
```

### Full BOFA stack

```bash
./bofa.sh
```

### Verification

```bash
python tools/verify_runtime_hardening.py
python tools/verify_control_plane.py
```

## Script metadata

Each script should describe itself with a YAML sidecar so BOFA can expose it consistently across interfaces.

```yaml
name: "script_name"
description: "What the script does"
category: "recon"
author: "@descambiado"
version: "1.0"
parameters:
  target:
    type: "string"
    required: true
    description: "Target host or URL"
```

Useful parameter types include `string`, `integer`, `boolean`, `select`, `file`, `multiselect` and `choice`.

## Adding or refining scripts

Use this directory when the change improves BOFA as a runtime:

- make outputs easier to review or export
- structure parameters so the UI and API can render them cleanly
- add clearer failure modes and logging
- keep scripts usable in authorized local workflows

For contribution guidance, see [CONTRIBUTING](../CONTRIBUTING.md).

## Responsible use

Use BOFA only on systems you own or are explicitly authorized to assess.

- Document your runs.
- Prefer reproducible evidence over one-off console output.
- Do not use these scripts against unauthorized targets.

## Support

- GitHub issues: [descambiado/BOFA issues](https://github.com/descambiado/BOFA/issues)
- Project overview: [README](../README.md)
- Workflow docs: [docs](../docs)
