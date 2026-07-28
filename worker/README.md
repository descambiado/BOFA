# BOFA one-job OCI worker

This directory contains BOFA's first deployable worker image. It is deliberately
small: the initial catalog allows only the offline
`forensics/hash_calculator` adapter with `evidence_read` capability and no
network interface.

The worker accepts a signed BOFA job envelope and a pinned Ed25519 public key.
It never accepts a shell command, package installation or an adapter that is
not baked into `catalog.json`.

## Local proof

With Docker running:

```bash
python tools/demo_worker_oci.py --build
```

The command:

1. builds `worker/Dockerfile`
2. creates a short-lived authorization grant and signed JobSpec
3. launches the image with a read-only root filesystem, no network, no Linux
   capabilities, `no-new-privileges`, CPU/memory/PID limits and writable
   one-use mounts only
4. executes the harmless hash fixture
5. verifies the manifest binding and receipt

Fixtures and receipts remain under `data/demo_worker_oci/` for inspection.
The local Docker image ID proves the local path only; hosted deployments must
launch the GHCR image by its immutable registry digest.

## Image contract

The image runs as UID/GID `65532`, has no package manager step or offensive
system binary, and contains only:

- BOFA core policy and execution code
- the worker runtime and immutable catalog
- `forensics/hash_calculator`
- pinned Python runtime dependencies

The surrounding dispatcher must enforce:

- launch by `repository@sha256:digest`
- read-only root filesystem
- CPU, memory, PID, disk and total TTL limits
- network mode matching the signed profile
- no added capabilities or privileged mode
- read-only envelope and trusted-key mounts
- one-use replay and receipt stores
- teardown after success, denial, timeout or cancellation

The first image supports only `network_mode=none`. Restricted egress is not
claimed until a provisioner can prove its firewall policy.

## Supply chain

`.github/workflows/worker-image.yml` builds and executes the image on pull
requests. On `main`, it publishes `linux/amd64` and `linux/arm64` images to
`ghcr.io/descambiado/bofa-worker`, attaches BuildKit SBOM/provenance, scans
for high and critical vulnerabilities, blocks findings with an available fix
and signs the immutable digest with Cosign keyless identity. Unfixed upstream
findings remain visible in the scan output without making a release impossible
before the base distribution ships a remediation.

All third-party actions in that workflow are pinned to full commit SHAs. The
base Python image is pinned to a multi-platform digest.

Example signature verification after publication:

```bash
cosign verify \
  --certificate-identity "https://github.com/descambiado/BOFA/.github/workflows/worker-image.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/descambiado/bofa-worker@sha256:<published-digest>
```

See [Execution Fabric](../docs/EXECUTION_FABRIC.md) for the protocol and
[BOFA and SotyHub](../docs/SOTYHUB_INTEGRATION.md) for hosted provisioning.
