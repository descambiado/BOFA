# BOFA Execution Fabric

BOFA v3 introduces a portable contract for authorized security work across a
local runtime, an OCI container, or an ephemeral virtual machine.

This is not a generic remote shell. The unit of work is a signed `JobSpec` that
names one BOFA script or flow, its target, required capabilities, approval,
limits, runner profile, expiry and canonical SHA-256 digest.

## Security model

Every controlled run follows the same sequence:

1. An administrator issues a time-limited authorization grant.
2. The grant binds a subject, project, environment, explicit scope,
   capabilities, quotas and optional human approval.
3. BOFA performs a deny-by-default preflight.
4. An allowed request becomes a canonical manifest signed with Ed25519.
5. The worker verifies the digest, signature, pinned key, target binding,
   expiry, exact launched image identity, baked adapter catalog, capabilities
   and runtime network mode.
6. The worker atomically claims the job so the same envelope cannot execute
   twice.
7. The BOFA adapter runs a catalogued script or flow. It never evaluates an
   arbitrary shell command from the envelope.
8. The worker returns an Ed25519-signed receipt with timestamps and hashes of
   captured output. The receipt key is separate from the JobSpec signing key.
9. The surrounding OCI or VM runtime uploads evidence and destroys the worker.

`privileged` and `cloud_mutation` are blocked by the default policy. Wildcard
scope is not accepted.

## Profiles

| Profile | State by default | Intended use |
|---------|------------------|--------------|
| `local-controlled` | Enabled | Local development and authorized workstation runs |
| `oci-ephemeral` | Disabled until image and digest exist | Automated, short, non-interactive jobs |
| `remote-ephemeral` | Disabled until endpoint, image and digest exist | Managed cloud worker or microVM |

Configuration:

```env
BOFA_OCI_WORKER_IMAGE=ghcr.io/descambiado/bofa-worker
BOFA_OCI_WORKER_IMAGE_DIGEST=sha256:<64-hex-digest>

BOFA_REMOTE_WORKER_URL=https://worker-control.example.internal
BOFA_REMOTE_WORKER_IMAGE=ghcr.io/descambiado/bofa-kali-worker
BOFA_REMOTE_WORKER_IMAGE_DIGEST=sha256:<64-hex-digest>
```

An image tag alone is insufficient. BOFA requires an immutable digest and the
worker compares the signed profile with the image reference and digest supplied
by the dispatcher. The current OCI image also observes that only the loopback
interface exists before accepting `network_mode=none`.

## First OCI image

`worker/Dockerfile` is the first concrete implementation of the worker
contract. It runs as UID/GID `65532`, contains one offline evidence adapter and
uses an immutable catalog. It intentionally has no network capability and is
not a Kali image.

Run the complete harmless proof locally:

```bash
python tools/demo_worker_oci.py --build
```

The dedicated image workflow builds and executes the proof on pull requests.
After merge to `main`, it publishes the image to GHCR with an SBOM, provenance,
fixable high/critical vulnerability gate and a keyless Cosign signature.

## Kali, containers and virtual machines

Use the smallest isolation boundary that fits the workflow:

- OCI container or microVM for repeatable, non-interactive scripts and flows.
- Kali VM for an interactive, tool-rich, human-led assessment.
- Ubuntu or a minimal hardened image for defensive collection and evidence
  processing.

The worker protocol is distribution-independent. Kali is an image choice, not a
special authority level.

The infrastructure layer must enforce the manifest limits with cgroups,
hypervisor controls or an equivalent mechanism:

- CPU and memory ceiling
- total TTL
- output and disk quota
- restricted egress
- no inbound public SSH
- immutable base image
- teardown on completion, timeout, revocation or operator stop

BOFA enforces contract limits in its adapters too, but process-level checks do
not replace OCI or hypervisor isolation.

## Worker command

Inspect an envelope without executing:

```bash
python tools/run_worker_job.py job.json \
  --trusted-key control-plane-public.pem \
  --worker-id worker-01 \
  --image-reference ghcr.io/descambiado/bofa-worker \
  --image-digest sha256:<64-hex-digest> \
  --runtime-network-mode none
```

Execute after verification:

```bash
python tools/run_worker_job.py job.json \
  --trusted-key control-plane-public.pem \
  --worker-id worker-01 \
  --replay-store /var/lib/bofa-worker/claims \
  --image-reference ghcr.io/descambiado/bofa-worker \
  --image-digest sha256:<64-hex-digest> \
  --runtime-network-mode none \
  --execute
```

The replay store uses an atomic marker per manifest digest. A managed worker
must keep that store durable for its lifetime; a one-job VM can use its
ephemeral disk because the VM is destroyed immediately afterwards.

## API

- `GET /execution/capabilities`
- `GET /execution/trust`
- `POST /execution/grants`
- `GET /execution/grants`
- `POST /execution/grants/{grant_id}/revoke`
- `POST /execution/preflight`
- `POST /execution/jobs`
- `GET /execution/service/trust`
- `POST /execution/service/preflight`
- `POST /execution/service/jobs`

The current API dispatches only `local-controlled`. OCI and remote profiles
produce valid preflight contracts but deliberately return `409` until a managed
dispatcher is configured. Controlled labs are remote-only because a local
Docker lab does not satisfy the ephemeral teardown contract.

The `/execution/service/*` routes are a separate SotyHub workload-identity
boundary. They require an exactly pinned Google OIDC service account and accept
only the offline evidence canary. The service job endpoint creates a durable
one-use claim and signed JobSpec but reports `dispatch_performed=false`; it does
not provision or mutate cloud infrastructure.

## Verification

```bash
python tools/verify_execution_fabric.py
python tools/verify_worker_protocol.py
python tools/verify_worker_oci.py
python tools/verify_execution_api.py
python tools/verify_sotyhub_service_identity.py
```

These checks cover scope, approval, quotas, pinned images, blocked capabilities,
signature tampering, wrong keys, target rebinding, image identity, immutable
adapter catalogs, network mode, expiry and replay.
