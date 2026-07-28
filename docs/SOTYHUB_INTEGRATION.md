# BOFA and SotyHub

This document defines the product boundary between the open-source BOFA runtime
and a hosted SotyHub control plane.

It reflects the public SotyHub staging surfaces reviewed on 2026-07-28:

- individual beta workflows with scope, review, evidence and history
- guided team discovery with written authorization
- quotas, TTL, logging, kill switch and human review
- cloud VMs, Kali and dedicated environments priced separately
- no autonomous AI with operational authority

## Boundary

BOFA remains open source and portable:

- scripts, flows and labs
- projects, environments and explicit scope contracts
- execution profiles and policy evaluation
- signed worker protocol
- local and remote LLM provider adapters
- runs, events, artifacts and evidence receipts
- offline verification

SotyHub owns hosted product concerns:

- organization, tenant, identity and MFA
- entitlements, quotas, billing and cost controls
- approval workflows and written authorization records
- cloud account integration and worker provisioning
- secrets brokerage with short-lived credentials
- evidence retention and tenant isolation
- support, discovery and adoption reporting

SotyHub should consume BOFA contracts, not fork their meaning. A deployment may
replace the policy implementation, but it must not weaken the signed manifest
or worker verification rules.

## Managed run lifecycle

```text
User -> SotyHub identity and entitlement
     -> authorization grant and human approval
     -> BOFA preflight and signed JobSpec
     -> cloud provisioner creates one ephemeral worker
     -> worker pins SotyHub/BOFA control-plane public key
     -> worker claims and executes one BOFA job
     -> receipt and evidence upload
     -> human review and adoption decision
     -> teardown confirmation
```

The worker must not receive Firebase credentials, Stripe secrets, tenant-wide
tokens or the cloud provisioner's credentials.

## Provisioner contract

A SotyHub provisioner can target AWS, GCP, Azure, Hetzner, Kubernetes, Firecracker
or another provider if it satisfies this interface:

1. Create a worker from an image pinned by digest.
2. Apply CPU, memory, disk, egress and TTL limits.
3. Inject only the signed envelope, pinned public key and one-use evidence
   upload credential.
4. Return worker identity and provisioning events.
5. Expose an independent stop operation.
6. Destroy the compute resource and prove teardown.

Provider-specific Terraform, billing accounts and private networking belong to
the hosted deployment or a separate adapter package. They do not belong in the
portable BOFA core.

## Interactive Kali

Interactive Kali is useful for a human-led red team or bug bounty session, but
it should not be the default for every run.

A safe SotyHub Kali session needs:

- a written scope and named operator
- an expiring browser or bastion session, not public SSH
- no standing cloud credentials
- egress restricted to approved targets and required package mirrors
- session recording or command/evidence events where legally appropriate
- a visible cost meter and hard TTL
- an independent kill switch
- evidence export before teardown

Automation should prefer OCI or a microVM because it starts faster, costs less
and is easier to reproduce. Kali should be reserved for workflows that need an
interactive desktop, specialist binaries or human judgment.

## First hosted milestone

The first useful cloud milestone is intentionally narrow:

1. One minimal offline OCI worker published, signed and consumed by digest.
2. One defensive BOFA workflow.
3. One cloud provider adapter.
4. One signed job per ephemeral worker.
5. Receipt, evidence bundle and teardown event visible in SotyHub.
6. Cost and completion metrics captured per run.

Only after this path is reliable should SotyHub add an interactive Kali VM,
multi-provider scheduling or team pools.

The first BOFA worker image implements the image and one-job protocol portion
of this milestone. It does not yet implement cloud provisioning, evidence
upload credentials, cost metering or teardown attestation. Those remain the
next SotyHub integration slice.

## Compatibility rule

BOFA releases version the JobSpec and policy contract. SotyHub records the BOFA
version, policy version, image digest and key id for every run. A hosted run is
not reproducible if any of those four values is missing.
