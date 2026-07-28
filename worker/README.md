# BOFA worker

The BOFA worker is the minimal execution adapter for an ephemeral OCI container
or virtual machine.

It accepts a signed BOFA job envelope, verifies the pinned Ed25519 control-plane
key and runs only a named BOFA script or flow. It does not accept arbitrary
shell commands.

Required deployment properties:

- image pinned by SHA-256 digest
- restricted or disabled network
- CPU, memory, disk and TTL enforced outside the Python process
- persistent replay claim store for multi-job workers
- one-use evidence upload credential
- teardown after completion or failure

See [Execution Fabric](../docs/EXECUTION_FABRIC.md) for the protocol and
[BOFA and SotyHub](../docs/SOTYHUB_INTEGRATION.md) for hosted provisioning.
