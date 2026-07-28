# BOFA + LLM for cybersecurity

BOFA combines model-assisted planning with deterministic security controls.

The LLM can:

- explain workspace evidence
- propose a BOFA script, flow or bounty skill
- summarize findings and deltas
- help prepare a human review

The LLM cannot:

- create or extend authorization
- approve its own action
- execute outside the written scope
- request blocked capabilities
- mutate cloud infrastructure
- report findings without human review

## Local-first providers

Ollama is the default. BOFA also supports a local OpenAI-compatible endpoint
such as LM Studio or vLLM. OpenAI and Anthropic remain explicit remote options;
their descriptor tells the UI that workspace data leaves the runtime.

## Execution path

```text
User intent
  -> LLM proposes one structured BOFA action
  -> BOFA validates subject, scope, approval, capabilities and quotas
  -> allowed action becomes a signed JobSpec
  -> local or ephemeral worker executes a catalogued adapter
  -> evidence and receipt return for human review
```

MCP clients should follow the same rule: discovery and planning are safe by
default; an execution tool must be tied to an authorization grant and preflight.

## References

- [Policy-gated agent](AGENT.md)
- [AI Control Plane](AI_CONTROL_PLANE.md)
- [Execution Fabric](EXECUTION_FABRIC.md)
- [Orchestration and chaining](ORCHESTRATION_AND_CHAINING.md)
