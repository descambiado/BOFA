# BOFA policy-gated security copilot

The BOFA agent is plan-first. It can use a local or remote LLM to propose the
next BOFA action, but it does not execute by default.

## Local planning

```bash
ollama pull llama3.2
ollama serve
python tools/run_agent.py https://authorized.example --provider ollama
```

LM Studio, vLLM or another OpenAI-compatible local server:

```bash
export BOFA_OPENAI_COMPATIBLE_URL=http://127.0.0.1:1234/v1
export BOFA_OPENAI_COMPATIBLE_MODEL=local-model
python tools/run_agent.py https://authorized.example --provider openai_compatible
```

`auto` is local-first and resolves to `BOFA_LLM_PROVIDER`, or Ollama when the
variable is absent.

## Remote planning

OpenAI and Anthropic are available as explicit providers. They transmit prompt
context outside the local runtime and require their corresponding API key.
BOFA never falls back to them automatically.

## Execution

Execution requires all three policy inputs:

```bash
python tools/run_agent.py https://authorized.example \
  --provider ollama \
  --execute \
  --subject-id 42 \
  --grant-file grant.json \
  --profile-file profile.json
```

For every proposed action BOFA checks:

- subject, project and environment
- grant issue and expiry times
- exact target scope
- required capabilities
- matching approval
- duration and step quotas
- enabled execution profile
- restricted network and pinned remote image

If any check fails, the executor is not imported or called.

## Why this changed

An LLM can be useful for selecting and explaining tools, but model output is
untrusted input. Scope, approval and evidence must remain deterministic and
auditable.

See [AI Control Plane](AI_CONTROL_PLANE.md) and
[Execution Fabric](EXECUTION_FABRIC.md).
