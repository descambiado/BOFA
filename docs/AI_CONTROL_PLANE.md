# BOFA AI Control Plane

BOFA treats an LLM as a copilot, not as an authority.

The model may explain evidence, propose a sequence of BOFA actions and summarize
results. It cannot create grants, expand scope, approve itself, select hidden
capabilities or bypass preflight.

## Modes

### Plan-only

This is the default. The agent asks a provider for one proposed action and
returns the plan without importing or invoking an executor.

```bash
python tools/run_agent.py https://authorized.example --provider ollama
```

### Policy-gated execution

Execution is explicit and requires a subject, grant and profile:

```bash
python tools/run_agent.py https://authorized.example \
  --provider ollama \
  --execute \
  --subject-id 42 \
  --grant-file grant.json \
  --profile-file profile.json
```

Every proposed action is evaluated against the same BOFA scope and capability
policy. An out-of-scope action stops before the executor is reached.

## Providers

| Provider | Locality | Workspace data leaves the runtime |
|----------|----------|-----------------------------------|
| Ollama | Local | No |
| OpenAI-compatible (LM Studio or vLLM) | Local by default | No |
| OpenAI | Remote | Yes |
| Anthropic | Remote | Yes |

`auto` selects `BOFA_LLM_PROVIDER`, defaulting to `ollama`. It never selects a
remote provider merely because an API key exists.

Remote planning through `POST /ai/plan` requires
`allow_remote_data=true` on that request. This is explicit consent, not a
global switch.

## Configuration

```env
BOFA_LLM_PROVIDER=ollama
BOFA_OLLAMA_URL=http://127.0.0.1:11434
BOFA_OLLAMA_MODEL=llama3.2

BOFA_OPENAI_COMPATIBLE_URL=http://127.0.0.1:1234/v1
BOFA_OPENAI_COMPATIBLE_MODEL=local-model
BOFA_OPENAI_COMPATIBLE_API_KEY=

OPENAI_API_KEY=
BOFA_OPENAI_MODEL=

ANTHROPIC_API_KEY=
BOFA_ANTHROPIC_MODEL=
```

The model names are deployment configuration. BOFA does not silently change a
model or send data to a fallback provider.

## API

- `GET /ai/providers` reports locality, configuration and data transmission.
- `POST /ai/plan` requires an active grant and an in-scope target.

The response always includes `authority: plan_only`.

## Non-goals

- fully autonomous pentesting
- model-created authorization
- model-controlled cloud infrastructure
- invisible provider fallback
- automatic reporting without human review

The useful AI advantage is better triage over BOFA evidence, not more
unaccountable actions.
