# Demo Master Plan

## Mission

Prepare two presentable demos without adding product features:

1. BOFA Agent OAuth Triage.
2. SotyHub Authorized Lab Control Plane.

The production rule is simple: show only what is real, local, authorized, and reviewable.

## Current Readiness

| Demo | Status | Recording Readiness | Main Gate |
| --- | --- | --- | --- |
| BOFA Agent OAuth Triage | Implemented and committed locally as `e869b76` on `bofa-agent-v1` | Ready for local recording after one fresh command pass | Use only synthetic data and adapter wording |
| SotyHub Authorized Lab Control Plane | Not verified in this repo as a SotyHub app; BOFA lab/control-plane surfaces exist | Requires staging/rehearsal before final recording | Prove API-backed run/timeline evidence or clearly label fallback as local/simulated |

## Demo 1: BOFA Agent OAuth Triage

Message:

> BOFA Agent defines scope before acting, records evidence for every step, and generates auditable reports for a synthetic OAuth triage case.

Assets already available:

- `docs/AGENT_SCOPE.md`
- `docs/AGENT_CONTRACT.md`
- `docs/DEMO_OAUTH_TRIAGE.md`
- `bofa/agent/demo/scope.oauth_triage.json`
- `bofa/agent/demo/input.sample.json`
- `bofa/agent/demo/oauth_app_triage.py`
- `examples/sotyhub_consumer.py`
- `tests/test_agent_*.py`

Commands:

```powershell
py -m bofa.agent.demo.oauth_app_triage
py examples/sotyhub_consumer.py bofa/agent/demo/output/report.json
py -m unittest discover -s tests
```

Fallback when `py` is unavailable:

```powershell
python -m bofa.agent.demo.oauth_app_triage
python examples/sotyhub_consumer.py bofa/agent/demo/output/report.json
python -m unittest discover -s tests
```

Codex bundled Python fallback used in validation:

```powershell
& 'C:\Users\davyd\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -m bofa.agent.demo.oauth_app_triage
```

## Demo 2: SotyHub Authorized Lab Control Plane

Message:

> SotyHub allows an authorized lab request to be reviewed, approved, evidenced, cost-estimated, reported, and stopped with a kill switch.

Repo reality as of this audit:

- No concrete SotyHub application tree was found in this workspace.
- BOFA has local lab/control-plane surfaces: `src/pages/Labs.tsx`, `api/main.py`, `api/lab_manager.py`, `tools/verify_control_plane.py`.
- Any public SotyHub claim must wait for staging verification.

Local rehearsal commands to verify before recording:

```powershell
py tools/verify_control_plane.py
npm run build
```

Optional UI rehearsal, only if dependencies and ports are clean:

```powershell
npm run dev
```

Expected UI URL from Vite config:

```text
http://localhost:8080/labs
```

## Assets We Can Produce Locally

- Demo docs and runbooks.
- Terminal transcript for BOFA Agent.
- Markdown/JSON report excerpts.
- Screenshot checklist and placeholders.
- LinkedIn, X, and YouTube copy.
- Risk review and publication checklist.

## Assets Requiring Human/Staging

- Final voice/face recording.
- Any live SotyHub staging proof.
- Any real Firebase or production-like environment capture.
- Final publishing from personal/company accounts.
- Any push, deploy, or public release approval.

## 24 Hour Plan

1. Lock this audit pack in `docs/demo`.
2. Generate BOFA Agent screenshots or placeholders under `docs/demo-assets/` if the local environment allows safe capture.
3. Re-run BOFA Agent demo, adapter, and tests immediately before recording.
4. Rehearse BOFA Agent video once with the script in `BOFA_AGENT_VIDEO_SCRIPT.md`.
5. Run `tools/verify_control_plane.py` for the lab-control-plane baseline.
6. If staging exists, follow `SOTYHUB_STAGING_REHEARSAL.md`; otherwise record only the local fallback story.
7. Run `RISK_REVIEW.md` publication gates.
8. Ask for explicit approval before commit/push/deploy/publication.

