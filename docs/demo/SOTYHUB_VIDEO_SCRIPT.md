# SotyHub Lab Control Plane Video Script

Target length: 3 minutes.

Status: staging required before final recording.

## Title

SotyHub Authorized Lab Control Plane: Request, Evidence, Cost, Kill Switch

## Honest Framing

The current BOFA repo contains lab/control-plane surfaces, but this workspace does not contain a verified SotyHub app implementation. Do not claim live SotyHub staging until a real staging rehearsal passes.

## Voiceover Script

### 0:00-0:20 Opening

This demo shows the control-plane idea behind authorized labs: a lab should not just start. It should be requested with scope, reviewed, tracked, evidenced, cost-aware, and stoppable.

### 0:20-0:50 Request

The user requests a lab with scope, TTL, quota, and use type. The goal is to make authorization explicit before execution. No real target is used.

### 0:50-1:20 Admin Review

The admin reviews the request. The approval step is where SotyHub governs the lab lifecycle: who asked, why, what is allowed, and how long it can run.

### 1:20-1:55 Evidence and Cost

Once approved, the control plane records events, estimated cost, artifacts, and report state. The important thing is traceability: every operation leaves evidence.

### 1:55-2:25 Kill Switch

The kill switch stops the lab and records the stop action. A demo should show that control is not only about starting things, but also about ending them safely.

### 2:25-3:00 Close

This is the governance layer: BOFA executes, SotyHub governs, and OpenClaw remains optional/manual. No production deployment or real target is required for the demo.

## Required Staging Shots

1. `/labs/requests`
2. request form with scope, TTL, quota, use type
3. admin lab request queue
4. approval action
5. evidence/report/cost/adapter view
6. kill switch action
7. final stopped state

## Local Fallback Story

If staging fails, record the BOFA local control-plane proof instead:

```powershell
py tools/verify_control_plane.py
npm run dev
```

Then capture:

- `http://localhost:8080/labs`
- lab inventory
- start/stop controls
- latest operation panel
- run/history page if available

Label the fallback clearly as BOFA local lab-control-plane rehearsal, not SotyHub staging.

