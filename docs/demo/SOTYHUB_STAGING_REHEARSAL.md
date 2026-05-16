# SotyHub Staging Rehearsal

## Status

Blocked until a real SotyHub staging environment or repo is available. This BOFA workspace only proves local lab/control-plane concepts and the BOFA Agent SotyHub-style adapter.

## Rehearsal Gates

Before recording:

- Staging URL confirmed.
- Test account confirmed.
- No real credentials visible on screen.
- Demo seed data uses fake organization, fake users, and fake lab names.
- Firebase or backend rules are staging-only.
- Cost values are estimates or synthetic demo values.
- Kill switch is tested against a safe lab only.

## Scenario

1. Sign in with staging/demo account.
2. Open `/labs/requests`.
3. Create request:
   - scope: `demo-oauth-lab-synthetic`
   - TTL: `30 minutes`
   - quota: `low`
   - use type: `training/demo`
   - target: `example.invalid` or no target
4. Switch to admin view.
5. Approve the request.
6. Show generated evidence/report/cost/adapter state.
7. Trigger kill switch.
8. Confirm final stopped state.

## Pass Criteria

- No production data appears.
- Request includes scope, TTL, quota, and use type.
- Approval is visible.
- Evidence or timeline is visible.
- Cost estimate is visible and clearly labeled.
- Kill switch stops the lab.
- Final state is stable enough to screenshot.

## Fallback If Staging Fails

Use BOFA local control-plane rehearsal:

```powershell
py tools/verify_control_plane.py
npm run dev
```

Capture `http://localhost:8080/labs` and present it as local rehearsal, not final SotyHub staging.

