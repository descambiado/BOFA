# BOFA Agent OAuth Triage Terminal Transcript

Recording date context: 2026-05-17.

Preferred Windows commands:

```powershell
py -m bofa.agent.demo.oauth_app_triage
py examples/sotyhub_consumer.py bofa/agent/demo/output/report.json
py -m unittest discover -s tests
```

This environment did not have the `py` launcher on `PATH`, so validation used the bundled Python interpreter:

```powershell
PS C:\path\to\BOFA> & 'C:\path\to\python.exe' -m bofa.agent.demo.oauth_app_triage
BOFA OAuth triage demo complete
evidence: C:\path\to\BOFA\bofa\agent\demo\output\evidence.jsonl
report_json: C:\path\to\BOFA\bofa\agent\demo\output\report.json
report_markdown: C:\path\to\BOFA\bofa\agent\demo\output\report.md

PS C:\path\to\BOFA> & 'C:\path\to\python.exe' examples\sotyhub_consumer.py bofa\agent\demo\output\report.json
{
  "blocked_tools_count": 1,
  "dedupe_key": "bofa-agent-oauth-triage-v1:synthetic-app-001",
  "findings_count": 4,
  "risk_score": 80,
  "severity": "high",
  "subject": {
    "application_id": "synthetic-app-001",
    "display_name": "Contoso Docs Sync Preview",
    "publisher": "Unknown Publisher"
  },
  "type": "passive_oauth_triage_report"
}

PS C:\path\to\BOFA> & 'C:\path\to\python.exe' -m unittest discover -s tests
...
----------------------------------------------------------------------
Ran 3 tests in 0.015s

OK
```

Evidence highlight:

```json
{"data": {"reason": "tool is explicitly blocked", "tool": "fetch_live_tenant_users"}, "event_id": 6, "event_type": "tool.blocked", "timestamp": "2026-05-16T21:30:00Z"}
```
