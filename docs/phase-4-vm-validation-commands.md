# Phase 4 VM Validation Commands

Run this after Phase 3 has produced a PID and UTC start/end window.

Inside the Windows 11 VM, from the DetFuzz project directory:

```powershell
$env:PYTHONPATH='src'
python -m detfuzz.cli validate-telemetry `
  --host DetFuzz-Win11-Lab `
  --pid <PID_FROM_PHASE_3> `
  --started <STARTED_UTC_FROM_PHASE_3> `
  --ended <ENDED_UTC_FROM_PHASE_3>
```

Expected result:

```json
{
  "event": {
    "event_id": 1,
    "provider": "Microsoft-Windows-Sysmon"
  },
  "missing_fields": [],
  "reason": "TELEMETRY_COMPLETE",
  "valid": true
}
```

If validation fails, export the latest matching XML using the Phase 3 commands
and compare `Computer`, `ProcessId`, `Image`, `CommandLine`, `Hashes`, and the
UTC event time.
