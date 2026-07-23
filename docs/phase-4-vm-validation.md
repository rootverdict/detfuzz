# Phase 4 VM Validation

Validation date: 2026-07-20

Lab:

- Windows 11 Enterprise Evaluation VM
- Computer name: `DetFuzz-Win11-Lab`
- Sysmon64 installed and running
- DetFuzz Phase 4 code copied into `C:\DetFuzz\detfuzz`

Command:

```powershell
python -m detfuzz.cli validate-telemetry `
  --host DetFuzz-Win11-Lab `
  --pid 3356 `
  --started 2026-07-20T18:16:03.7596721Z `
  --ended 2026-07-20T18:16:07.9442731Z `
  --max-events 5000
```

Result:

```json
{
  "missing_fields": [],
  "reason": "TELEMETRY_COMPLETE",
  "valid": true
}
```

Matched event:

```text
Provider: Microsoft-Windows-Sysmon
EventID: 1
Computer: DetFuzz-Win11-Lab
RecordId: 491
ProcessId: 3356
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe ... -EncodedCommand ...
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Hashes: MD5=...,SHA256=0FF6F2C94BC7E2833A5F7E16DE1622E5DBA70396F31C7D5F56381870317E8C46,IMPHASH=...
UtcTime: 2026-07-20 18:16:03.873
```

Note:

The first run with the default `--max-events 200` did not find the older Phase 3
event. Re-running with `--max-events 5000` found and validated the matching
event. Future runner automation should query with a bounded time filter instead
of relying only on recent event count.
