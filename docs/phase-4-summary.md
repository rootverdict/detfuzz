# Phase 4 Summary

Phase 4 adds the Windows telemetry adapter around the Phase 3 Sysmon XML
validation logic.

## Implemented

- Sysmon Event ID 1 query command generation through PowerShell.
- Parsing multiple `Get-WinEvent ... ToXml()` results.
- Correlation criteria model with:
  - host
  - PID
  - UTC start time
  - UTC end time
  - image suffix
  - command-line fragment
  - required hash algorithm
- Correlation by:
  - Sysmon provider
  - Event ID 1
  - `Computer`
  - `ProcessId`
  - `Image`
  - `CommandLine`
  - `Hashes`
  - bounded UTC execution window
- Required-field validation reused from Phase 3.
- `validate-telemetry` CLI command.
- Unit tests with a fake PowerShell command runner.

## Status

```text
Phase 4 code complete
Phase 4 unit tests complete
Phase 4 VM validation complete
```

## Example CLI

```powershell
python -m detfuzz.cli validate-telemetry `
  --host DetFuzz-Win11-Lab `
  --pid 3356 `
  --started 2026-07-20T18:16:03.7596721Z `
  --ended 2026-07-20T18:16:07.9442731Z
```

## VM Validation Result

Validated on 2026-07-20 against the Windows 11 Enterprise Evaluation VM.

Result:

```text
valid: true
reason: TELEMETRY_COMPLETE
provider: Microsoft-Windows-Sysmon
event_id: 1
computer: DetFuzz-Win11-Lab
record_id: 491
ProcessId: 3356
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe ... -EncodedCommand ...
Hashes: includes SHA256
missing_fields: none
```
