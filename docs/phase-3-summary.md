# Phase 3 Summary

Phase 3 adds the marker oracle and initial Sysmon Event ID 1 telemetry
validation.

## Implemented

- Exact marker path validation.
- Marker JSON parsing.
- Suite ID, case ID, nonce, and `completed` result validation.
- Negative-control marker absence validation.
- Optional marker timestamp check against execution start/end time.
- Sysmon XML parsing from exported `Get-WinEvent ... ToXml()` output.
- Sysmon provider and Event ID validation.
- Required field validation for:
  - `UtcTime`
  - `ProcessGuid`
  - `ProcessId`
  - `Image`
  - `CommandLine`
  - `ParentImage`
  - `Hashes`
- Initial correlation by PID, image suffix, and command-line fragment.

## Status

```text
Phase 3 code complete
Phase 3 unit tests complete
Phase 3 VM validation complete
```

## VM Validation Result

Validated on 2026-07-20 against the Windows 11 Enterprise Evaluation VM.

Confirmed:

- B0 marker content matched suite ID, case ID, nonce, and `completed` result.
- Matching Sysmon Event ID 1 was found by XML field correlation.
- `ProcessId` matched the captured process PID.
- `Image` ended with `powershell.exe`.
- `CommandLine` contained `EncodedCommand`.
- Required fields were present:
  - `UtcTime`
  - `ProcessGuid`
  - `ProcessId`
  - `Image`
  - `CommandLine`
  - `ParentImage`
  - `Hashes`

Phase 4 can now build the automated Windows telemetry adapter around this
validated XML-field matching approach.
