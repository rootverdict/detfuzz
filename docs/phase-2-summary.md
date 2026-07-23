# Phase 2 Summary

Phase 2 adds the harmless PowerShell runner preparation layer.

## Implemented

- Fresh suite UUID generation.
- Suite-isolated case directories.
- Per-case nonce generation.
- Exact marker path construction.
- Harmless marker-writing PowerShell payload generation.
- UTF-16LE Base64 encoding for `-EncodedCommand`.
- Allow-listed command generation for `B0`, `M1-M5`, `NC1`, and `B1`.
- Negative control command with deliberately invalid Base64.
- Optional process execution helper that captures PID, timestamps, exit code,
  stdout, stderr, and timeout state.
- `prepare-suite` CLI command that clearly labels output as not executed.

## VM Validation

Phase 2 VM validation was completed on 2026-07-20 using the Windows 11
Enterprise Evaluation lab VM with Sysmon installed.

Validated:

```text
B0 command exits with code 0
B0 marker file exists
B0 marker JSON contains suite ID, case ID, nonce, and completed result
NC1 exits non-zero
NC1 marker file does not exist
Sysmon Event ID 1 records powershell.exe Process Create events
```

Full Sysmon field correlation begins in Phase 3.
