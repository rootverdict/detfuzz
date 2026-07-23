# Phase 5 VM Validation

Validation date: 2026-07-21

Lab:

- Windows 11 Enterprise Evaluation VM
- Computer name: `DetFuzz-Win11-Lab`
- Sysmon64 installed and running
- DetFuzz Phase 5 code copied into `C:\DetFuzz\detfuzz`

## Input Event

The B0 Sysmon Event ID 1 XML was saved to:

```text
C:\DetFuzz\b0-sysmon-event.xml
```

## Command

```powershell
cd C:\DetFuzz\detfuzz
$env:PYTHONPATH='src'
python -m detfuzz.cli evaluate-detection --xml C:\DetFuzz\b0-sysmon-event.xml
```

## Result

```json
{
  "dependency_results": {
    "CommandLine|contains|-EncodedCommand": true,
    "Image|endswith|\\powershell.exe": true
  },
  "matched": true,
  "reason": "RULE_MATCHED",
  "rule_id": "d4f8c4e4-984d-4f5f-9f6c-1cc6b37f2f62"
}
```

## Interpretation

- The real B0 Sysmon event matched the v0 rule.
- `Image` satisfied `endswith \powershell.exe`.
- `CommandLine` satisfied `contains -EncodedCommand`.
- The adapter produced dependency-level evidence instead of a bare yes/no.

## Boundary

The rule ID is a UUID so pySigma can parse it. The current bundled Python
environment does not have pySigma installed; environments that install
`pysigma>=0.11.0` run the real-rule pySigma test with fallback disabled.
