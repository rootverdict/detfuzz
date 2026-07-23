# Phase 3 VM Validation

Validation date: 2026-07-20

Lab:

- Windows 11 Enterprise Evaluation VM
- Computer name: `DetFuzz-Win11-Lab`
- Sysmon64 installed and running
- Sysmon Operational log readable

## B0 Execution

```text
suite_id: 2b2671ab-4e3a-460d-83ab-31eec2f426db
case_id: B0
nonce: adb7d396faad418196bc3d133cc3bac9
marker_path: C:\DetFuzz\runs\2b2671ab-4e3a-460d-83ab-31eec2f426db\B0\effect.json
pid: 3356
exit_code: 0
started: 2026-07-20T18:16:03.7596721Z
ended: 2026-07-20T18:16:07.9442731Z
```

Marker content:

```json
{"run_id":"2b2671ab-4e3a-460d-83ab-31eec2f426db","case_id":"B0","nonce":"adb7d396faad418196bc3d133cc3bac9","result":"completed"}
```

## Sysmon Correlation

Matching Sysmon event:

```text
Provider: Microsoft-Windows-Sysmon
EventID: 1
Computer: DetFuzz-Win11-Lab
ProcessId: 3356
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe ... -EncodedCommand ...
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Hashes: MD5=...,SHA256=0FF6F2C94BC7E2833A5F7E16DE1622E5DBA70396F31C7D5F56381870317E8C46,IMPHASH=...
```

Required fields confirmed:

```text
UtcTime
ProcessGuid
ProcessId
Image
CommandLine
ParentImage
Hashes
```

## Phase 3 Status

```text
Phase 3 code complete
Phase 3 unit tests complete
Phase 3 VM validation complete
Next: Phase 4 Windows telemetry adapter
```
