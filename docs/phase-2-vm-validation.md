# Phase 2 VM Validation

Validation date: 2026-07-20

Lab:

- Windows 11 Enterprise Evaluation VM
- Sysmon64 installed and running
- Sysmon Operational log readable

## B0 Positive Control

Result:

```text
B0 marker path:
C:\DetFuzz\runs\c6947327-9ae1-43ef-89db-10e52b8d49cb\B0\effect.json

B0 marker content:
{"run_id":"c6947327-9ae1-43ef-89db-10e52b8d49cb","case_id":"B0","nonce":"6ed3d56d3b7d4fcf9cc8b91ffd942f45","result":"completed"}
```

Interpretation:

- Marker file was created at the exact expected path.
- `run_id` matched the suite ID.
- `case_id` was `B0`.
- `nonce` was present.
- `result` was `completed`.

## Sysmon Check

Result:

```text
Latest Sysmon PowerShell Process Create events:
7/20/2026 11:38:47 PM  Id 1  Microsoft-Windows-Sysmon  Process Create:...
7/20/2026 11:38:42 PM  Id 1  Microsoft-Windows-Sysmon  Process Create:...
```

Interpretation:

- Sysmon Event ID 1 captured PowerShell process creation events.
- Detailed field-level correlation is deferred to Phase 3.

## NC1 Negative Control

Result:

```text
Cannot process the command because the value specified with -EncodedCommand is not properly encoded.

NC1 marker should NOT exist:
False
```

Interpretation:

- The invalid Base64 command failed as intended.
- The NC1 marker file was not created.

## Phase 2 Status

```text
Phase 2 code complete
Phase 2 VM validation complete
Phase 3 next: marker oracle and Sysmon field-level correlation
```
