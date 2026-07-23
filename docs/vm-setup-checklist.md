# Windows VM Setup Checklist

Use this checklist while preparing the DetFuzz lab VM.

## Recommended VM

- Windows 11 Enterprise Evaluation, 64-bit
- 2 CPU cores
- 4-8 GB RAM
- 60 GB disk
- NAT networking

## Snapshots

1. Clean Windows installed.
2. Sysmon installed and Event ID 1 visible.
3. DetFuzz baseline marker payload verified.
4. Full v0 suite and v0.1 benign fixture validation complete.

## Phase 2 Validation Target

Run one prepared baseline command and confirm:

- The marker file is created at the exact expected path.
- The marker JSON contains the expected suite ID, case ID, nonce, and result.
- The command exits with code 0.

## V1 Validation Target

Before using the VM for a V1 demo, confirm:

- `clock-preflight` returns `PASS`.
- `calibrate-timeouts` returns `PASS`.
- `run-suite` writes a complete v0 report under `C:\DetFuzz\runs\<suite-id>`.
- `run-benign-fixtures` writes a complete v0.1 report under
  `C:\DetFuzz\benign\<suite-id>`.
- Raw reports and evidence manifests are retained outside the source archive.
