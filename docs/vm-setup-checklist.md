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

## Phase 2 Validation Target

Run one prepared baseline command and confirm:

- The marker file is created at the exact expected path.
- The marker JSON contains the expected suite ID, case ID, nonce, and result.
- The command exits with code 0.

Sysmon Event ID 1 validation belongs to the next phase.
