# Phase 6 Evidence Boundary

This note exists to keep the project claims honest and reviewable.

## What the Source Zip Proves

The DetFuzz source package proves:

- The runner code exists.
- The telemetry parser exists.
- The Sysmon query adapter exists.
- The detection evaluator exists.
- The classifier/reporting path exists.
- The local unit tests pass.

The source zip alone does not prove that a Windows VM run happened.

## What the VM Evidence Proves

The real VM proof is the raw run output and artifacts created under the Windows
lab paths:

```text
C:\DetFuzz\runs\<suite-id>\suite-results.json
C:\DetFuzz\runs\<suite-id>\reports\evidence-manifest.json
C:\DetFuzz\runs\<suite-id>\reports\suite-report.json
C:\DetFuzz\runs\<suite-id>\reports\suite-report.md
C:\DetFuzz\calibration\<suite-id>\timeout-calibration.json
```

Those files should be preserved alongside the portfolio release, even if they
are not committed to source control.

## Recorded VM Run

The documented v0 result is based on pasted PowerShell output from the Windows
11 Sysmon lab, not on an invented expected result:

```text
suite_id: 49125a2a-6606-4a2e-8c99-5bda29857f6b
suite_status: COMPLETED
B0: DETECTED
M1: VALID_BYPASS
M2: DETECTED
M3: DETECTED
M4: DETECTED
M5: DETECTED
NC1: INVALID_MUTANT
B1: DETECTED
```

Reviewers should still ask for the raw suite artifacts above if they want to
verify the claim independently.

## Claim Language

Use this wording:

```text
The v0 suite was run in the Windows VM and produced the recorded result. Raw
evidence artifacts are stored under C:\DetFuzz\runs\<suite-id> and should be
kept with the portfolio evidence package.
```

Avoid this wording:

```text
The source zip itself proves the VM result.
```
