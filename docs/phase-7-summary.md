# Phase 7 Summary

Phase 7 implements the first DetFuzz v0.1 controlled expansion:

```text
Benign activity fixtures
```

The goal is to measure whether the current v0 EncodedCommand rule also alerts
on harmless benign PowerShell usage. This is a false-positive lens, not a bypass
claim.

## Implemented

- v0.1 benign fixture inventory:
  - `BF0`: plain PowerShell version check.
  - `BF1`: encoded `Get-Date` benign command.
  - `BF2`: encoded service-listing benign command.
- Safe allow-listed command generation.
- `prepare-benign-fixtures` CLI command.
- `run-benign-fixtures` CLI command.
- Sysmon Process Create telemetry correlation for each fixture.
- Detection evaluation using the v0 rule dependency model.
- Fixture classifications:
  - `BENIGN_NO_ALERT`
  - `BENIGN_ALERT`
  - `BENIGN_EXECUTION_FAILED`
  - `BENIGN_EXECUTION_TIMEOUT`
  - `BENIGN_TELEMETRY_FAILURE`
  - `BENIGN_DETECTION_NOT_EVALUATED`
- Evidence archive and Markdown/JSON report output.
- Unit tests for command generation and fixture result classification.

## Predicted v0.1 Result Before VM Validation

The v0 rule intentionally depends on:

```text
Image endswith \powershell.exe
CommandLine contains -EncodedCommand
```

Predicted fixture outcomes:

```text
BF0 plain command: BENIGN_NO_ALERT
BF1 encoded benign command: BENIGN_ALERT
BF2 encoded benign command: BENIGN_ALERT
```

If the VM run matches this prediction, that result means the v0 rule is useful
for demonstrating encoded PowerShell coverage, but not specific enough to
distinguish malicious encoded behavior from harmless encoded administrative
activity.

If the VM result differs, keep the observed result and explain the difference.
Do not edit the prediction to make it look like it was known in advance.

## Observed VM Result

Phase 7 was run in the Windows 11 Sysmon lab:

```text
suite_id: 1a545575-f640-45b2-91de-fc0bf1ed419c
suite_status: COMPLETED
BF0: BENIGN_NO_ALERT
BF1: BENIGN_ALERT
BF2: BENIGN_ALERT
```

All three fixtures had complete Sysmon telemetry. The observed result matched
the pre-validation prediction.

## Boundary

Phase 7 does not add parent-process mutation yet. Parent mutation changes
telemetry semantics and should be characterized separately.

The source zip does not prove Phase 7 VM validation. See
`docs/phase-7-evidence-boundary.md`.

## Status

```text
Phase 7 code complete
Phase 7 unit tests complete
Phase 7 VM validation complete
Predicted results documented separately from observed results
```
