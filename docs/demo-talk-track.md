# DetFuzz Demo Talk Track

## One-Minute Version

DetFuzz is a blue-team detection resilience lab. It safely runs harmless
PowerShell command-line variants in a Windows VM, validates that the intended
marker effect happened, correlates the process with Sysmon telemetry, evaluates
the detection rule dependency, and classifies the result.

The important point is that DetFuzz does not call something a bypass just
because a rule missed. A candidate must still complete the marker oracle, have
valid telemetry, and be bracketed by working baseline detections.

## Demo Story

1. Confirm Sysmon is running.
2. Run clock preflight so timing-based telemetry correlation is trustworthy.
3. Run timeout calibration to choose stable lab timeouts.
4. Run the full v0 sequence: `B0, M1-M5, NC1, B1`.
5. Open the Markdown report and evidence manifest.
6. Explain why `M1` is classified as `VALID_BYPASS`.

## Validated Result

```text
B0 DETECTED
M1 VALID_BYPASS
M2 DETECTED
M3 DETECTED
M4 DETECTED
M5 DETECTED
NC1 INVALID_MUTANT
B1 DETECTED
```

## What Makes It Different

- It separates execution truth from detection truth.
- It uses a marker oracle instead of assuming a process launch means success.
- It requires Sysmon Event ID 1 telemetry before classification.
- It uses opening and closing controls to avoid stale or broken-detector claims.
- It archives evidence with hashes for repeatable review.

## Current Boundaries

- v0 is intentionally scoped to a single encoded PowerShell rule shape.
- Payloads are harmless marker writers.
- pySigma is declared as a dependency; the local bundled runner skips the
  installed-pySigma test if the package is absent.
- The Windows VM lab is required for real telemetry validation.
