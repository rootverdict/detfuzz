# DetFuzz Demo Talk Track

## One-Minute Version

DetFuzz is a blue-team detection resilience lab. It safely runs harmless
PowerShell command-line variants in a Windows VM, validates that the intended
marker effect happened, correlates the process with Sysmon telemetry, evaluates
the detection rule dependency, and classifies the result.

The important point is that DetFuzz does not call something a bypass just
because a rule missed. A candidate must still complete the marker oracle, have
valid telemetry, and be bracketed by working baseline detections.

For V1, DetFuzz also runs benign encoded PowerShell fixtures and exports a
versioned JSON Schema so SignalBudget can consume the generated suite report as
stable input.

## Demo Story

1. Confirm Sysmon is running.
2. Run clock preflight so timing-based telemetry correlation is trustworthy.
3. Run timeout calibration to choose stable lab timeouts.
4. Run the full v0 sequence: `B0, M1-M5, NC1, B1`.
5. Run the v0.1 benign fixture sequence: `BF0-BF2`.
6. Export the DetFuzz suite-report JSON Schema.
7. Open the Markdown reports and evidence manifests.
8. Explain why `M1` is classified as `VALID_BYPASS` and why `BF1/BF2` are
   benign alerts, not bypasses.

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

Benign fixture result:

```text
BF0 BENIGN_NO_ALERT
BF1 BENIGN_ALERT
BF2 BENIGN_ALERT
```

## What Makes It Different

- It separates execution truth from detection truth.
- It uses a marker oracle instead of assuming a process launch means success.
- It requires Sysmon Event ID 1 telemetry before classification.
- It uses opening and closing controls to avoid stale or broken-detector claims.
- It archives evidence with hashes for repeatable review.
- It separates bypass evidence from benign false-positive evidence.
- It exports a stable JSON contract for SignalBudget instead of coupling the two
  projects directly.

## Current Boundaries

- V1 is intentionally scoped to a single encoded PowerShell rule shape plus the
  v0.1 benign fixture lens.
- Payloads are harmless marker writers.
- pySigma is declared as a dependency; the local bundled runner skips the
  installed-pySigma test if the package is absent.
- The Windows VM lab is required for real telemetry validation.
- SignalBudget consumption is outside DetFuzz V1; DetFuzz only exports the
  report and schema.
