# DetFuzz V1 Demo Talk Track

## One-minute version

DetFuzz is a blue-team detection-resilience lab. It executes allow-listed,
harmless PowerShell command-line variants, verifies the intended marker effect,
correlates the process with Sysmon Event ID 1, evaluates the packaged detection
rule, and writes evidence-backed reports.

DetFuzz does not call a missed alert a bypass by itself. The fixture must execute
successfully, pass exact marker validation, have complete telemetry and matching
executable identity, and be bracketed by working opening and closing controls.

V1 also runs benign fixtures to expose false positives and exports a versioned
JSON Schema so another project can consume the report without sharing DetFuzz
internals.

## Demo sequence

1. Confirm Sysmon is running and Process Create events are visible.
2. Run clock preflight.
3. Calibrate process and telemetry timeouts.
4. Run `B0, M1-M5, NC1, B1`.
5. Run benign fixtures `BF0-BF2`.
6. Export the suite-report JSON Schema.
7. Review the reports and evidence manifests.
8. Explain `M1` as a valid bypass and `BF1/BF2` as benign alerts.

## Validated result

```text
B0 DETECTED
M1 VALID_BYPASS
M2 DETECTED
M3 DETECTED
M4 DETECTED
M5 DETECTED
NC1 INVALID_MUTANT
B1 DETECTED

BF0 BENIGN_NO_ALERT
BF1 BENIGN_ALERT
BF2 BENIGN_ALERT
```

## Why the result is defensible

- Execution truth and detection truth are evaluated separately.
- The marker oracle proves the harmless effect happened.
- Sysmon correlation is required before classification.
- Executable SHA256 identity is checked.
- Opening and closing controls guard against a broken detector.
- Evidence files are hashed for later review.
- Benign alerts are kept separate from bypass findings.

## Boundaries

V1 covers one encoded-command PowerShell rule shape and one Windows Sysmon
telemetry path. It does not claim broad detector coverage, production SIEM
integration, malicious payload testing, or downstream SignalBudget execution.
