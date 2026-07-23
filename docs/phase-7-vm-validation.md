# Phase 7 VM Validation

Validation status: complete

Validation date: 2026-07-21

Lab:

- Windows 11 Enterprise Evaluation VM
- Computer name: `DetFuzz-Win11-Lab`
- Sysmon64 installed and running
- DetFuzz Phase 7 code copied into `C:\DetFuzz\detfuzz`

## Command

```powershell
cd C:\DetFuzz\detfuzz
$env:PYTHONPATH='src'
python -m detfuzz.cli run-benign-fixtures `
  --output-root C:\DetFuzz\benign `
  --host DetFuzz-Win11-Lab `
  --max-events 5000
```

## Observed Result

```text
suite_id: 1a545575-f640-45b2-91de-fc0bf1ed419c
suite_status: COMPLETED
BF0: BENIGN_NO_ALERT
BF1: BENIGN_ALERT
BF2: BENIGN_ALERT
```

The observed result matched the pre-validation prediction.

## Case Summary

| Fixture | Classification | Telemetry | Detection | Prediction |
|---|---|---|---|---|
| BF0 | BENIGN_NO_ALERT | TELEMETRY_COMPLETE | RULE_NOT_MATCHED | met |
| BF1 | BENIGN_ALERT | TELEMETRY_COMPLETE | RULE_MATCHED | met |
| BF2 | BENIGN_ALERT | TELEMETRY_COMPLETE | RULE_MATCHED | met |

## Report Summary

```text
BENIGN_ALERT: 2
BENIGN_NO_ALERT: 1
```

## Required Raw Artifacts

```text
C:\DetFuzz\benign\1a545575-f640-45b2-91de-fc0bf1ed419c\benign-results.json
C:\DetFuzz\benign\1a545575-f640-45b2-91de-fc0bf1ed419c\reports\evidence-manifest.json
C:\DetFuzz\benign\1a545575-f640-45b2-91de-fc0bf1ed419c\reports\suite-report.json
C:\DetFuzz\benign\1a545575-f640-45b2-91de-fc0bf1ed419c\reports\suite-report.md
```

## Evidence Manifest Highlights

The evidence manifest contains per-fixture records for:

```text
BF0/detection-result.json
BF0/execution.json
BF0/fixture-record.json
BF0/telemetry-validation.json
BF1/detection-result.json
BF1/execution.json
BF1/fixture-record.json
BF1/telemetry-validation.json
BF2/detection-result.json
BF2/execution.json
BF2/fixture-record.json
BF2/telemetry-validation.json
```

## Interpretation

`BENIGN_ALERT` does not mean the benign command is malicious. It means the v0
rule matched harmless encoded PowerShell activity. This is useful evidence that
the v0 rule is broad: it detects encoded PowerShell, but does not distinguish
benign encoded administrative activity from the v0 marker behavior.
