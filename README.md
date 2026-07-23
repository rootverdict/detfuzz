# DetFuzz

DetFuzz is a small detection resilience experiment runner. Its first version
tests whether a Sigma/SIEM detection for PowerShell encoded commands still
matches when the same harmless behavior is expressed through valid command-line
variations.

## v0 Goal

The first milestone is intentionally narrow:

- Opening positive control: standard `-EncodedCommand`
- Five valid syntactic mutations
- Invalid negative control with corrupted Base64
- Closing positive control
- Deterministic classification
- Machine-readable JSON output
- Human-readable report

## Current Status

This repository currently contains the local core:

- v0 case inventory
- result data model
- classification logic
- CLI demo using simulated case observations
- Phase 2 runner preparation for safe PowerShell marker payloads
- allow-listed v0 command generation
- Phase 3 marker oracle
- Phase 3 Sysmon Event ID 1 XML parsing and required-field validation
- Phase 5 v0 detection rule dependencies and event evaluation
- Phase 6 evidence manifest and report generation
- blueprint Phase 6 documentation and demo materials
- Phase 7 v0.1 benign fixture runner
- unit tests for the classifier

Phase 2, Phase 3, Phase 4, Phase 5, timeout calibration, and clock preflight
VM validation are complete.
Simulated classifier output is still fake and must not be presented as a real
DetFuzz report.

The full v0 suite runner has also been run in the VM according to the pasted
lab output:

```text
B0 DETECTED
M1 VALID_BYPASS
M2-M5 DETECTED
NC1 INVALID_MUTANT
B1 DETECTED
```

Important evidence boundary: the source zip does not independently prove the VM
run. Keep the raw files from `C:\DetFuzz\runs\<suite-id>` and
`C:\DetFuzz\calibration\<suite-id>` with the portfolio evidence package. See
`docs/phase-6-evidence-boundary.md`.

Blueprint Phase 6 adds the portfolio/demo layer:

- `docs/demo-runbook.md`
- `docs/demo-talk-track.md`
- `docs/evidence-checklist.md`
- `demo/detfuzz-demo.ps1`

## Run Locally

```powershell
$env:PYTHONPATH='src'
python -m unittest discover -s tests
python -m detfuzz.cli simulate-report
python -m detfuzz.cli prepare-suite --root artifacts/runs
python -m detfuzz.cli validate-telemetry --host DetFuzz-Win11-Lab --pid 3356 --started 2026-07-20T18:16:03.7596721Z --ended 2026-07-20T18:16:07.9442731Z
python -m detfuzz.cli evaluate-detection --xml artifacts/sample-sysmon-event.xml
python -m detfuzz.cli build-report --suite-results artifacts/suite-results.json --evidence-root artifacts/evidence --output-dir artifacts/reports
python -m detfuzz.cli clock-preflight
python -m detfuzz.cli calibrate-timeouts --output-root C:\DetFuzz\calibration --host DetFuzz-Win11-Lab --runs 20
python -m detfuzz.cli run-suite --output-root C:\DetFuzz\runs --host DetFuzz-Win11-Lab --calibration-result C:\DetFuzz\calibration\<suite-id>\timeout-calibration.json
python -m detfuzz.cli prepare-benign-fixtures --root C:\DetFuzz\benign
python -m detfuzz.cli run-benign-fixtures --output-root C:\DetFuzz\benign --host DetFuzz-Win11-Lab
```

For release verification with pySigma installed:

```powershell
python -m pip install -e .
python -m unittest discover -s tests
```

Expected installed-dependency result:

```text
Ran 60 tests
OK (skipped=1)
```

One local-only negative test is skipped when pySigma is installed because it
only verifies the missing-pySigma error path.

## Demo

Inside the VM:

```powershell
cd C:\DetFuzz\detfuzz
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\demo\detfuzz-demo.ps1 -RunSuite
```

For a faster check that skips calibration:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\demo\detfuzz-demo.ps1 -SkipCalibration -RunSuite
```

## v0.1 Benign Fixtures

Phase 7 adds benign false-positive fixtures:

```text
BF0 plain PowerShell command
BF1 benign encoded Get-Date
BF2 benign encoded service listing
```

These are not bypass candidates. They measure whether the current v0 rule also
matches harmless encoded PowerShell activity.

Validated Phase 7 VM result:

```text
BF0 BENIGN_NO_ALERT
BF1 BENIGN_ALERT
BF2 BENIGN_ALERT
```

## Safety

DetFuzz v0 must only execute harmless marker-producing PowerShell payloads in an
isolated lab you own or are explicitly authorized to test.
