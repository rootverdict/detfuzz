# DetFuzz V1 Demo Runbook

This runbook demonstrates the DetFuzz V1 story in the Windows 11 lab VM:

- Run the full v0 encoded-command resilience suite.
- Run the v0.1 benign false-positive fixtures.
- Export the JSON Schema contract that downstream consumers such as
  SignalBudget can validate against.

## Lab Assumptions

- Windows 11 Enterprise Evaluation VM is running.
- VM computer name is `DetFuzz-Win11-Lab`.
- Sysmon64 is installed and running.
- DetFuzz source is copied to `C:\DetFuzz\detfuzz`.
- Commands are run in Administrator PowerShell.

## 1. Confirm Sysmon

```powershell
Get-Service Sysmon64
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 5
```

Expected result:

```text
Sysmon64 is Running
Recent Event ID 1 process creation events are visible
```

## 2. Clock Preflight

```powershell
cd C:\DetFuzz\detfuzz
$env:PYTHONPATH='src'
python -m detfuzz.cli clock-preflight
```

Expected result:

```text
status: PASS
reason: CLOCK_SYNC_OK
```

If the status is `PREFLIGHT_FAILED`, resync the VM clock and rerun:

```powershell
w32tm /resync /force
python -m detfuzz.cli clock-preflight
```

## 3. Timeout Calibration

```powershell
python -m detfuzz.cli calibrate-timeouts `
  --output-root C:\DetFuzz\calibration `
  --host DetFuzz-Win11-Lab `
  --runs 20 `
  --max-events 5000
```

Validated result from the lab:

```text
status: PASS
runs_completed: 20
selected process timeout: 30s
selected telemetry timeout: 30s
selected telemetry query timeout: 73s
```

## 4. Run Full v0 Suite

```powershell
python -m detfuzz.cli run-suite `
  --output-root C:\DetFuzz\runs `
  --host DetFuzz-Win11-Lab `
  --max-events 5000 `
  --calibration-result C:\DetFuzz\calibration\<suite-id>\timeout-calibration.json
```

Replace `<suite-id>` with the calibration folder created in step 3. This keeps
the suite run aligned with the calibrated telemetry-query timeout instead of
falling back to the default.

Validated DetFuzz v0 result:

```text
B0: DETECTED
M1: VALID_BYPASS
M2: DETECTED
M3: DETECTED
M4: DETECTED
M5: DETECTED
NC1: INVALID_MUTANT
B1: DETECTED
```

## 5. Show Evidence

Open the created suite folder:

```powershell
Get-ChildItem C:\DetFuzz\runs
```

Then inspect:

```text
C:\DetFuzz\runs\<suite-id>\suite-results.json
C:\DetFuzz\runs\<suite-id>\reports\suite-report.md
C:\DetFuzz\runs\<suite-id>\reports\suite-report.json
C:\DetFuzz\runs\<suite-id>\reports\evidence-manifest.json
```

## 6. Run Benign Fixtures

```powershell
python -m detfuzz.cli run-benign-fixtures `
  --output-root C:\DetFuzz\benign `
  --host DetFuzz-Win11-Lab `
  --max-events 5000
```

Validated DetFuzz v0.1 benign result:

```text
BF0: BENIGN_NO_ALERT
BF1: BENIGN_ALERT
BF2: BENIGN_ALERT
```

Inspect:

```text
C:\DetFuzz\benign\<suite-id>\benign-results.json
C:\DetFuzz\benign\<suite-id>\reports\suite-report.md
C:\DetFuzz\benign\<suite-id>\reports\suite-report.json
C:\DetFuzz\benign\<suite-id>\reports\evidence-manifest.json
```

## 7. Export the SignalBudget Contract

```powershell
python -m detfuzz.cli export-contract `
  --output C:\DetFuzz\detfuzz\artifacts\detfuzz-suite-report-1.0.schema.json
```

Expected result:

```text
schema: C:\DetFuzz\detfuzz\artifacts\detfuzz-suite-report-1.0.schema.json
```

This schema is the V1 handoff contract. DetFuzz owns producing the report and
schema; SignalBudget owns consuming them.

## 8. Explain the Finding

The key v0 finding is that the brittle demo rule matched standard
`-EncodedCommand`, but the alias mutation `-enc` produced the same harmless
marker effect without matching that exact command-line dependency.

That makes `M1` a valid bypass for the intentionally narrow v0 rule, while the
closing positive control `B1` proves the detector was still working at the end.

The benign fixture result adds the false-positive lens: the same v0 rule also
alerts on harmless encoded administrative activity, so V1 can discuss both
resilience and specificity without claiming the benign commands are malicious.

## Optional Guided Demo Helper

From the project root:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\demo\detfuzz-demo.ps1 -RunSuite
```

For a faster rerun after calibration has already been captured:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\demo\detfuzz-demo.ps1 -SkipCalibration -RunSuite
```
