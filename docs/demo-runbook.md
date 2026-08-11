# DetFuzz V1 Demo Runbook

This runbook demonstrates the complete V1 workflow in an authorized Windows
lab: preflight, calibration, detection-resilience cases, benign fixtures,
evidence review, and contract export.

## Lab assumptions

- Windows 10 or Windows 11 test host.
- Administrator PowerShell.
- Python 3.11 or newer with DetFuzz installed.
- Sysmon64 running with [`../configs/sysmon-detfuzz.xml`](../configs/sysmon-detfuzz.xml).
- Commands are run from the DetFuzz project root.

Set the source import path and use the actual computer name recorded by Sysmon:

```powershell
$env:PYTHONPATH = "$PWD\src"
$hostName = $env:COMPUTERNAME
```

## 1. Confirm Sysmon

```powershell
Get-Service Sysmon64
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 5
```

The service must be `Running`, and recent Process Create events must be visible.

## 2. Run clock preflight

```powershell
python -m detfuzz.cli clock-preflight
```

Continue only when the JSON result reports `status: PASS`. If it fails, correct
Windows time synchronization and rerun the command.

## 3. Calibrate timeouts

```powershell
python -m detfuzz.cli calibrate-timeouts `
  --output-root C:\DetFuzz\calibration `
  --host $hostName `
  --runs 20 `
  --telemetry-probe-timeout-seconds 120 `
  --max-events 5000
```

Capture the emitted `output_path`, or select the latest calibration result:

```powershell
$calibration = Get-ChildItem C:\DetFuzz\calibration -Directory |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 1
$calibrationResult = Join-Path $calibration.FullName 'timeout-calibration.json'
```

Continue only when calibration reports `status: PASS`.

## 4. Run the detection suite

```powershell
python -m detfuzz.cli run-suite `
  --output-root C:\DetFuzz\runs `
  --host $hostName `
  --max-events 5000 `
  --calibration-result $calibrationResult
```

The validated V1 classification pattern is:

```text
B0  DETECTED
M1  VALID_BYPASS
M2  DETECTED
M3  DETECTED
M4  DETECTED
M5  DETECTED
NC1 INVALID_MUTANT
B1  DETECTED
```

The command exits nonzero unless the suite status is `COMPLETED`.

## 5. Run benign fixtures

```powershell
python -m detfuzz.cli run-benign-fixtures `
  --output-root C:\DetFuzz\benign `
  --host $hostName `
  --max-events 5000
```

The validated benign pattern is:

```text
BF0 BENIGN_NO_ALERT
BF1 BENIGN_ALERT
BF2 BENIGN_ALERT
```

`BENIGN_ALERT` means the intentionally simple V1 rule matched harmless encoded
administrative activity. It is a false-positive observation, not a malicious
classification.

## 6. Export the report contract

```powershell
python -m detfuzz.cli export-contract `
  --output C:\DetFuzz\contracts\detfuzz-suite-report-1.0.schema.json
```

The exported schema is the stable handoff contract for downstream consumers.

## 7. Review evidence

Inspect the newest suite and benign directories. Each must contain raw results,
JSON and Markdown reports, and an evidence manifest:

```text
C:\DetFuzz\runs\<suite-id>\suite-results.json
C:\DetFuzz\runs\<suite-id>\reports\suite-report.json
C:\DetFuzz\runs\<suite-id>\reports\suite-report.md
C:\DetFuzz\runs\<suite-id>\reports\evidence-manifest.json
C:\DetFuzz\benign\<suite-id>\benign-results.json
C:\DetFuzz\benign\<suite-id>\reports\suite-report.json
C:\DetFuzz\benign\<suite-id>\reports\evidence-manifest.json
```

Verify the raw files and SHA256 hashes before presenting a historical result.
The source repository alone does not prove a Windows telemetry run.

## Guided helper

Run the complete workflow with the bundled helper:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\demo\detfuzz-demo.ps1 `
  -ProjectRoot $PWD `
  -HostName $env:COMPUTERNAME `
  -RunAll
```

For a faster rerun that uses default suite timeouts:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\demo\detfuzz-demo.ps1 `
  -ProjectRoot $PWD `
  -HostName $env:COMPUTERNAME `
  -SkipCalibration `
  -RunAll
```

## Explain the finding

The V1 rule depends on the literal `-EncodedCommand` command-line fragment.
`M1` uses PowerShell's valid `-enc` alias, produces the same harmless marker,
and retains complete Sysmon telemetry, but does not satisfy that literal rule
dependency. The closing baseline `B1` proves the detector was still working.

That makes `M1` a valid bypass of this intentionally narrow test rule. The
benign encoded fixtures show the other side of the design problem: broad
matching can also alert on harmless administration.
