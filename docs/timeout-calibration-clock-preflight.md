# Clock Preflight and Timeout Calibration

Live Sysmon correlation is timing-sensitive. DetFuzz checks clock health and
measures the lab before running the detection suite.

## Clock preflight

```powershell
$env:PYTHONPATH = "$PWD\src"
python -m detfuzz.cli clock-preflight
```

The command queries Windows time status and compares local UTC sources. It
returns nonzero unless status is `PASS`; an absolute offset greater than 2000 ms
fails preflight.

## Timeout calibration

```powershell
python -m detfuzz.cli calibrate-timeouts `
  --output-root C:\DetFuzz\calibration `
  --host $env:COMPUTERNAME `
  --runs 20 `
  --telemetry-probe-timeout-seconds 120 `
  --max-events 5000
```

Calibration repeatedly runs the opening baseline and records process duration,
telemetry latency, and query duration. Each selected timeout is:

```text
max(30 seconds, observed maximum + 10 seconds)
```

Calibration reports `PASS` only when every observation has valid execution,
marker, telemetry, and detection results and every selected timeout is at most
120 seconds. Otherwise it reports `CALIBRATION_FAILED` and exits nonzero.

## Output

Each calibration creates:

```text
C:\DetFuzz\calibration\<suite-id>\timeout-calibration.json
```

Pass this file to `run-suite --calibration-result` so the live suite uses the
measured process and telemetry timeouts.
