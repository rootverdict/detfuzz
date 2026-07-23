# Timeout Calibration and Clock Preflight

This implements the blueprint phase:

```text
Timeout calibration + clock preflight
```

## Clock Preflight

Run inside the Windows 11 VM:

```powershell
cd C:\DetFuzz\detfuzz
$env:PYTHONPATH='src'
python -m detfuzz.cli clock-preflight
```

Expected status:

```text
PASS
```

The preflight fails when absolute UTC offset is greater than 2000 ms.

## Timeout Calibration

Run 20 B0 baselines:

```powershell
cd C:\DetFuzz\detfuzz
$env:PYTHONPATH='src'
python -m detfuzz.cli calibrate-timeouts `
  --output-root C:\DetFuzz\calibration `
  --host DetFuzz-Win11-Lab `
  --runs 20 `
  --telemetry-probe-timeout-seconds 120 `
  --max-events 5000
```

The selected timeout method is:

```text
max(30s, observed_max + 10s)
```

If a selected timeout exceeds 120 seconds, calibration status becomes:

```text
UNSTABLE_TIMEOUTS
```

## Output

Each calibration creates:

```text
C:\DetFuzz\calibration\<suite-id>\timeout-calibration.json
```

The file records raw observations, min/median/max values, selected timeouts,
and the selection method.
