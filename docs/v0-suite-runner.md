# DetFuzz v0 Suite Runner

The `run-suite` command executes the full v0 sequence:

```text
B0 -> M1 -> M2 -> M3 -> M4 -> M5 -> NC1 -> B1
```

## Command

Run inside the Windows 11 VM from the DetFuzz project directory:

```powershell
cd C:\DetFuzz\detfuzz
$env:PYTHONPATH='src'
python -m detfuzz.cli run-suite `
  --output-root C:\DetFuzz\runs `
  --host DetFuzz-Win11-Lab `
  --max-events 5000 `
  --calibration-result C:\DetFuzz\calibration\<suite-id>\timeout-calibration.json
```

`--calibration-result` is optional for development, but portfolio/demo runs
should use it so the full suite inherits the measured process and telemetry
timeouts from `calibrate-timeouts`.

## Outputs

Each run creates:

```text
C:\DetFuzz\runs\<suite-id>\suite-results.json
C:\DetFuzz\runs\<suite-id>\evidence\
C:\DetFuzz\runs\<suite-id>\reports\evidence-manifest.json
C:\DetFuzz\runs\<suite-id>\reports\suite-report.json
C:\DetFuzz\runs\<suite-id>\reports\suite-report.md
```

## Validated v0 Result

The first full VM run completed with:

```text
B0: DETECTED
M1: VALID_BYPASS
M2-M5: DETECTED
NC1: INVALID_MUTANT
B1: DETECTED
```

If B0 is not detected in a future run, the suite aborts and writes a partial
report.
