# Phase 7 VM Validation Commands

Run these inside the Windows 11 VM in Administrator PowerShell.

## Prepare Only

This prints the benign fixture commands without executing them:

```powershell
cd C:\DetFuzz\detfuzz
$env:PYTHONPATH='src'
python -m detfuzz.cli prepare-benign-fixtures --root C:\DetFuzz\benign
```

Confirm:

```text
BF0 uses -Command
BF1 uses -EncodedCommand
BF2 uses -EncodedCommand
```

## Run Benign Fixtures

```powershell
cd C:\DetFuzz\detfuzz
$env:PYTHONPATH='src'
python -m detfuzz.cli run-benign-fixtures `
  --output-root C:\DetFuzz\benign `
  --host DetFuzz-Win11-Lab `
  --telemetry-timeout-seconds 30 `
  --max-events 5000
```

Predicted output pattern before VM validation:

```text
BF0: BENIGN_NO_ALERT
BF1: BENIGN_ALERT
BF2: BENIGN_ALERT
```

If the observed output differs, keep the observed output. The difference is a
finding, not something to hide.

## Output Files

Each run creates:

```text
C:\DetFuzz\benign\<suite-id>\benign-results.json
C:\DetFuzz\benign\<suite-id>\evidence\
C:\DetFuzz\benign\<suite-id>\reports\evidence-manifest.json
C:\DetFuzz\benign\<suite-id>\reports\suite-report.json
C:\DetFuzz\benign\<suite-id>\reports\suite-report.md
```

## Interpretation

`BENIGN_ALERT` does not mean the benign command is bad. It means the current v0
rule dependency matched harmless benign activity. This is useful evidence for
later v0.1/v1 rule comparison and false-positive discussion.

After the run, update `docs/phase-7-vm-validation.md` with the actual suite ID,
observed classifications, and raw artifact paths.
