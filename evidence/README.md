# DetFuzz v0 Evidence

This folder points to the final portfolio evidence package:

```text
evidence/portfolio-v0-evidence.zip
SHA256 7c58fd3ee092abf19841f6ea738f4674d6f138e81e779731283077b3d577dd85
```

The evidence archive contains the real Windows VM run for suite:

```text
dc017824-0d4e-41d0-9d32-610b410accb0
```

Summary:

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

The archive includes clock preflight, the failed first calibration, the passing
20-run calibration retry, eight matched Sysmon Event ID 1 XML files, the
canonical suite report, and a 63-file evidence manifest.

The first calibration is kept intentionally: three telemetry correlations timed
out under the initial polling window, so calibration was rerun with a larger
process timeout. The passing retry selected a 74-second telemetry query timeout,
and the final suite used that Python-written calibration file.

Quick validation command:

```powershell
cd C:\DetFuzz\release-v0\signalbudget
$env:PYTHONPATH='src'
python -m signalbudget.cli validate-detfuzz `
  --path C:\DetFuzz\portfolio-v0\runs\dc017824-0d4e-41d0-9d32-610b410accb0\reports\suite-report.json `
  --evidence-root C:\DetFuzz\portfolio-v0\runs\dc017824-0d4e-41d0-9d32-610b410accb0\evidence `
  --require-suite-contract
```

Expected validation highlights:

```text
suite_status: COMPLETED
evidence_files_checked: 63
evidence_hashes_verified: true
validated_rule_ids: d4f8c4e4-984d-4f5f-9f6c-1cc6b37f2f62
```
