# Evidence and Report Generation

DetFuzz writes an evidence-backed report bundle for both the detection suite
and benign fixtures.

## Outputs

- `suite-report.json`: canonical machine-readable report.
- `suite-report.md`: concise human-readable rendering.
- `evidence-manifest.json`: relative path, size, and SHA256 for each raw evidence
  file.

The report layer never invents evidence. It hashes files that already exist in
the supplied evidence directory and validates the generated JSON against the
packaged V1 report contract.

## Input shape

The standalone reporter accepts a results JSON file containing at least a suite
ID, environment, and case records:

```json
{
  "suite_id": "suite-id",
  "suite_status": "COMPLETED",
  "environment": {
    "host": "DetFuzz-Win11-Lab"
  },
  "cases": [
    {
      "case_id": "B0",
      "classification": "DETECTED"
    }
  ],
  "notes": []
}
```

## Rebuild a report

```powershell
python -m detfuzz.cli build-report `
  --suite-results C:\DetFuzz\runs\<suite-id>\suite-results.json `
  --evidence-root C:\DetFuzz\runs\<suite-id>\evidence `
  --output-dir C:\DetFuzz\runs\<suite-id>\reports
```

The output directory is created when needed. Existing report files at the exact
destination paths are replaced by the newly validated bundle.

## Contract

The canonical schema is
`src/detfuzz/contracts/detfuzz-suite-report-1.0.schema.json`. Export a consumer
copy with:

```powershell
python -m detfuzz.cli export-contract `
  --output C:\DetFuzz\contracts\detfuzz-suite-report-1.0.schema.json
```
