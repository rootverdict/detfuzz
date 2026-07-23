# Evidence and Report Generation

This document covers the report-generation capability that was built before the
blueprint documentation/demo phase.

## Implemented

- SHA-256 hashing for evidence files.
- Evidence manifest generation with relative path, size, and hash.
- Suite results JSON validation.
- Evidence-backed suite report model.
- Classification summary counts.
- JSON report output.
- Markdown report output.
- Standalone evidence manifest output.
- `build-report` CLI command.

## Input Contract

The reporter expects a suite results JSON file:

```json
{
  "suite_id": "suite-id",
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

The reporter does not invent evidence. It hashes files already present in the
provided evidence directory.

## CLI

```powershell
python -m detfuzz.cli build-report `
  --suite-results C:\DetFuzz\suite-results.json `
  --evidence-root C:\DetFuzz\evidence `
  --output-dir C:\DetFuzz\reports
```

## VM Validation Result

Validated on 2026-07-21 against the Windows 11 Enterprise Evaluation VM.

Output files:

```text
C:\DetFuzz\reports\evidence-manifest.json
C:\DetFuzz\reports\suite-report.json
C:\DetFuzz\reports\suite-report.md
```
