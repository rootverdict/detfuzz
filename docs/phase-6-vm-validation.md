# Phase 6 VM Validation

Validation date: 2026-07-21

Lab:

- Windows 11 Enterprise Evaluation VM
- Computer name: `DetFuzz-Win11-Lab`
- DetFuzz Phase 6 code copied into `C:\DetFuzz\detfuzz`

## Command

```powershell
cd C:\DetFuzz\detfuzz
$env:PYTHONPATH='src'
python -m detfuzz.cli build-report `
  --suite-results C:\DetFuzz\suite-results.json `
  --evidence-root C:\DetFuzz\evidence `
  --output-dir C:\DetFuzz\reports
```

## Result

```json
{
  "evidence_manifest": "C:\\DetFuzz\\reports\\evidence-manifest.json",
  "json_report": "C:\\DetFuzz\\reports\\suite-report.json",
  "markdown_report": "C:\\DetFuzz\\reports\\suite-report.md"
}
```

## Interpretation

- Suite results JSON was read successfully.
- Evidence directory was hashed successfully.
- Evidence manifest was written.
- JSON report was written.
- Markdown report was written.

## Phase 6 Status

```text
Phase 6 code complete
Phase 6 unit tests complete
Phase 6 VM validation complete
```
