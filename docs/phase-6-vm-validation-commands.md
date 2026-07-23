# Phase 6 VM Validation Commands

Run these inside the Windows 11 VM after collecting a real event XML.

## Prepare Evidence Folder

```powershell
New-Item -ItemType Directory -Force -Path C:\DetFuzz\evidence\b0 | Out-Null
Copy-Item -LiteralPath C:\DetFuzz\b0-sysmon-event.xml -Destination C:\DetFuzz\evidence\b0\sysmon-event.xml -Force
Copy-Item -LiteralPath C:\DetFuzz\runs\2b2671ab-4e3a-460d-83ab-31eec2f426db\B0\effect.json -Destination C:\DetFuzz\evidence\b0\effect.json -Force
```

Adjust the suite ID path if your current run uses a different suite ID.

## Create Suite Results JSON

```powershell
@'
{
  "suite_id": "2b2671ab-4e3a-460d-83ab-31eec2f426db",
  "environment": {
    "host": "DetFuzz-Win11-Lab",
    "os": "Windows 11 Enterprise Evaluation",
    "telemetry": "Microsoft-Windows-Sysmon/Operational"
  },
  "cases": [
    {
      "case_id": "B0",
      "classification": "DETECTED",
      "marker_valid": true,
      "telemetry_valid": true,
      "detection_matched": true
    }
  ],
  "notes": [
    "Phase 6 validation report uses B0 evidence only."
  ]
}
'@ | Set-Content -LiteralPath C:\DetFuzz\suite-results.json -Encoding UTF8
```

## Build Report

```powershell
cd C:\DetFuzz\detfuzz
$env:PYTHONPATH='src'
python -m detfuzz.cli build-report `
  --suite-results C:\DetFuzz\suite-results.json `
  --evidence-root C:\DetFuzz\evidence `
  --output-dir C:\DetFuzz\reports
```

Expected files:

```text
C:\DetFuzz\reports\suite-report.json
C:\DetFuzz\reports\suite-report.md
C:\DetFuzz\reports\evidence-manifest.json
```
