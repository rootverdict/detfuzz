# DetFuzz Evidence Checklist

Use this checklist before packaging a DetFuzz phase or demo archive.

## Required Lab Evidence

- Windows VM name: `DetFuzz-Win11-Lab`
- Sysmon64 service status screenshot or command output.
- `clock-preflight` JSON output showing `status: PASS`.
- `calibrate-timeouts` JSON output showing `status: PASS`.
- Full `run-suite` JSON output.
- Suite folder path under `C:\DetFuzz\runs\<suite-id>`.
- Phase 7 benign fixture output, if validating v0.1.

Do not rely on Markdown summaries alone. A reviewer should be able to inspect
the raw JSON reports and evidence manifest.

## Required Files

```text
C:\DetFuzz\runs\<suite-id>\suite-results.json
C:\DetFuzz\runs\<suite-id>\reports\suite-report.md
C:\DetFuzz\runs\<suite-id>\reports\suite-report.json
C:\DetFuzz\runs\<suite-id>\reports\evidence-manifest.json
C:\DetFuzz\calibration\<suite-id>\timeout-calibration.json
C:\DetFuzz\benign\<suite-id>\benign-results.json
C:\DetFuzz\benign\<suite-id>\reports\suite-report.md
```

## Review Checks

- `B0` is `DETECTED`.
- `B1` is `DETECTED`.
- `NC1` is `INVALID_MUTANT`.
- Candidate bypasses are only called valid when marker and telemetry are valid.
- Evidence manifest contains hashes for saved evidence files.
- Report notes mention any calibration or clock warnings.
- For Phase 7, benign fixture alerts are reported as `BENIGN_ALERT`, not as
  bypasses.
- For Phase 7, predicted fixture results must stay separate from observed VM
  results.

## Portfolio Notes

Include the final Markdown report and the talk track. Keep raw logs available
for review, but lead with the short result table.
