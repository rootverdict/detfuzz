# Blueprint Phase 6 Summary

Phase 6 turns DetFuzz into a presentable project: documentation, demo commands,
evidence checklist, and a short talk track for explaining the result.

## Implemented

- End-to-end demo runbook for the Windows 11 lab.
- PowerShell demo driver with safe defaults and an explicit `-RunSuite` switch.
- Evidence checklist for portfolio packaging.
- Interview/demo talk track.
- Updated README with the validated v0 story.
- Report-generation notes moved to `docs/report-generation.md`.

## Evidence Status

Phase 6 documentation is built from the real VM run output that was pasted from
the Windows 11 Sysmon lab. The source zip itself does not prove that run; the
proof is the raw VM artifact set under `C:\DetFuzz\runs\<suite-id>` and
`C:\DetFuzz\calibration\<suite-id>`.

Recorded v0 run:

```text
suite_id: 49125a2a-6606-4a2e-8c99-5bda29857f6b
B0: DETECTED
M1: VALID_BYPASS
M2: DETECTED
M3: DETECTED
M4: DETECTED
M5: DETECTED
NC1: INVALID_MUTANT
B1: DETECTED
```

Recorded timeout calibration and clock preflight:

```text
clock-preflight: PASS
calibrate-timeouts: PASS, 20/20 runs
```

Keep these raw evidence files with the portfolio evidence package:

```text
C:\DetFuzz\runs\<suite-id>\suite-results.json
C:\DetFuzz\runs\<suite-id>\reports\evidence-manifest.json
C:\DetFuzz\runs\<suite-id>\reports\suite-report.json
C:\DetFuzz\runs\<suite-id>\reports\suite-report.md
C:\DetFuzz\calibration\<suite-id>\timeout-calibration.json
```

See `docs/phase-6-evidence-boundary.md` for the claim boundary.

## Demo Entry Points

- `docs/demo-runbook.md`: exact commands for a live VM demo.
- `docs/demo-talk-track.md`: concise explanation for an interviewer or reviewer.
- `docs/evidence-checklist.md`: files to collect before archiving a phase.
- `demo/detfuzz-demo.ps1`: guided PowerShell demo helper.

## Status

```text
Blueprint Phase 6 documentation complete
Blueprint Phase 6 demo materials complete
Local documentation package complete
VM result recorded from pasted lab output; raw VM artifacts must be preserved
```
