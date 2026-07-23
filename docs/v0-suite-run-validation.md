# DetFuzz v0 Suite Run Validation

Validation date: 2026-07-21

Lab:

- Windows 11 Enterprise Evaluation VM
- Computer name: `DetFuzz-Win11-Lab`
- Sysmon64 installed and running
- DetFuzz suite runner copied into `C:\DetFuzz\detfuzz`

## Command

```powershell
python -m detfuzz.cli run-suite `
  --output-root C:\DetFuzz\runs `
  --host DetFuzz-Win11-Lab `
  --max-events 5000
```

## Result

This section records pasted PowerShell output from the Windows 11 Sysmon lab.
The source repository should not be treated as independent proof of this run;
preserve the raw `suite-results.json`, report files, and evidence manifest from
the VM for portfolio review.

```text
suite_id: 49125a2a-6606-4a2e-8c99-5bda29857f6b
suite_status: COMPLETED
abort_reason: null
suite_path: C:\DetFuzz\runs\49125a2a-6606-4a2e-8c99-5bda29857f6b
```

Reports:

```text
C:\DetFuzz\runs\49125a2a-6606-4a2e-8c99-5bda29857f6b\reports\evidence-manifest.json
C:\DetFuzz\runs\49125a2a-6606-4a2e-8c99-5bda29857f6b\reports\suite-report.json
C:\DetFuzz\runs\49125a2a-6606-4a2e-8c99-5bda29857f6b\reports\suite-report.md
```

## Case Summary

| Case | Classification | Marker | Telemetry | Detection |
|---|---|---|---|---|
| B0 | DETECTED | MARKER_VALID | TELEMETRY_COMPLETE | RULE_MATCHED |
| M1 | VALID_BYPASS | MARKER_VALID | TELEMETRY_COMPLETE | RULE_NOT_MATCHED |
| M2 | DETECTED | MARKER_VALID | TELEMETRY_COMPLETE | RULE_MATCHED |
| M3 | DETECTED | MARKER_VALID | TELEMETRY_COMPLETE | RULE_MATCHED |
| M4 | DETECTED | MARKER_VALID | TELEMETRY_COMPLETE | RULE_MATCHED |
| M5 | DETECTED | MARKER_VALID | TELEMETRY_COMPLETE | RULE_MATCHED |
| NC1 | INVALID_MUTANT | MARKER_ABSENT_AS_EXPECTED | TELEMETRY_COMPLETE | RULE_MATCHED |
| B1 | DETECTED | MARKER_VALID | TELEMETRY_COMPLETE | RULE_MATCHED |

## Interpretation

- Opening baseline B0 detected successfully.
- Closing baseline B1 detected successfully.
- M1 was promoted from `CANDIDATE_VALID_BYPASS` to `VALID_BYPASS` because B1
  confirmed the detection pipeline was still healthy.
- M2-M5 were detected.
- NC1 was classified as `INVALID_MUTANT` because the corrupted Base64 command
  exited non-zero and did not create a marker.
- NC1 still matched the simple syntactic v0 rule because its command line
  contained `-EncodedCommand`; the classification model correctly gives
  invalid execution priority over detection result.

## Blueprint Status

This validates the full v0 test sequence:

```text
B0 -> M1 -> M2 -> M3 -> M4 -> M5 -> NC1 -> B1
```

## Evidence Boundary

Required raw artifacts:

```text
C:\DetFuzz\runs\49125a2a-6606-4a2e-8c99-5bda29857f6b\suite-results.json
C:\DetFuzz\runs\49125a2a-6606-4a2e-8c99-5bda29857f6b\reports\evidence-manifest.json
C:\DetFuzz\runs\49125a2a-6606-4a2e-8c99-5bda29857f6b\reports\suite-report.json
C:\DetFuzz\runs\49125a2a-6606-4a2e-8c99-5bda29857f6b\reports\suite-report.md
```

Without those raw files, this document should be read as a recorded validation
summary, not as independently verifiable evidence.
