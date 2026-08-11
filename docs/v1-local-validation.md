# DetFuzz V1 Local Validation

This record captures the successful end-to-end run completed locally on
2026-08-11. The generated raw artifacts remain under the ignored `artifacts/`
directory; they are not part of the source commits.

## Environment

- Host: `DESKTOP-42ET8NS`
- Sysmon: `Sysmon64` service running; `SysmonDrv` driver running.
- Sysmon channel: `Microsoft-Windows-Sysmon/Operational`.
- Configuration: `configs/sysmon-detfuzz.xml` with PowerShell Process Create
  filtering and SHA256 hashes.
- Clock preflight: `PASS` from `time.windows.com,0x9`.

## Calibration

- Suite ID: `1bcbcf2c-0104-41db-8dca-4c30dc1f9102`
- Status: `PASS`
- Runs: `20/20`
- Selected process timeout: `30s`
- Selected telemetry timeout: `30s`
- Selected telemetry query timeout: `30s`
- Raw result:
  `artifacts/v1-calibration-dd2a0ded-59fb-4a49-8fd2-7491073502fc/1bcbcf2c-0104-41db-8dca-4c30dc1f9102/timeout-calibration.json`

## Detection Suite

- Suite ID: `72e4da7c-a516-477c-a836-b94d773ca722`
- Status: `COMPLETED`
- B0: `DETECTED`
- M1: `VALID_BYPASS`
- M2: `DETECTED`
- M3: `DETECTED`
- M4: `DETECTED`
- M5: `DETECTED`
- NC1: `INVALID_MUTANT`
- B1: `DETECTED`
- Telemetry: all 8 cases `TELEMETRY_COMPLETE`.
- Evidence manifest: 63 files, all SHA256 hashes verified.
- Raw report:
  `artifacts/v1-suite-a63b9677-cf52-4009-a83b-2b5ca7caf485/runs/72e4da7c-a516-477c-a836-b94d773ca722/reports/suite-report.json`

## Benign Fixtures

- Suite ID: `63b91b40-ba79-4cd4-b6ed-fc33099546a8`
- Status: `COMPLETED`
- BF0: `BENIGN_NO_ALERT`
- BF1: `BENIGN_ALERT`
- BF2: `BENIGN_ALERT`
- Telemetry: all 3 fixtures `TELEMETRY_COMPLETE`.
- Evidence manifest: 12 files, all SHA256 hashes verified.
- Raw report:
  `artifacts/v1-suite-a63b9677-cf52-4009-a83b-2b5ca7caf485/benign/63b91b40-ba79-4cd4-b6ed-fc33099546a8/reports/suite-report.json`

## Contract and Detection Smoke Checks

- `evaluate-detection` against the saved B0 XML: `RULE_MATCHED`.
- `evaluate-detection` against the saved M1 XML: `RULE_NOT_MATCHED`.
- Contract export succeeded.
- Temporary wheel build succeeded and included `detfuzz/configs/sysmon-detfuzz.xml`.

The historical evidence IDs in the phase summaries and `evidence/README.md`
refer to separate external runs. They are not the same as this local run and
should remain labeled separately when assembling a portfolio package.
