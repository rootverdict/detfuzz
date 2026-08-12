# DetFuzz V1 Local Validation

This record captures the latest V1 end-to-end validation completed on
2026-08-12. Raw artifacts are retained under the ignored
`artifacts/detfuzz-v1.0.0-release/` directory and in the external portfolio
archive; they are not committed to Git.

## Environment

- Host: `DESKTOP-42ET8NS`.
- Package: `detfuzz 1.0.0`.
- Python: `3.12.10`.
- Sysmon: `Sysmon64` running with automatic startup.
- Channel: `Microsoft-Windows-Sysmon/Operational`.
- Sysmon config: `configs/sysmon-detfuzz.xml`.
- Sysmon config SHA256:
  `b6b7a84bc0daccddb7824ac5a69352336206f0a450f6422e36e98982804471f9`.
- Rule slug: `detfuzz-v1-powershell-encoded-command`.
- Clock preflight: `PASS`, source `time.windows.com,0x9`, suite-recorded offset
  `179 ms`.

The Windows Time service (`W32Time`) must be running before the suite starts.
It is set to `Manual` startup on this host, and a stopped service makes
`w32tm /query /status` fail, which correctly aborts preflight with
`TIME_SYNC_STATUS_QUERY_FAILED`.

## Calibration

- Suite ID: `cc192eec-015c-4691-a0ff-e3b3d6f2f2fb`.
- Status: `PASS` (`CALIBRATION_HEALTHY`).
- Runs: `20/20`.
- Selected process timeout: `30s`.
- Selected telemetry timeout: `30s`.
- Selected telemetry-query timeout: `46s`.
- Maximum observed telemetry-query duration: `36500 ms`.
- Result:
  `artifacts/detfuzz-v1.0.0-release/calibration/cc192eec-015c-4691-a0ff-e3b3d6f2f2fb/timeout-calibration.json`.

The selected telemetry-query timeout rose from `30s` to `46s` relative to the
2026-08-11 run because the Sysmon operational channel has grown and each query
now scans more events. The `max(30s, observed_max + 10s)` selection method
absorbed the change without operator intervention.

## Detection suite

- Suite ID: `914304ea-8723-45c2-a35e-4a1bbfde9e38`.
- Status: `COMPLETED`.
- B0: `DETECTED`.
- M1: `VALID_BYPASS`.
- M2: `DETECTED`.
- M3: `DETECTED`.
- M4: `DETECTED`.
- M5: `DETECTED`.
- NC1: `INVALID_MUTANT`.
- B1: `DETECTED`.
- Telemetry: all eight cases `TELEMETRY_COMPLETE`.
- Evidence manifest: 63 files; sizes and SHA256 hashes independently rechecked
  with zero failures.
- B0 detection smoke check: `RULE_MATCHED`.
- M1 detection smoke check: `RULE_NOT_MATCHED`.
- Report:
  `artifacts/detfuzz-v1.0.0-release/runs/914304ea-8723-45c2-a35e-4a1bbfde9e38/reports/suite-report.json`.

## Benign fixtures

- Suite ID: `f291323f-f0af-4120-8031-32e8a8b01d57`.
- Status: `COMPLETED`.
- BF0: `BENIGN_NO_ALERT`.
- BF1: `BENIGN_ALERT`.
- BF2: `BENIGN_ALERT`.
- Telemetry: all three fixtures `TELEMETRY_COMPLETE`.
- Evidence manifest: 12 files; sizes and SHA256 hashes independently rechecked
  with zero failures.
- Report:
  `artifacts/detfuzz-v1.0.0-release/benign/f291323f-f0af-4120-8031-32e8a8b01d57/reports/suite-report.json`.

## Contract and packaging

- Exported contract exactly matches the packaged canonical schema.
- Contract SHA256:
  `771d36f605fc6dd359724ccf40396b84ac41c768041d74d16a231d57bc94a4d2`.
- Clean wheel: `detfuzz-1.0.0-py3-none-any.whl`.
- Wheel SHA256:
  `d74c34e4018807b0293c56a99f24976667096b33972225e72bbd1fc646bc3ac5`.
- Wheel contains 27 entries, all required V1 configs and contract resources,
  and zero legacy config entries.
- Isolated wheel installation imports version `1.0.0` successfully.
- Packaged resources load from the isolated installation: the contract hashes
  to the canonical digest above, and `detfuzz/configs` contains exactly
  `sysmon-detfuzz.xml`, `v1-powershell-encoded-command.sigma.yml`, and
  `v1-rule-dependencies.json`.

## Code quality

- Unit tests: 87 run; 86 passed and one expected missing-dependency-path test
  skipped because pySigma is installed.
- Ruff: all checks passed.
- mypy: no issues found in 31 source files.
- PowerShell demo helper: parser validation passed.

## External evidence package

- Archive: `artifacts/detfuzz-v1.0.0-release.zip`.
- SHA256:
  `f5e4fb1aa40f2c6ca3245fc874b1d5c408315413b36000997b6b37f4259ba562`.
- Archive entries: 114 files.
- Legacy or temporary entries: 0.

The archive stores files only; empty per-case working directories are not
retained because every marker and telemetry artifact is copied into the
`evidence/` tree that the manifest hashes.

The source repository records these identities and results but cannot prove the
historical Windows run without the external archive. Recompute the archive and
evidence-manifest hashes before relying on the result.

## Reproducibility

This run reproduced the 2026-08-11 result exactly: the same eight
classifications, the same `M1` bypass, the same three benign outcomes, and the
same 63-file and 12-file evidence counts, on a freshly calibrated timing
profile and a new set of suite identifiers.
