# DetFuzz V1 Local Validation

This record captures the latest V1 end-to-end validation completed on
2026-08-13. It is a point-in-time record: the figures below describe the tree
that was validated, and they are deliberately not revised as the repository
moves on.

The release bundle is committed as `artifacts/detfuzz-v1.0.1-release.zip`, with
its digest pinned in `artifacts/detfuzz-v1.0.1-release.sha256.txt`. The
extracted `artifacts/detfuzz-v1.0.1-release/` directory stays ignored by Git.

## Environment

- Host: `DESKTOP-42ET8NS`.
- Package: `detfuzz 1.0.1`.
- Python: `3.12.10`.
- Sysmon: `Sysmon64` running with automatic startup.
- Channel: `Microsoft-Windows-Sysmon/Operational`.
- Sysmon config: `configs/sysmon-detfuzz.xml`.
- Sysmon config SHA256:
  `b6b7a84bc0daccddb7824ac5a69352336206f0a450f6422e36e98982804471f9`.
- Rule slug: `detfuzz-v1-powershell-encoded-command`.
- Clock preflight: `PASS`, source `time.windows.com,0x9`, suite-recorded offset
  `771 ms`.

The Windows Time service (`W32Time`) must be running before the suite starts.
It is set to `Manual` startup on this host, and a stopped service makes
`w32tm /query /status` fail, which correctly aborts preflight with
`TIME_SYNC_STATUS_QUERY_FAILED`.

## Calibration

- Suite ID: `1ec64ed5-fd14-4788-9b94-a052996450e8`.
- Status: `PASS` (`CALIBRATION_HEALTHY`).
- Runs: `20/20`.
- Selected process timeout: `30s`.
- Selected telemetry timeout: `30s`.
- Selected telemetry-query timeout: `35s`.
- Maximum observed telemetry-query duration: `24420 ms`.
- Result:
  `artifacts/detfuzz-v1.0.1-release/calibration/1ec64ed5-fd14-4788-9b94-a052996450e8/timeout-calibration.json`.

The selected telemetry-query timeout rounded the `24.420s` observed maximum up
to the next whole second before adding the full `10s` safety margin. The final
`35s` value matches the documented `max(30s, observed_max + 10s)` policy.

## Detection suite

- Suite ID: `33874ec6-bda3-472f-b7e3-0d0437c00c0c`.
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
  `artifacts/detfuzz-v1.0.1-release/runs/33874ec6-bda3-472f-b7e3-0d0437c00c0c/reports/suite-report.json`.

## Benign fixtures

- Suite ID: `eb23c7b3-bf13-446b-940e-0eaae8d029c3`.
- Status: `COMPLETED`.
- BF0: `BENIGN_NO_ALERT`.
- BF1: `BENIGN_ALERT`.
- BF2: `BENIGN_ALERT`.
- Telemetry: all three fixtures `TELEMETRY_COMPLETE`.
- Evidence manifest: 12 files; sizes and SHA256 hashes independently rechecked
  with zero failures.
- Report:
  `artifacts/detfuzz-v1.0.1-release/benign/eb23c7b3-bf13-446b-940e-0eaae8d029c3/reports/suite-report.json`.

## Contract and packaging

- Exported contract exactly matches the packaged canonical schema.
- Contract SHA256:
  `d6feaac7c86d38566d949771feee4f7e3025b4cd59dfa46080d0d3ba5f3f6f95`.
- Clean wheel: `detfuzz-1.0.1-py3-none-any.whl`.
- Wheel SHA256:
  `697853b756679537b93427cdd14bb344d0d4ff389b3b5f3a9fc3048c9da03e98`.
- Wheel contains 27 entries, all required V1 configs and contract resources,
  and zero legacy config entries.
- Installed package imports version `1.0.1` successfully.
- Packaged resources load from the isolated installation: the contract hashes
  to the canonical digest above, and `detfuzz/configs` contains exactly
  `sysmon-detfuzz.xml`, `v1-powershell-encoded-command.sigma.yml`, and
  `v1-rule-dependencies.json`.

## Code quality

- Unit tests: 95 run; 94 passed and one expected missing-dependency-path test
  skipped because pySigma is installed.
- Ruff: all checks passed.
- mypy: no issues found in 31 source files.
- PowerShell demo helper: parser validation passed.

## Evidence package

- Archive: `artifacts/detfuzz-v1.0.1-release.zip`, committed to Git.
- SHA256 as packed on the validation host, 2026-08-13:
  `5feae77e09e35323cf4a9384f7efc3353e61416714d5a8a86923b7f5a2e331ab`.
- SHA256 of the committed archive:
  `7b9a5a56ce9fc383640b50b75da21278ee7d1340de2a9b390779c9f5527e2e38`.
- Archive entries: 114 files.
- Legacy or temporary entries: 0.

The two digests differ because the bundle was repacked when the artifacts were
consolidated and committed. Verify against
`artifacts/detfuzz-v1.0.1-release.sha256.txt`, which pins the committed archive
and is the authoritative reference; the first digest is retained as history.

The archive stores files only; empty per-case working directories are not
retained because every marker and telemetry artifact is copied into the
`evidence/` tree that the manifest hashes.

The source repository records these identities and results but cannot prove the
historical Windows run on its own. Recompute the archive and evidence-manifest
hashes before relying on the result.

## Reproducibility

This run reproduced the V1.0.0 result exactly: the same eight
classifications, the same `M1` bypass, the same three benign outcomes, and the
same 63-file and 12-file evidence counts, on a freshly calibrated timing
profile and a new set of suite identifiers.
