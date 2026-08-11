# DetFuzz V1 Local Validation

This record captures the final V1 end-to-end validation completed on
2026-08-11. Raw artifacts are retained under the ignored
`artifacts/v1-release-20260811-final/` directory and in the external portfolio
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
- Clock preflight: `PASS`, source `time.windows.com,0x9`, offset `147 ms`.

## Calibration

- Suite ID: `80ae23e4-2354-40e3-98db-819ebf2c5dd0`.
- Status: `PASS` (`CALIBRATION_HEALTHY`).
- Runs: `20/20`.
- Selected process timeout: `30s`.
- Selected telemetry timeout: `30s`.
- Selected telemetry-query timeout: `30s`.
- Maximum observed telemetry-query duration: `15458 ms`.
- Result:
  `artifacts/v1-release-20260811-final/calibration/80ae23e4-2354-40e3-98db-819ebf2c5dd0/timeout-calibration.json`.

## Detection suite

- Suite ID: `6336eceb-29f8-420e-9cbf-570596354abc`.
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
  `artifacts/v1-release-20260811-final/runs/6336eceb-29f8-420e-9cbf-570596354abc/reports/suite-report.json`.

## Benign fixtures

- Suite ID: `8010ec26-0c67-4100-a4ea-324d3edd6bbe`.
- Status: `COMPLETED`.
- BF0: `BENIGN_NO_ALERT`.
- BF1: `BENIGN_ALERT`.
- BF2: `BENIGN_ALERT`.
- Telemetry: all three fixtures `TELEMETRY_COMPLETE`.
- Evidence manifest: 12 files; sizes and SHA256 hashes independently rechecked
  with zero failures.
- Report:
  `artifacts/v1-release-20260811-final/benign/8010ec26-0c67-4100-a4ea-324d3edd6bbe/reports/suite-report.json`.

## Contract and packaging

- Exported contract exactly matches the packaged canonical schema.
- Contract SHA256:
  `771d36f605fc6dd359724ccf40396b84ac41c768041d74d16a231d57bc94a4d2`.
- Clean wheel: `detfuzz-1.0.0-py3-none-any.whl`.
- Wheel SHA256:
  `01df31fcdb349d33ce6828d34bb362ddc40bf76385f492de2818eb3f021e5490`.
- Wheel contains 27 entries, all required V1 configs and contract resources,
  and zero legacy config entries.
- Isolated wheel installation imports version `1.0.0` successfully.

## Code quality

- Unit tests: 87 run; 86 passed and one expected missing-dependency-path test
  skipped because pySigma is installed.
- Ruff: all checks passed.
- mypy: no issues found in 31 source files.
- PowerShell demo helper: parser validation passed.

## External evidence package

- Archive: `artifacts/detfuzz-portfolio-v1-20260811.zip`.
- SHA256:
  `6d5ba268a4ad59a1732e8d15117854d7c74610736d0597d1e894d7db7b008126`.
- Archive entries: 140.
- Legacy or temporary entries: 0.

The source repository records these identities and results but cannot prove the
historical Windows run without the external archive. Recompute the archive and
evidence-manifest hashes before relying on the result.
