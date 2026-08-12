# DetFuzz V1 Evidence

This directory records the identity and claim boundary of the latest external
V1 evidence package.

```text
artifacts/detfuzz-v1.0.0-release.zip
SHA256 f5e4fb1aa40f2c6ca3245fc874b1d5c408315413b36000997b6b37f4259ba562
```

The archive is intentionally ignored by Git. A source clone cannot independently
prove the Windows telemetry run; obtain the archive through the portfolio
delivery channel and verify its SHA256 first.

## Included validation

- DetFuzz package: `1.0.0`.
- Rule slug: `detfuzz-v1-powershell-encoded-command`.
- Validated: 2026-08-12.
- Calibration suite: `cc192eec-015c-4691-a0ff-e3b3d6f2f2fb`, `PASS`, 20/20
  runs.
- Detection suite: `914304ea-8723-45c2-a35e-4a1bbfde9e38`, `COMPLETED`.
- Benign suite: `f291323f-f0af-4120-8031-32e8a8b01d57`, `COMPLETED`.
- Detection evidence: 63 files, zero hash or size failures.
- Benign evidence: 12 files, zero hash or size failures.
- Contract export and clean wheel.
- `release-manifest.json` with all release identities and hashes.

## Detection result

```text
B0  DETECTED
M1  VALID_BYPASS
M2  DETECTED
M3  DETECTED
M4  DETECTED
M5  DETECTED
NC1 INVALID_MUTANT
B1  DETECTED
```

## Benign result

```text
BF0 BENIGN_NO_ALERT
BF1 BENIGN_ALERT
BF2 BENIGN_ALERT
```

## Verify the archive

```powershell
Get-FileHash `
  -Algorithm SHA256 `
  -LiteralPath .\artifacts\detfuzz-v1.0.0-release.zip
```

After extraction, inspect `release-manifest.json`, the two suite reports, and
their evidence manifests. Recompute every evidence-file hash before treating
the recorded result as proven.
