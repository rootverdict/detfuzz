# DetFuzz V1 Evidence

This directory records the identity and claim boundary of the latest external
V1 evidence package.

```text
artifacts/detfuzz-v1.0.1-release.zip
SHA256 5feae77e09e35323cf4a9384f7efc3353e61416714d5a8a86923b7f5a2e331ab
```

The archive is intentionally ignored by Git. A source clone cannot independently
prove the Windows telemetry run; obtain the archive through the portfolio
delivery channel and verify its SHA256 first.

## Included validation

- DetFuzz package: `1.0.1`.
- Rule slug: `detfuzz-v1-powershell-encoded-command`.
- Validated: 2026-08-13.
- Calibration suite: `1ec64ed5-fd14-4788-9b94-a052996450e8`, `PASS`, 20/20
  runs.
- Detection suite: `33874ec6-bda3-472f-b7e3-0d0437c00c0c`, `COMPLETED`.
- Benign suite: `eb23c7b3-bf13-446b-940e-0eaae8d029c3`, `COMPLETED`.
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
  -LiteralPath .\artifacts\detfuzz-v1.0.1-release.zip
```

After extraction, inspect `release-manifest.json`, the two suite reports, and
their evidence manifests. Recompute every evidence-file hash before treating
the recorded result as proven.
