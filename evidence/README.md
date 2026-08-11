# DetFuzz V1 Evidence

This directory records the identity and claim boundary of the latest external
V1 evidence package.

```text
artifacts/detfuzz-v1.0.0-release.zip
SHA256 6d5ba268a4ad59a1732e8d15117854d7c74610736d0597d1e894d7db7b008126
```

The archive is intentionally ignored by Git. A source clone cannot independently
prove the Windows telemetry run; obtain the archive through the portfolio
delivery channel and verify its SHA256 first.

## Included validation

- DetFuzz package: `1.0.0`.
- Rule slug: `detfuzz-v1-powershell-encoded-command`.
- Calibration suite: `80ae23e4-2354-40e3-98db-819ebf2c5dd0`, `PASS`, 20/20
  runs.
- Detection suite: `6336eceb-29f8-420e-9cbf-570596354abc`, `COMPLETED`.
- Benign suite: `8010ec26-0c67-4100-a4ea-324d3edd6bbe`, `COMPLETED`.
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
