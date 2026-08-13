# DetFuzz V1 Evidence

This directory records the identity and claim boundary of the committed V1
evidence package.

```text
artifacts/detfuzz-v1.0.1-release.zip
SHA256 7b9a5a56ce9fc383640b50b75da21278ee7d1340de2a9b390779c9f5527e2e38
```

The archive is tracked in Git alongside
`artifacts/detfuzz-v1.0.1-release.sha256.txt`, so a clone carries the evidence
these claims rest on. Extractions and intermediate build output stay ignored.

A clone still cannot independently prove the Windows telemetry run. The hashes
establish that the bundle is internally consistent and unmodified relative to its
recorded manifest; they do not authenticate the producer or the host, because
DetFuzz computes them for its own output.

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

Compare the result with `artifacts/detfuzz-v1.0.1-release.sha256.txt`, which is
committed beside the archive and is the authoritative pin.

After extraction, inspect `release-manifest.json`, the two suite reports, and
their evidence manifests. Recompute every evidence-file hash before treating
the recorded result as proven.
