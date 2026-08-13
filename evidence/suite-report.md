# DetFuzz V1 Evidence Snapshot

> This tracked file is a navigation summary. The raw evidence files live in the
> committed archive recorded in `evidence/README.md`; verify its SHA256 and
> recompute the evidence hashes before relying on this result.

Suite ID: `33874ec6-bda3-472f-b7e3-0d0437c00c0c`

Suite status: `COMPLETED`

Generated UTC: `2026-08-13T09:24:00.739700+00:00`

Rule: `detfuzz-v1-powershell-encoded-command`

Case count: `8`

## Classification summary

- `DETECTED`: 6
- `INVALID_MUTANT`: 1
- `VALID_BYPASS`: 1

## Cases

- `B0`: `DETECTED`
- `M1`: `VALID_BYPASS`
- `M2`: `DETECTED`
- `M3`: `DETECTED`
- `M4`: `DETECTED`
- `M5`: `DETECTED`
- `NC1`: `INVALID_MUTANT`
- `B1`: `DETECTED`

## Evidence verification

- Manifest entries: 63.
- Size mismatches: 0.
- SHA256 mismatches: 0.
- All cases: `TELEMETRY_COMPLETE`.
- B0 standalone evaluation: `RULE_MATCHED`.
- M1 standalone evaluation: `RULE_NOT_MATCHED`.

Canonical raw report inside the committed package:

```text
runs/33874ec6-bda3-472f-b7e3-0d0437c00c0c/reports/suite-report.json
```
