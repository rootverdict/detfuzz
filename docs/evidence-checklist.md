# DetFuzz V1 Evidence Checklist

Use this checklist before packaging or presenting a DetFuzz run.

## Environment record

- Windows host name and operating-system version.
- Python and DetFuzz package versions.
- Sysmon64 service status and active configuration hash.
- Sysmon operational channel name.
- Clock-preflight JSON with `status: PASS`.
- Timeout-calibration JSON with `status: PASS`.

## Detection-suite files

```text
<run-root>\<suite-id>\suite-results.json
<run-root>\<suite-id>\reports\suite-report.json
<run-root>\<suite-id>\reports\suite-report.md
<run-root>\<suite-id>\reports\evidence-manifest.json
<run-root>\<suite-id>\evidence\...
```

## Benign-fixture files

```text
<benign-root>\<suite-id>\benign-results.json
<benign-root>\<suite-id>\reports\suite-report.json
<benign-root>\<suite-id>\reports\suite-report.md
<benign-root>\<suite-id>\reports\evidence-manifest.json
<benign-root>\<suite-id>\evidence\...
```

## Review checks

- Suite status is `COMPLETED`.
- `B0` and `B1` are `DETECTED`.
- `NC1` is `INVALID_MUTANT`.
- A bypass is valid only when execution, marker, telemetry, identity, and closing
  baseline checks all succeed.
- Every retained evidence file matches its recorded SHA256 digest and size.
- Benign results use `BENIGN_ALERT` or `BENIGN_NO_ALERT`; they are never labeled
  as bypasses.
- Predicted benign outcomes remain separate from observed outcomes.
- The exported schema matches the packaged canonical contract.

## Claim boundary

Markdown summaries are navigation aids, not independent proof. Keep the raw
suite, calibration, benign, telemetry, and manifest files with the release
bundle so another reviewer can recompute every hash. The v1.0.1 bundle is
committed as `artifacts/detfuzz-v1.0.1-release.zip`, with its digest pinned in
`artifacts/detfuzz-v1.0.1-release.sha256.txt`.

Recomputing those hashes shows the bundle is internally consistent and
unmodified relative to its recorded manifest. It does not authenticate the
producer or the host.
