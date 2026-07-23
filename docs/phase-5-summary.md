# Phase 5 Summary

Phase 5 adds the first detection adapter layer.

## Implemented

- v0 encoded PowerShell detection rule dependency model.
- Explicit rule dependencies:
  - `Image endswith \powershell.exe`
  - `CommandLine contains -EncodedCommand`
- Detection evaluation against validated Sysmon Event ID 1 fields.
- Dependency-by-dependency match results.
- Sigma dictionary dependency extraction for the v0 selection shape.
- pySigma-first Sigma loader with an explicit offline fallback only when pySigma
  is not installed.
- Example Sigma rule file:
  - `configs/v0-powershell-encoded-command.sigma.yml`
- JSON dependency contract:
  - `configs/v0-rule-dependencies.json`
- `evaluate-detection` CLI command for saved Sysmon XML events.

## Important Boundary

The Sigma rule uses a UUID `id` for pySigma compatibility and keeps the readable
DetFuzz rule name in `detfuzz_slug`. The local bundled Python environment used
for this package does not have pySigma installed, so the pySigma-specific test
is skipped locally; in an installed environment it loads the real rule with
fallback disabled.

This phase still avoids presenting a custom Sigma parser as the core project
value. The implemented evaluator works from explicit rule dependencies and from
already-validated Sysmon event fields.

## Status

```text
Phase 5 code complete
Phase 5 unit tests complete
Phase 5 VM validation complete
pySigma dependency declared; installed-pySigma test added
```

## VM Validation Result

Validated on 2026-07-21 against the Windows 11 Enterprise Evaluation VM using
the saved B0 Sysmon Event ID 1 XML.

Result:

```json
{
  "dependency_results": {
    "CommandLine|contains|-EncodedCommand": true,
    "Image|endswith|\\powershell.exe": true
  },
  "matched": true,
  "reason": "RULE_MATCHED",
  "rule_id": "d4f8c4e4-984d-4f5f-9f6c-1cc6b37f2f62"
}
```

This confirms the detection adapter can evaluate a real validated Sysmon process
creation event and report dependency-level match evidence.

## Expected v0 Behavior

Baseline command:

```text
powershell.exe ... -EncodedCommand ...
```

Expected detection result:

```text
RULE_MATCHED
```

Alias mutation:

```text
powershell.exe ... -enc ...
```

Expected detection result for this specific brittle v0 rule:

```text
RULE_NOT_MATCHED
```
