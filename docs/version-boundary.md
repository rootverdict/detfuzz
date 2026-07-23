# DetFuzz Version Boundary

This document defines what belongs in the first portfolio-ready DetFuzz release
and what should wait for the next expansion. Use it as the guardrail when a new
idea appears during implementation or demo preparation.

## Decision Rule

Before adding work, ask:

```text
Is this required for the V1 DetFuzz story to run end-to-end and be defensible?
```

If yes, keep it in V1. If no, record it under V2 or later.

## V1 Scope

V1 is the first complete, evidence-backed DetFuzz release. It should show one
narrow detection-resilience experiment from safe execution through telemetry,
detection evaluation, classification, and report output.

V1 includes:

- Safe PowerShell encoded-command test cases only.
- Opening and closing positive controls.
- Five valid syntactic mutations for the v0 encoded-command rule shape.
- One invalid corrupted-Base64 negative control.
- Marker-file oracle validation.
- Sysmon Event ID 1 telemetry correlation.
- Detection evaluation for the packaged v0 rule dependency model.
- Deterministic case classification.
- Timeout calibration and clock preflight.
- Evidence manifest generation with file hashes.
- Machine-readable JSON report output.
- Human-readable Markdown report output.
- Repeatable Windows VM demo flow.
- v0.1 benign false-positive fixtures:
  - Plain benign PowerShell command.
  - Encoded benign `Get-Date`.
  - Encoded benign service listing.
- Packaged DetFuzz-to-SignalBudget JSON Schema export.

## V1 Outputs

The V1 handoff artifacts are:

- `suite-report.json`
- `suite-report.md`
- `evidence-manifest.json`
- `detfuzz-suite-report-1.0.schema.json`

DetFuzz owns producing these artifacts. SignalBudget owns consuming the JSON
report and validating it against the exported schema.

## V1 Done Criteria

V1 is done only when:

- Unit tests pass with the pinned dependency set.
- VM validation exists for the full v0 suite.
- VM validation exists for the v0.1 benign fixtures.
- `export-contract` produces the packaged suite-report schema.
- Raw evidence artifacts are retained outside the source zip.
- README status and demo commands match the implemented behavior.
- The demo runbook and talk track explain the claim boundary honestly.

## Not In V1

These are useful ideas, but they should not expand V1:

- Parent-process mutation.
- More execution surfaces beyond the current PowerShell encoded-command shape.
- Multiple Sigma rules or rule packs.
- Live SIEM integrations beyond the current evidence/report path.
- Additional telemetry providers beyond the current Windows Sysmon flow.
- Web UI or dashboard.
- Distributed runners.
- Automatic remediation recommendations.
- Large malicious payload libraries.
- Claims that cannot be backed by retained raw VM evidence.

## V2 Scope

V2 can start after V1 is stable and demonstrable. Its purpose is controlled
expansion, not reworking the V1 core.

Good V2 candidates:

- Parent-process mutation as a separate telemetry-semantics experiment.
- Additional harmless PowerShell behavior families.
- More rule dependency models or pySigma-backed evaluation paths.
- Cross-rule comparison between strict and broad detections.
- Richer false-positive analysis using more benign fixtures.
- Optional dashboard or report viewer.
- Better export workflows for downstream consumers such as SignalBudget.

Each V2 feature should have its own evidence boundary and validation checklist
before implementation begins.

## Parking Lot

When a new idea is not required for V1, add it here instead of changing V1
scope.

- Parent-process mutation.
- Broader detector/backend comparison.
- Larger benign fixture catalog.
- UI/dashboard for report inspection.
