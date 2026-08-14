# DetFuzz Version Boundary

This document defines the supported V1 release and prevents scope creep from
weakening its evidence story.

## Decision rule

Work belongs in V1 only when it is required for the current safe experiment to
run end to end or to make its result defensible. Everything else belongs in a
later release.

## V1 scope

V1 includes:

- Safe PowerShell encoded-command fixtures.
- Opening and closing positive controls.
- Five valid syntactic command-line mutations.
- One corrupted-Base64 negative control.
- Exact marker-file oracle validation.
- Sysmon Event ID 1 correlation.
- Executable SHA256 identity validation.
- Evaluation of the packaged single-rule dependency model.
- Deterministic case classification.
- Clock preflight and timeout calibration.
- Evidence manifests with file sizes and SHA256 hashes.
- JSON and Markdown reports.
- Three benign false-positive fixtures.
- A repeatable Windows demo workflow.
- Export of the versioned suite-report JSON Schema.

## V1 outputs

- `suite-results.json` or `benign-results.json`.
- `suite-report.json`.
- `suite-report.md`.
- `evidence-manifest.json`.
- Raw case or fixture evidence.
- `detfuzz-suite-report-1.0.schema.json`.

## Done criteria

V1 is done when:

- unit tests pass with the pinned dependency set;
- Ruff and mypy pass;
- a live Windows run validates the detection suite and benign fixtures;
- clock preflight and timeout calibration pass;
- every evidence-manifest entry can be rehashed successfully;
- contract export and packaged-resource checks pass;
- README and demo instructions match the implemented CLI;
- raw evidence is retained with an explicit claim boundary, and the release
  bundle is committed with a pinned digest.

## Outside V1

- Parent-process mutation.
- Additional execution surfaces.
- Multiple Sigma rules or rule packs.
- Live SIEM integrations.
- Additional telemetry providers.
- Web dashboards or distributed runners.
- Automated remediation recommendations.
- Malicious payload libraries.
- Claims that cannot be supported by retained raw evidence.

## Later releases

Good candidates for a later release include additional harmless behavior
families, multiple rule dependency models, backend comparison, broader benign
fixture analysis, and richer report visualization. Each expansion needs its own
evidence boundary and validation checklist.
