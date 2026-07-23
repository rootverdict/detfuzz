# DetFuzz Build Plan

Use `docs/version-boundary.md` as the release scope guardrail. The phase plan
describes completed implementation stages; the version boundary decides whether
new ideas belong in V1 or should wait for V2.

## Phase 1: Local Core

- Define v0 cases.
- Implement classification model.
- Add JSON result output.
- Add unit tests.

## Phase 2: Harmless PowerShell Runner

- Generate suite UUID, case paths, and nonces.
- Build encoded marker-writing payloads.
- Execute only allow-listed templates.
- Capture PID, timestamps, exit code, stdout, and stderr.
- Current status: code complete and VM validated.

## Phase 3: Marker Oracle

- Verify exact marker path.
- Validate suite ID, case ID, nonce, and result.
- Reject stale or broad-glob marker matches.
- Parse exported Sysmon Event XML.
- Validate Event ID 1 required fields.
- Correlate process telemetry by PID, image suffix, and command fragment.
- Current status: code complete and VM validated.

## Phase 4: Windows Telemetry Adapter

- Query Sysmon Event ID 1.
- Correlate by host, PID, image, hash, command line, and UTC window.
- Validate required fields.
- Current status: code complete and VM validated.

## Phase 5: Detection Adapter

- Load Sigma rules through pySigma.
- Convert or evaluate against the selected backend.
- Record rule dependencies.
- Current status: v0 dependency evaluator complete; pySigma dependency declared;
  UUID-backed Sigma rule added; installed-pySigma test added; VM validated.

## Phase 6: Evidence and Report

- Save raw observations.
- Hash evidence files.
- Produce JSON and Markdown reports.
- Current status: code complete and VM validated.

## Full v0 Suite Runner

- Execute B0, M1-M5, NC1, and B1 in order.
- Validate markers, telemetry, detection result, and classification per case.
- Abort when opening baseline B0 is not detected.
- Finalize candidate bypasses only after B1 succeeds.
- Write suite results, evidence files, evidence manifest, JSON report, and
  Markdown report.
- Current status: code complete and VM validated.

## Timeout Calibration and Clock Preflight

- Query UTC clock from the test environment.
- Fail preflight if absolute offset exceeds 2000 ms.
- Run repeated B0 baselines.
- Measure process duration, telemetry latency, and telemetry query duration.
- Select timeouts using `max(30s, observed_max + 10s)`.
- Mark calibration unstable if selected timeouts exceed 120 seconds.
- Current status: code complete and VM validated.

## Blueprint Phase 6: DetFuzz Documentation and Demo

- Provide a repeatable Windows VM demo runbook.
- Provide a short talk track for explaining the project.
- Provide an evidence checklist for portfolio packaging.
- Provide a guided PowerShell demo helper.
- Current status: documentation complete and locally packaged.

## Phase 7: DetFuzz v0.1 Benign Fixtures

- Add safe benign PowerShell fixtures.
- Measure whether the v0 rule alerts on harmless encoded activity.
- Classify benign fixture outcomes separately from bypass candidates.
- Produce evidence-backed benign fixture reports.
- Current status: code complete and VM validated.

## SignalBudget Handoff

- Export a versioned JSON contract for SignalBudget.
- Current status: canonical 1.0 JSON Schema is packaged and exportable through
  `detfuzz export-contract`; the cross-project consumer test remains independent.
