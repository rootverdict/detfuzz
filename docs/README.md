# DetFuzz V1 Documentation

This directory contains the current operator, validation, and release-boundary
documentation for DetFuzz V1.

## Start here

- [`../README.md`](../README.md): project overview, setup, commands, and current
  verified status.
- [`demo-runbook.md`](demo-runbook.md): complete Windows lab demonstration.
- [`demo-talk-track.md`](demo-talk-track.md): short explanation of the design and
  validated finding.
- [`v1-local-validation.md`](v1-local-validation.md): latest live Windows
  validation record.

## Operations and evidence

- [`vm-setup-checklist.md`](vm-setup-checklist.md): Windows and Sysmon setup.
- [`timeout-calibration-clock-preflight.md`](timeout-calibration-clock-preflight.md):
  timing checks used before a live suite.
- [`report-generation.md`](report-generation.md): report and evidence-manifest
  behavior.
- [`evidence-checklist.md`](evidence-checklist.md): files and checks required for
  a reviewable portfolio package.

## Scope

- [`version-boundary.md`](version-boundary.md): what V1 includes and what belongs
  in a later release.

Obsolete implementation-phase notes were removed from the release tree. Their
history remains available through Git, while these documents describe the
current supported workflow.
