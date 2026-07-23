# Phase 7 Evidence Boundary

Phase 7 is a v0.1 benign-fixture expansion. Its source code and unit tests prove
that the fixture runner exists, but they do not prove what the Windows VM will
observe.

## What Is Predicted Before VM Validation

The v0 rule depends on:

```text
Image endswith \powershell.exe
CommandLine contains -EncodedCommand
```

Before running the VM validation, the predicted fixture results are:

```text
BF0 plain command: BENIGN_NO_ALERT
BF1 encoded benign command: BENIGN_ALERT
BF2 encoded benign command: BENIGN_ALERT
```

These are predictions from the rule dependency model, not proof.

## What Proves Phase 7 Validation

The proof is the raw VM artifact set:

```text
C:\DetFuzz\benign\<suite-id>\benign-results.json
C:\DetFuzz\benign\<suite-id>\reports\evidence-manifest.json
C:\DetFuzz\benign\<suite-id>\reports\suite-report.json
C:\DetFuzz\benign\<suite-id>\reports\suite-report.md
```

The VM run is now recorded in `docs/phase-7-vm-validation.md`. If a future run
differs from this result, keep the mismatch and explain it.

## Claim Language

Pre-validation wording:

```text
Phase 7 code is complete and predicts BF1/BF2 will alert, but VM validation is
pending.
```

Validated wording:

```text
Phase 7 was run in the Windows VM and produced the recorded benign fixture
result. Raw evidence artifacts are stored under
C:\DetFuzz\benign\1a545575-f640-45b2-91de-fc0bf1ed419c.
```
