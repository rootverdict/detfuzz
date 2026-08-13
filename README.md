# DetFuzz

DetFuzz is an evidence-backed Windows detection-resilience test runner. It
executes safe PowerShell fixtures, correlates the resulting process telemetry,
evaluates a packaged detection rule, and produces reproducible JSON and
Markdown reports.

The current release is V1. It is deliberately focused on one encoded-command
PowerShell rule shape so that every finding can be tied to valid execution,
complete telemetry, a detection result, and retained evidence.

## V1 at a glance

DetFuzz V1 provides:

- Eight safe resilience cases: opening baseline `B0`, five valid mutations
  (`M1`-`M5`), invalid negative control `NC1`, and closing baseline `B1`.
- Marker-file validation proving that each fixture completed the expected
  harmless action with the correct suite ID, case ID, nonce, and result.
- Sysmon Event ID 1 correlation by host, PID, executable image, command line,
  SHA256 hash, and UTC execution window.
- Deterministic classification of detected cases, valid bypass candidates,
  invalid mutants, telemetry failures, and pipeline errors.
- Clock preflight and repeated timeout calibration before timing-sensitive runs.
- SHA256 evidence manifests plus machine-readable and human-readable reports.
- Three benign false-positive fixtures: plain PowerShell, encoded `Get-Date`,
  and encoded service listing.
- Export of the versioned `detfuzz-suite-report-1.0` JSON Schema for consumers
  such as SignalBudget.

A `VALID_BYPASS` result means that a known harmless fixture executed
successfully, its marker and telemetry were valid, the rule did not match, and
the closing baseline confirmed that detection was still functioning. It is a
rule-resilience finding, not a claim that the fixture is malicious.

## V1 status

V1.0.1 is complete and locally verified on 2026-08-13 with the pinned
development toolchain. It adds fail-closed suite-health, clock-status, and
report-contract hardening while preserving the same deliberately narrow V1
experiment.

The latest end-to-end run produced:

```text
Detection suite: COMPLETED
B0  DETECTED
M1  VALID_BYPASS
M2  DETECTED
M3  DETECTED
M4  DETECTED
M5  DETECTED
NC1 INVALID_MUTANT
B1  DETECTED

Benign fixtures: COMPLETED
BF0 BENIGN_NO_ALERT
BF1 BENIGN_ALERT
BF2 BENIGN_ALERT
```

All eight resilience cases and all three benign fixtures had complete
telemetry. The detection run produced a 63-file SHA256 evidence manifest; the
benign run produced a 12-file manifest. Timeout calibration passed all 20 of
20 baseline runs, and contract export passed.

The release bundle is committed as `artifacts/detfuzz-v1.0.1-release.zip`, with
its digest pinned in `artifacts/detfuzz-v1.0.1-release.sha256.txt`, so a clone
carries the evidence these results rest on. Extracted run directories and
intermediate build output stay ignored by Git.

Verifying those hashes shows the bundle is internally consistent and unmodified
relative to its recorded manifest. It does not authenticate the producer or the
host, and a clone alone cannot prove a historical Windows telemetry run.
See [`docs/v1-local-validation.md`](docs/v1-local-validation.md) and
[`docs/evidence-checklist.md`](docs/evidence-checklist.md).

## Requirements

- Windows 10 or Windows 11 test host or lab VM.
- Python 3.11 or newer.
- Windows PowerShell available as `powershell.exe`.
- Sysmon64 installed and running with Process Create events enabled and
  SHA256 hashing configured. The repository includes the recommended config at
  [`configs/sysmon-detfuzz.xml`](configs/sysmon-detfuzz.xml).
- The Windows Time service (`W32Time`) running, because clock preflight calls
  `w32tm /query /status`. The service often ships with `Manual` startup; start
  it with `Start-Service W32Time` from an elevated session if preflight reports
  `TIME_SYNC_STATUS_QUERY_FAILED`.
- An elevated session, because reading the Sysmon operational channel requires
  Administrator rights.
- `pySigma==1.4.0`; the pinned development tools are listed in
  [`constraints.txt`](constraints.txt).

Run the commands below from an Administrator PowerShell session in an isolated
lab that you own or are authorized to test.

## Setup

```powershell
py -3.12 -m venv .venv312
.\.venv312\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -c constraints.txt -e ".[dev]"
$env:PYTHONPATH = "$PWD\src"
```

If Sysmon is not installed, obtain the official Sysinternals Sysmon package,
then apply the checked-in configuration from the project root:

```powershell
.\Sysmon64.exe -accepteula -i .\configs\sysmon-detfuzz.xml
```

For an existing installation, update its configuration with:

```powershell
.\Sysmon64.exe -c .\configs\sysmon-detfuzz.xml
Get-Service Sysmon64
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 5
```

The service must be running and the operational channel must contain Process
Create events before a live suite is started.

## Run the V1 workflow

Set the output roots somewhere outside the source tree when retaining a lab
evidence package. The following commands use `C:\DetFuzz` as an example.

```powershell
$env:PYTHONPATH = "$PWD\src"
$hostName = $env:COMPUTERNAME

python -m detfuzz.cli clock-preflight

python -m detfuzz.cli calibrate-timeouts `
  --output-root C:\DetFuzz\calibration `
  --host $hostName `
  --runs 20 `
  --telemetry-probe-timeout-seconds 120 `
  --max-events 5000

$calibration = Get-ChildItem C:\DetFuzz\calibration -Directory |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 1
$calibrationResult = Join-Path $calibration.FullName 'timeout-calibration.json'

python -m detfuzz.cli run-suite `
  --output-root C:\DetFuzz\runs `
  --host $hostName `
  --max-events 5000 `
  --calibration-result $calibrationResult

python -m detfuzz.cli run-benign-fixtures `
  --output-root C:\DetFuzz\benign `
  --host $hostName `
  --max-events 5000

python -m detfuzz.cli export-contract `
  --output .\artifacts\detfuzz-suite-report-1.0.schema.json
```

Health-producing commands return a nonzero exit code when preflight,
calibration, telemetry, or suite validation fails. Their JSON result is still
written to standard output for diagnosis and automation.

For a guided demonstration of the complete V1 workflow, use:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\demo\detfuzz-demo.ps1 `
  -ProjectRoot $PWD `
  -HostName $env:COMPUTERNAME `
  -RunAll
```

After calibration has already been captured, the faster rerun is:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\demo\detfuzz-demo.ps1 `
  -ProjectRoot $PWD `
  -HostName $env:COMPUTERNAME `
  -SkipCalibration `
  -RunAll
```

The complete operator sequence and evidence review steps are documented in
[`docs/demo-runbook.md`](docs/demo-runbook.md).

## Reports and evidence

Every live detection suite creates a fresh suite directory containing:

```text
<suite-id>\suite-results.json
<suite-id>\reports\suite-report.json
<suite-id>\reports\suite-report.md
<suite-id>\reports\evidence-manifest.json
<suite-id>\evidence\...
```

The benign-fixture runner creates the same report bundle alongside
`benign-results.json`. The evidence manifest records each retained file's
relative path, size, and SHA256 digest. Reports do not invent evidence: they
hash the files produced by the run.

For an existing result and evidence directory, reports can also be rebuilt
directly:

```powershell
python -m detfuzz.cli build-report `
  --suite-results C:\DetFuzz\runs\<suite-id>\suite-results.json `
  --evidence-root C:\DetFuzz\runs\<suite-id>\evidence `
  --output-dir C:\DetFuzz\runs\<suite-id>\reports
```

The canonical contract is packaged at
[`src/detfuzz/contracts/detfuzz-suite-report-1.0.schema.json`](src/detfuzz/contracts/detfuzz-suite-report-1.0.schema.json).
Use `export-contract` to hand a copy to a downstream consumer. DetFuzz owns
the report and schema; the consumer owns its independent validation and
integration checks.

## Useful diagnostic commands

Generate safe case directories and command lines without executing them:

```powershell
python -m detfuzz.cli prepare-suite --root C:\DetFuzz\prepared
python -m detfuzz.cli prepare-benign-fixtures --root C:\DetFuzz\prepared-benign
```

Validate one saved Sysmon XML event:

```powershell
python -m detfuzz.cli evaluate-detection `
  --xml C:\DetFuzz\runs\<suite-id>\evidence\B0\matched-sysmon-event.xml
```

The `simulate-report` command is available only as a local development aid.
Its output is explicitly marked as simulated and must never be used as VM
evidence or presented as a real DetFuzz result.

## Development verification

Install the pinned toolchain and run all checks:

```powershell
python -m pip install -c constraints.txt -e ".[dev]"
python -m ruff check src tests
python -m mypy src tests
python -m unittest discover -s tests
```

The current verified result is:

```text
98 tests run; 97 passed and 1 expected dependency-path test skipped
Ruff: all checks passed
mypy: no issues found in 31 source files
```

The v1.0.1 release was validated at 95 tests; the three additional tests cover
the DOCTYPE rejection added after that release. `docs/v1-local-validation.md`
and the release manifest retain the 95/94 figures deliberately, as a
point-in-time record of the validated run rather than a claim about this tree.

## V1 boundary

V1 intentionally covers one safe encoded-command PowerShell rule shape and
the Windows Sysmon evidence path. It does not include:

- parent-process mutation or additional execution surfaces;
- multiple rule packs or broad backend comparison;
- live SIEM integrations;
- telemetry providers other than the current Sysmon flow;
- a web UI, dashboard, or distributed runner;
- automated remediation or large payload libraries.

These are possible future expansions and are tracked in
[`docs/version-boundary.md`](docs/version-boundary.md). They are not required
to operate or evaluate the current V1 release.

## Safety

DetFuzz is designed for harmless, marker-producing PowerShell fixtures in an
isolated lab. Do not run it against systems, accounts, or telemetry that you do
not own or have explicit permission to test. Keep raw evidence and reports
available for review, and do not treat a `VALID_BYPASS` result as a license to
execute arbitrary or malicious payloads.
