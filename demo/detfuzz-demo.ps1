param(
    [string]$ProjectRoot = "C:\DetFuzz\detfuzz",
    [string]$HostName = "DetFuzz-Win11-Lab",
    [string]$RunOutputRoot = "C:\DetFuzz\runs",
    [string]$CalibrationOutputRoot = "C:\DetFuzz\calibration",
    [string]$BenignOutputRoot = "C:\DetFuzz\benign",
    [string]$ContractOutput = "C:\DetFuzz\contracts\detfuzz-suite-report-1.0.schema.json",
    [int]$CalibrationRuns = 20,
    [int]$MaxEvents = 5000,
    [string]$CalibrationResult = "",
    [switch]$SkipCalibration,
    [switch]$RunSuite,
    [switch]$RunBenignFixtures,
    [switch]$ExportContract,
    [switch]$RunAll
)

$ErrorActionPreference = "Stop"

function Assert-NativeSuccess {
    param([string]$Operation)

    if ($LASTEXITCODE -ne 0) {
        throw "$Operation failed with exit code $LASTEXITCODE."
    }
}

Set-Location -LiteralPath $ProjectRoot
$env:PYTHONPATH = "src"

Write-Host ""
Write-Host "== DetFuzz demo preflight =="
Get-Service Sysmon64 | Select-Object Status, Name, DisplayName

Write-Host ""
Write-Host "== Clock preflight =="
python -m detfuzz.cli clock-preflight
Assert-NativeSuccess "Clock preflight"

$shouldRunSuite = $RunSuite -or $RunAll
$shouldRunBenign = $RunBenignFixtures -or $RunAll
$shouldExportContract = $ExportContract -or $RunAll

if ($shouldRunSuite -and -not $SkipCalibration) {
    Write-Host ""
    Write-Host "== Timeout calibration =="
    $calibrationOutput = python -m detfuzz.cli calibrate-timeouts `
        --output-root $CalibrationOutputRoot `
        --host $HostName `
        --runs $CalibrationRuns `
        --max-events $MaxEvents
    Assert-NativeSuccess "Timeout calibration"
    $calibrationOutput
    $calibration = $calibrationOutput | ConvertFrom-Json
    if ($calibration.status -ne "PASS") {
        throw "Timeout calibration reported status $($calibration.status)."
    }
    $CalibrationResult = $calibration.output_path
}

if ($shouldRunSuite) {
    Write-Host ""
    Write-Host "== Full V1 suite =="
    $suiteArgs = @(
        "-m", "detfuzz.cli", "run-suite",
        "--output-root", $RunOutputRoot,
        "--host", $HostName,
        "--max-events", $MaxEvents
    )
    if ($CalibrationResult) {
        $suiteArgs += @("--calibration-result", $CalibrationResult)
    }
    python @suiteArgs
    Assert-NativeSuccess "DetFuzz suite"
}

if ($shouldRunBenign) {
    Write-Host ""
    Write-Host "== V1 benign fixtures =="
    python -m detfuzz.cli run-benign-fixtures `
        --output-root $BenignOutputRoot `
        --host $HostName `
        --max-events $MaxEvents
    Assert-NativeSuccess "DetFuzz benign fixtures"
}

if ($shouldExportContract) {
    Write-Host ""
    Write-Host "== V1 report contract =="
    python -m detfuzz.cli export-contract --output $ContractOutput
    Assert-NativeSuccess "DetFuzz contract export"
}

if (-not $shouldRunSuite -and -not $shouldRunBenign -and -not $shouldExportContract) {
    Write-Host ""
    Write-Host "No workflow selected. Re-run with -RunAll for the complete V1 demo."
}
