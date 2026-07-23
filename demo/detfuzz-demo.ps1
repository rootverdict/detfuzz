param(
    [string]$ProjectRoot = "C:\DetFuzz\detfuzz",
    [string]$HostName = "DetFuzz-Win11-Lab",
    [string]$RunOutputRoot = "C:\DetFuzz\runs",
    [string]$CalibrationOutputRoot = "C:\DetFuzz\calibration",
    [int]$CalibrationRuns = 20,
    [int]$MaxEvents = 5000,
    [string]$CalibrationResult = "",
    [switch]$SkipCalibration,
    [switch]$RunSuite
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

if (-not $SkipCalibration) {
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

if ($RunSuite) {
    Write-Host ""
    Write-Host "== Full v0 suite =="
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
} else {
    Write-Host ""
    Write-Host "Full suite not run. Re-run with -RunSuite when ready."
}
