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

Set-Location -LiteralPath $ProjectRoot
$env:PYTHONPATH = "src"

Write-Host ""
Write-Host "== DetFuzz demo preflight =="
Get-Service Sysmon64 | Select-Object Status, Name, DisplayName

Write-Host ""
Write-Host "== Clock preflight =="
python -m detfuzz.cli clock-preflight

if (-not $SkipCalibration) {
    Write-Host ""
    Write-Host "== Timeout calibration =="
    $calibrationOutput = python -m detfuzz.cli calibrate-timeouts `
        --output-root $CalibrationOutputRoot `
        --host $HostName `
        --runs $CalibrationRuns `
        --max-events $MaxEvents
    $calibrationOutput
    $calibration = $calibrationOutput | ConvertFrom-Json
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
} else {
    Write-Host ""
    Write-Host "Full suite not run. Re-run with -RunSuite when ready."
}
