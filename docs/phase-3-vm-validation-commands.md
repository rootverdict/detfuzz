# Phase 3 VM Validation Commands

Run these commands inside the Windows 11 VM in an Administrator PowerShell.

## Run B0 and Capture PID

```powershell
$suiteId = [guid]::NewGuid().ToString()
$caseId = "B0"
$nonce = [guid]::NewGuid().ToString("N")
$markerPath = "C:\DetFuzz\runs\$suiteId\$caseId\effect.json"

$payload = @"
`$markerPath = '$markerPath'
`$parent = Split-Path -Parent `$markerPath
New-Item -ItemType Directory -Force -Path `$parent | Out-Null
`$effect = [ordered]@{
  run_id = '$suiteId'
  case_id = '$caseId'
  nonce = '$nonce'
  result = 'completed'
}
`$effect | ConvertTo-Json -Compress | Set-Content -LiteralPath `$markerPath -Encoding UTF8
"@

$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
$started = Get-Date
$process = Start-Process powershell.exe `
  -ArgumentList "-NoProfile -NonInteractive -EncodedCommand $encoded" `
  -PassThru `
  -Wait
$ended = Get-Date

[ordered]@{
  suite_id = $suiteId
  case_id = $caseId
  nonce = $nonce
  marker_path = $markerPath
  pid = $process.Id
  exit_code = $process.ExitCode
  started = $started.ToUniversalTime().ToString("o")
  ended = $ended.ToUniversalTime().ToString("o")
}
```

## Confirm Marker

```powershell
Get-Content -LiteralPath $markerPath
```

## Export Matching Sysmon Event XML

```powershell
$event = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' |
  Where-Object {
    if ($_.Id -ne 1) { return $false }

    [xml]$xml = $_.ToXml()
    $data = @{}
    foreach ($item in $xml.Event.EventData.Data) {
      $data[$item.Name] = $item.'#text'
    }

    $data.ProcessId -eq [string]$process.Id -and
    $data.Image -like "*powershell.exe" -and
    $data.CommandLine -like "*EncodedCommand*"
  } |
  Select-Object -First 1

if ($null -eq $event) {
  "NO MATCHING SYSMON EVENT FOUND"
} else {
  $event.ToXml()
}
```

## Troubleshooting Event Lookup

If the lookup returns `NO MATCHING SYSMON EVENT FOUND`, inspect the latest
PowerShell process events:

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 20 |
  Where-Object { $_.Id -eq 1 -and $_.Message -like "*powershell.exe*" } |
  Select-Object -First 5 TimeCreated, Id, Message
```

## Required Fields To Check

The exported XML should contain:

```text
UtcTime
ProcessGuid
ProcessId
Image
CommandLine
ParentImage
Hashes
```

Send the marker content, PID block, and exported XML back to Codex for Phase 3
validation.
