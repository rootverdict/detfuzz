# Windows Lab Setup Checklist

Use an isolated Windows host or VM that you own or are explicitly authorized to
test.

## Recommended lab

- Windows 10 or Windows 11, 64-bit.
- 2 or more CPU cores.
- 4-8 GB RAM.
- 60 GB disk.
- NAT networking.
- Administrator PowerShell.
- Python 3.11 or newer.

## Sysmon

Copy the official Sysinternals `Sysmon64.exe` to a known tools directory, then
install the checked-in configuration:

```powershell
$sysmonPath = 'C:\Tools\DetFuzzSysmon\Sysmon64.exe'
& $sysmonPath -accepteula -i C:\DetFuzz\detfuzz\configs\sysmon-detfuzz.xml
Get-Service Sysmon64
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 5
```

For an existing installation, apply configuration changes with `-c` instead of
`-i`. The configuration must record PowerShell Process Create events and include
SHA256 hashes.

## Python environment

```powershell
cd C:\DetFuzz\detfuzz
py -3.12 -m venv .venv312
.\.venv312\Scripts\Activate.ps1
python -m pip install -c constraints.txt -e ".[dev]"
$env:PYTHONPATH = "$PWD\src"
```

## Validation checklist

- `Get-Service Sysmon64` reports `Running`.
- Recent Sysmon Event ID 1 records are visible.
- `clock-preflight` returns `PASS`.
- `calibrate-timeouts` completes all requested runs and returns `PASS`.
- `run-suite` writes a complete V1 report and evidence manifest.
- `run-benign-fixtures` writes a complete benign report and evidence manifest.
- `export-contract` writes the canonical schema.
- Raw evidence is retained with the release bundle and its pinned digest.

Take a clean VM snapshot after installation and another after the complete V1
workflow has been validated.
