from __future__ import annotations

import base64


def powershell_single_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def marker_payload(
    suite_id: str,
    case_id: str,
    nonce: str,
    marker_path: str,
) -> str:
    marker = powershell_single_quote(marker_path)
    run_id = powershell_single_quote(suite_id)
    case = powershell_single_quote(case_id)
    nonce_value = powershell_single_quote(nonce)

    return "\n".join(
        [
            f"$markerPath = {marker}",
            "$parent = Split-Path -Parent $markerPath",
            "New-Item -ItemType Directory -Force -Path $parent | Out-Null",
            "$effect = [ordered]@{",
            f"  run_id = {run_id}",
            f"  case_id = {case}",
            f"  nonce = {nonce_value}",
            "  result = 'completed'",
            "}",
            "$effect | ConvertTo-Json -Compress | "
            "Set-Content -LiteralPath $markerPath -Encoding UTF8",
        ]
    )


def encode_powershell_command(script: str) -> str:
    return base64.b64encode(script.encode("utf-16le")).decode("ascii")
