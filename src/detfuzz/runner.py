from __future__ import annotations

import secrets
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path

from detfuzz.cases import V0_CASES
from detfuzz.models import CaseSpec, PreparedCase, ProcessExecution, SuiteContext
from detfuzz.payloads import encode_powershell_command, marker_payload

ALLOWED_CASE_IDS = {case.case_id for case in V0_CASES}


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def create_suite(root: Path) -> SuiteContext:
    suite_id = str(uuid.uuid4())
    suite_path = root.resolve() / suite_id
    if suite_path.exists():
        raise FileExistsError(f"suite path already exists: {suite_path}")
    suite_path.mkdir(parents=True)
    return SuiteContext(suite_id=suite_id, suite_path=suite_path)


def prepare_case(
    suite: SuiteContext,
    case: CaseSpec,
    powershell_path: str = "powershell.exe",
) -> PreparedCase:
    if case.case_id not in ALLOWED_CASE_IDS:
        raise ValueError(f"case is not allow-listed: {case.case_id}")

    case_path = suite.suite_path / case.case_id
    marker_path = case_path / "effect.json"
    nonce = secrets.token_hex(16)

    if case_path.exists():
        raise FileExistsError(f"case path already exists: {case_path}")

    case_path.mkdir(parents=True)

    encoded_payload = _encoded_payload_for_case(
        suite_id=suite.suite_id,
        case_id=case.case_id,
        nonce=nonce,
        marker_path=marker_path,
    )
    command_line = command_line_for_case(case, encoded_payload, powershell_path)

    return PreparedCase(
        case=case,
        suite_id=suite.suite_id,
        case_path=case_path,
        marker_path=marker_path,
        nonce=nonce,
        encoded_payload=encoded_payload,
        command_line=command_line,
    )


def command_line_for_case(
    case: CaseSpec,
    encoded_payload: str,
    powershell_path: str = "powershell.exe",
) -> str:
    quoted_exe = quote_windows_arg(powershell_path)

    match case.case_id:
        case "B0" | "B1":
            return f"{quoted_exe} -NoProfile -NonInteractive -EncodedCommand {encoded_payload}"
        case "M1":
            return f"{quoted_exe} -NoProfile -NonInteractive -enc {encoded_payload}"
        case "M2":
            return f"{quoted_exe} -NoProfile -NonInteractive -eNcOdEdCoMmAnD {encoded_payload}"
        case "M3":
            return (
                f"{quoted_exe}    -NoProfile    -NonInteractive    "
                f"-EncodedCommand    {encoded_payload}"
            )
        case "M4":
            return (
                f"{quoted_exe} -NoProfile -NonInteractive "
                f'"-EncodedCommand" {encoded_payload}'
            )
        case "M5":
            return f"{quoted_exe} -NonInteractive -NoProfile -EncodedCommand {encoded_payload}"
        case "NC1":
            return f"{quoted_exe} -NoProfile -NonInteractive -EncodedCommand !!!invalid-base64!!!"
        case _:
            raise ValueError(f"case is not allow-listed: {case.case_id}")


def execute_prepared_case(
    prepared: PreparedCase,
    timeout_seconds: int = 30,
) -> ProcessExecution:
    started_at = utc_now_iso()
    process = subprocess.Popen(
        prepared.command_line,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        stdout, stderr = process.communicate()

    ended_at = utc_now_iso()

    return ProcessExecution(
        case_id=prepared.case.case_id,
        command_line=prepared.command_line,
        pid=process.pid,
        started_at_utc=started_at,
        ended_at_utc=ended_at,
        exit_code=process.returncode,
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
    )


def quote_windows_arg(value: str) -> str:
    if not value or any(character.isspace() for character in value):
        return '"' + value.replace('"', '\\"') + '"'
    return value


def _encoded_payload_for_case(
    suite_id: str,
    case_id: str,
    nonce: str,
    marker_path: Path,
) -> str:
    script = marker_payload(
        suite_id=suite_id,
        case_id=case_id,
        nonce=nonce,
        marker_path=str(marker_path),
    )
    return encode_powershell_command(script)
