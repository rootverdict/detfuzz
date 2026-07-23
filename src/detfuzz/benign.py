from __future__ import annotations

import json
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

from detfuzz.detection import V0_ENCODED_POWERSHELL_RULE, evaluate_detection_rule
from detfuzz.models import (
    DetectionResult,
    ProcessCorrelationCriteria,
    ProcessExecution,
    SuiteContext,
    TelemetryValidation,
)
from detfuzz.payloads import encode_powershell_command
from detfuzz.report import write_report_bundle
from detfuzz.runner import create_suite, quote_windows_arg, utc_now_iso
from detfuzz.telemetry import wait_for_process_create_event


@dataclass(frozen=True)
class BenignFixtureSpec:
    fixture_id: str
    description: str
    script: str
    invocation: str
    predicted_v0_rule_match: bool


@dataclass(frozen=True)
class PreparedBenignFixture:
    fixture: BenignFixtureSpec
    suite_id: str
    fixture_path: Path
    command_line: str
    command_fragment: str


V01_BENIGN_FIXTURES: tuple[BenignFixtureSpec, ...] = (
    BenignFixtureSpec(
        fixture_id="BF0",
        description="plain PowerShell version check",
        script="$PSVersionTable.PSVersion.ToString() | Out-Null",
        invocation="plain_command",
        predicted_v0_rule_match=False,
    ),
    BenignFixtureSpec(
        fixture_id="BF1",
        description="encoded Get-Date benign command",
        script="Get-Date | Out-Null",
        invocation="encoded_command",
        predicted_v0_rule_match=True,
    ),
    BenignFixtureSpec(
        fixture_id="BF2",
        description="encoded service listing benign command",
        script="Get-Service | Select-Object -First 1 | Out-Null",
        invocation="encoded_command",
        predicted_v0_rule_match=True,
    ),
)

ALLOWED_BENIGN_FIXTURE_IDS = {
    fixture.fixture_id for fixture in V01_BENIGN_FIXTURES
}


def prepare_benign_fixture(
    suite: SuiteContext,
    fixture: BenignFixtureSpec,
    powershell_path: str = "powershell.exe",
) -> PreparedBenignFixture:
    if fixture.fixture_id not in ALLOWED_BENIGN_FIXTURE_IDS:
        raise ValueError(f"benign fixture is not allow-listed: {fixture.fixture_id}")

    fixture_path = suite.suite_path / fixture.fixture_id
    if fixture_path.exists():
        raise FileExistsError(f"fixture path already exists: {fixture_path}")
    fixture_path.mkdir(parents=True)

    command_line, command_fragment = command_line_for_benign_fixture(
        fixture,
        powershell_path=powershell_path,
    )
    return PreparedBenignFixture(
        fixture=fixture,
        suite_id=suite.suite_id,
        fixture_path=fixture_path,
        command_line=command_line,
        command_fragment=command_fragment,
    )


def command_line_for_benign_fixture(
    fixture: BenignFixtureSpec,
    powershell_path: str = "powershell.exe",
) -> tuple[str, str]:
    quoted_exe = quote_windows_arg(powershell_path)
    if fixture.invocation == "plain_command":
        quoted_script = '"' + fixture.script.replace('"', '\\"') + '"'
        return (
            f"{quoted_exe} -NoProfile -NonInteractive -Command {quoted_script}",
            "-Command",
        )
    if fixture.invocation == "encoded_command":
        encoded = encode_powershell_command(fixture.script)
        return (
            f"{quoted_exe} -NoProfile -NonInteractive -EncodedCommand {encoded}",
            "-EncodedCommand",
        )
    raise ValueError(f"unsupported benign invocation: {fixture.invocation}")


def execute_benign_fixture(
    prepared: PreparedBenignFixture,
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
        case_id=prepared.fixture.fixture_id,
        command_line=prepared.command_line,
        pid=process.pid,
        started_at_utc=started_at,
        ended_at_utc=ended_at,
        exit_code=process.returncode,
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
    )


def run_benign_fixtures(
    output_root: Path,
    host: str,
    powershell_path: str = "powershell.exe",
    timeout_seconds: int = 30,
    telemetry_timeout_seconds: int = 30,
    max_events: int = 5000,
) -> dict[str, object]:
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    if telemetry_timeout_seconds <= 0:
        raise ValueError("telemetry_timeout_seconds must be positive")
    if max_events <= 0:
        raise ValueError("max_events must be positive")

    suite = create_suite(output_root)
    evidence_root = suite.suite_path / "evidence"
    evidence_root.mkdir()

    fixture_records: list[dict[str, object]] = []

    for fixture in V01_BENIGN_FIXTURES:
        prepared = prepare_benign_fixture(
            suite,
            fixture,
            powershell_path=powershell_path,
        )
        execution = execute_benign_fixture(prepared, timeout_seconds=timeout_seconds)
        telemetry = _query_fixture_telemetry(
            prepared=prepared,
            execution=execution,
            host=host,
            max_events=max_events,
            powershell_path=powershell_path,
            telemetry_timeout_seconds=telemetry_timeout_seconds,
        )
        detection = _evaluate_fixture_detection(telemetry)
        record = _fixture_record(prepared, execution, telemetry, detection)
        fixture_records.append(record)
        _write_fixture_evidence(evidence_root, record, execution, telemetry, detection)

    suite_status, abort_reason = _benign_suite_health(fixture_records)
    results = {
        "schema_version": "1.0",
        "suite_id": suite.suite_id,
        "suite_status": suite_status,
        "abort_reason": abort_reason,
        "environment": {
            "host": host,
            "telemetry": "Microsoft-Windows-Sysmon/Operational",
            "rule_id": V0_ENCODED_POWERSHELL_RULE.rule_id,
            "rule_slug": V0_ENCODED_POWERSHELL_RULE.slug,
        },
        "cases": fixture_records,
        "notes": [
            "Generated by detfuzz run-benign-fixtures.",
            "Benign fixtures are false-positive fixtures, not bypass candidates.",
            "A BENIGN_ALERT means the v0 rule matched harmless benign activity.",
        ],
    }

    results_path = suite.suite_path / "benign-results.json"
    results_path.write_text(
        json.dumps(results, indent=2, sort_keys=True, default=str),
        encoding="utf-8",
    )
    report_paths = write_report_bundle(
        suite_results_path=results_path,
        evidence_root=evidence_root,
        output_dir=suite.suite_path / "reports",
    )

    return {
        "suite_id": suite.suite_id,
        "suite_path": str(suite.suite_path),
        "suite_status": suite_status,
        "abort_reason": abort_reason,
        "benign_results": str(results_path),
        "reports": {name: str(path) for name, path in report_paths.items()},
        "fixtures": fixture_records,
    }


def _query_fixture_telemetry(
    prepared: PreparedBenignFixture,
    execution: ProcessExecution,
    host: str,
    max_events: int,
    powershell_path: str,
    telemetry_timeout_seconds: int,
) -> TelemetryValidation:
    if execution.pid is None:
        return TelemetryValidation(False, "EXECUTION_PID_MISSING")

    criteria = ProcessCorrelationCriteria(
        host=host,
        pid=execution.pid,
        started_at_utc=execution.started_at_utc,
        ended_at_utc=execution.ended_at_utc,
        command_fragment=prepared.command_fragment,
    )
    try:
        return wait_for_process_create_event(
            criteria,
            powershell_exe=powershell_path,
            max_events=max_events,
            timeout_seconds=telemetry_timeout_seconds,
        )
    except RuntimeError:
        return TelemetryValidation(False, "TELEMETRY_QUERY_FAILED")


def _evaluate_fixture_detection(
    telemetry: TelemetryValidation,
) -> DetectionResult | None:
    if not telemetry.valid or telemetry.event is None:
        return None
    return evaluate_detection_rule(V0_ENCODED_POWERSHELL_RULE, telemetry.event)


def _fixture_record(
    prepared: PreparedBenignFixture,
    execution: ProcessExecution,
    telemetry: TelemetryValidation,
    detection: DetectionResult | None,
) -> dict[str, object]:
    detection_matched = None if detection is None else detection.matched
    return {
        "case_id": prepared.fixture.fixture_id,
        "kind": "benign_fixture",
        "description": prepared.fixture.description,
        "invocation": prepared.fixture.invocation,
        "classification": _classify_benign_fixture(execution, telemetry, detection),
        "command_line": prepared.command_line,
        "pid": execution.pid,
        "exit_code": execution.exit_code,
        "started_at_utc": execution.started_at_utc,
        "ended_at_utc": execution.ended_at_utc,
        "telemetry_valid": telemetry.valid,
        "telemetry_reason": telemetry.reason,
        "detection_matched": detection_matched,
        "detection_reason": "NOT_EVALUATED" if detection is None else detection.reason,
        "predicted_v0_rule_match": prepared.fixture.predicted_v0_rule_match,
        "prediction_met": (
            None
            if detection_matched is None
            else detection_matched == prepared.fixture.predicted_v0_rule_match
        ),
    }


def _classify_benign_fixture(
    execution: ProcessExecution,
    telemetry: TelemetryValidation,
    detection: DetectionResult | None,
) -> str:
    if execution.timed_out:
        return "BENIGN_EXECUTION_TIMEOUT"
    if execution.exit_code != 0:
        return "BENIGN_EXECUTION_FAILED"
    if not telemetry.valid:
        return "BENIGN_TELEMETRY_FAILURE"
    if detection is None:
        return "BENIGN_DETECTION_NOT_EVALUATED"
    if detection.matched:
        return "BENIGN_ALERT"
    return "BENIGN_NO_ALERT"


def _benign_suite_health(
    fixture_records: list[dict[str, object]],
) -> tuple[str, str | None]:
    unhealthy = {
        "BENIGN_EXECUTION_TIMEOUT",
        "BENIGN_EXECUTION_FAILED",
        "BENIGN_TELEMETRY_FAILURE",
        "BENIGN_DETECTION_NOT_EVALUATED",
    }
    for record in fixture_records:
        classification = str(record["classification"])
        if classification in unhealthy:
            return (
                "PIPELINE_HEALTH_FAILED",
                f"{record['case_id']}:{classification}",
            )

    mismatches = [
        str(record["case_id"])
        for record in fixture_records
        if record.get("prediction_met") is False
    ]
    if mismatches:
        return "PREDICTION_MISMATCH", "PREDICTION_MISMATCH:" + ",".join(mismatches)

    return "COMPLETED", None


def _write_fixture_evidence(
    evidence_root: Path,
    record: dict[str, object],
    execution: ProcessExecution,
    telemetry: TelemetryValidation,
    detection: DetectionResult | None,
) -> None:
    fixture_dir = evidence_root / str(record["case_id"])
    fixture_dir.mkdir(parents=True, exist_ok=True)
    _write_json(fixture_dir / "fixture-record.json", record)
    _write_json(fixture_dir / "execution.json", asdict(execution))
    _write_json(fixture_dir / "telemetry-validation.json", asdict(telemetry))
    if detection is not None:
        _write_json(fixture_dir / "detection-result.json", asdict(detection))


def _write_json(path: Path, payload: object) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, default=str),
        encoding="utf-8",
    )
