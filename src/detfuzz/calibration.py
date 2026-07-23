from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from statistics import median

from detfuzz.cases import V0_CASES
from detfuzz.detection import V0_ENCODED_POWERSHELL_RULE, evaluate_detection_rule
from detfuzz.models import (
    ProcessCorrelationCriteria,
    ProcessExecution,
    SuiteContext,
    TelemetryValidation,
)
from detfuzz.oracle import validate_marker
from detfuzz.runner import create_suite, execute_prepared_case, prepare_case
from detfuzz.telemetry import wait_for_process_create_event

MAXIMUM_STABLE_TIMEOUT_SECONDS = 120


def run_clock_preflight(
    powershell_exe: str = "powershell.exe",
    command_runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, object]:
    runner_started_utc = datetime.now(UTC)
    try:
        completed = command_runner(
            [
                powershell_exe,
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "(Get-Date).ToUniversalTime().ToString('o')",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as error:
        return {
            "status": "PREFLIGHT_FAILED",
            "reason": f"CLOCK_QUERY_ERROR:{type(error).__name__}:{error}",
            "runner_utc": runner_started_utc.isoformat(),
            "target_utc": None,
            "offset_ms": None,
        }
    runner_ended_utc = datetime.now(UTC)
    runner_utc = runner_started_utc + (runner_ended_utc - runner_started_utc) / 2

    if completed.returncode != 0:
        return {
            "status": "PREFLIGHT_FAILED",
            "reason": "CLOCK_QUERY_FAILED",
            "runner_utc": runner_utc.isoformat(),
            "target_utc": None,
            "offset_ms": None,
        }

    try:
        sync_status = _query_time_sync_status(powershell_exe, command_runner)
    except OSError as error:
        return {
            "status": "PREFLIGHT_FAILED",
            "reason": f"TIME_SYNC_QUERY_ERROR:{type(error).__name__}:{error}",
            "runner_utc": runner_utc.isoformat(),
            "target_utc": completed.stdout.strip() or None,
            "offset_ms": None,
        }
    if not sync_status["synchronized"]:
        return {
            "status": "PREFLIGHT_FAILED",
            "reason": sync_status["reason"],
            "runner_utc": runner_utc.isoformat(),
            "target_utc": None,
            "offset_ms": None,
            "time_sync_source": sync_status["source"],
        }

    target_text = completed.stdout.strip()
    try:
        target_utc = _parse_utc(target_text)
    except ValueError:
        return {
            "status": "PREFLIGHT_FAILED",
            "reason": "CLOCK_PARSE_FAILED",
            "runner_utc": runner_utc.isoformat(),
            "target_utc": target_text,
            "offset_ms": None,
        }

    offset_ms = int((target_utc - runner_utc).total_seconds() * 1000)
    status = "PASS" if abs(offset_ms) <= 2000 else "PREFLIGHT_FAILED"
    reason = "CLOCK_SYNC_OK" if status == "PASS" else "CLOCK_UNSYNCED"
    return {
        "status": status,
        "reason": reason,
        "runner_utc": runner_utc.isoformat(),
        "target_utc": target_utc.isoformat(),
        "offset_ms": offset_ms,
        "maximum_allowed_absolute_offset_ms": 2000,
        "time_sync_source": sync_status["source"],
    }


def calibrate_timeouts(
    output_root: Path,
    host: str,
    runs: int = 20,
    powershell_path: str = "powershell.exe",
    process_timeout_seconds: int = 30,
    telemetry_probe_timeout_seconds: int = MAXIMUM_STABLE_TIMEOUT_SECONDS,
    max_events: int = 5000,
) -> dict[str, object]:
    if runs <= 0:
        raise ValueError("runs must be positive")
    if process_timeout_seconds <= 0:
        raise ValueError("process_timeout_seconds must be positive")
    if telemetry_probe_timeout_seconds <= 0:
        raise ValueError("telemetry_probe_timeout_seconds must be positive")
    if max_events <= 0:
        raise ValueError("max_events must be positive")

    suite = create_suite(output_root)
    baseline = next(case for case in V0_CASES if case.case_id == "B0")
    observations: list[dict[str, object]] = []

    for index in range(1, runs + 1):
        run_context = SuiteContext(
            suite_id=suite.suite_id,
            suite_path=suite.suite_path / f"calibration-{index}",
        )
        prepared = prepare_case(run_context, baseline, powershell_path=powershell_path)
        execution = execute_prepared_case(prepared, timeout_seconds=process_timeout_seconds)
        marker = validate_marker(prepared, execution)

        telemetry_query_started = datetime.now(UTC)
        telemetry = _query_calibration_telemetry(
            prepared_case_id="B0",
            execution=execution,
            host=host,
            max_events=max_events,
            telemetry_timeout_seconds=telemetry_probe_timeout_seconds,
        )
        telemetry_query_ended = datetime.now(UTC)
        detection_matched = _calibration_detection_matched(telemetry)

        process_duration_ms = _duration_ms(execution.started_at_utc, execution.ended_at_utc)
        telemetry_latency_ms = _telemetry_latency_ms(execution, telemetry)
        telemetry_query_duration_ms = int(
            (telemetry_query_ended - telemetry_query_started).total_seconds() * 1000
        )

        observations.append(
            {
                "run": index,
                "case_id": "B0",
                "pid": execution.pid,
                "exit_code": execution.exit_code,
                "marker_valid": marker.valid,
                "marker_reason": marker.reason,
                "telemetry_valid": telemetry.valid,
                "telemetry_reason": telemetry.reason,
                "detection_matched": detection_matched,
                "process_duration_ms": process_duration_ms,
                "telemetry_latency_ms": telemetry_latency_ms,
                "telemetry_query_duration_ms": telemetry_query_duration_ms,
            }
        )

    process_values = _integer_measurements(observations, "process_duration_ms")
    telemetry_values = _integer_measurements(observations, "telemetry_latency_ms")
    query_values = _integer_measurements(
        observations,
        "telemetry_query_duration_ms",
    )

    selected_telemetry_timeout = _selected_timeout_seconds(telemetry_values)
    selected_process_timeout = _selected_timeout_seconds(process_values)
    selected_query_timeout = _selected_timeout_seconds(query_values)
    healthy_observations = bool(observations) and all(
        item["exit_code"] == 0
        and item["marker_valid"] is True
        and item["telemetry_valid"] is True
        and item["detection_matched"] is True
        for item in observations
    )
    stable = healthy_observations and all(
        value <= MAXIMUM_STABLE_TIMEOUT_SECONDS
        for value in (
            selected_telemetry_timeout,
            selected_process_timeout,
            selected_query_timeout,
        )
    )

    result = {
        "schema_version": "1.0",
        "suite_id": suite.suite_id,
        "runs_requested": runs,
        "runs_completed": len(observations),
        "host": host,
        "status": "PASS" if stable else "CALIBRATION_FAILED",
        "reason": "CALIBRATION_HEALTHY" if stable else "CALIBRATION_HEALTH_CHECK_FAILED",
        "selection_method": "max(30s, observed_max + 10s)",
        "maximum_stable_timeout_seconds": MAXIMUM_STABLE_TIMEOUT_SECONDS,
        "telemetry_probe_timeout_seconds": telemetry_probe_timeout_seconds,
        "process_duration_ms": _summary(process_values),
        "telemetry_latency_ms": _summary(telemetry_values),
        "telemetry_query_duration_ms": _summary(query_values),
        "selected_timeouts_seconds": {
            "process": selected_process_timeout,
            "telemetry": selected_telemetry_timeout,
            "telemetry_query": selected_query_timeout,
        },
        "observations": observations,
    }
    output_path = suite.suite_path / "timeout-calibration.json"
    output_path.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    result["output_path"] = str(output_path)
    return result


def _query_calibration_telemetry(
    prepared_case_id: str,
    execution: ProcessExecution,
    host: str,
    max_events: int,
    telemetry_timeout_seconds: int,
) -> TelemetryValidation:
    if execution.pid is None:
        return TelemetryValidation(False, "EXECUTION_PID_MISSING")
    criteria = ProcessCorrelationCriteria(
        host=host,
        pid=execution.pid,
        started_at_utc=execution.started_at_utc,
        ended_at_utc=execution.ended_at_utc,
        command_fragment="EncodedCommand",
    )
    try:
        return wait_for_process_create_event(
            criteria,
            max_events=max_events,
            timeout_seconds=telemetry_timeout_seconds,
        )
    except RuntimeError:
        return TelemetryValidation(False, "TELEMETRY_QUERY_FAILED")


def _calibration_detection_matched(telemetry: TelemetryValidation) -> bool:
    if not telemetry.valid or telemetry.event is None:
        return False
    return evaluate_detection_rule(V0_ENCODED_POWERSHELL_RULE, telemetry.event).matched


def _query_time_sync_status(
    powershell_exe: str,
    command_runner: Callable[..., subprocess.CompletedProcess[str]],
) -> dict[str, object]:
    completed = command_runner(
        [
            powershell_exe,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "w32tm /query /status",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        return {
            "synchronized": False,
            "reason": "TIME_SYNC_STATUS_QUERY_FAILED",
            "source": None,
        }
    stdout = completed.stdout
    source = _extract_w32tm_source(stdout)
    if "Leap Indicator: 3" in stdout or "not synchronized" in stdout.lower():
        return {
            "synchronized": False,
            "reason": "TIME_SYNC_NOT_SYNCHRONIZED",
            "source": source,
        }
    if source == "Local CMOS Clock":
        return {
            "synchronized": False,
            "reason": "TIME_SYNC_LOCAL_CMOS_CLOCK",
            "source": source,
        }
    return {"synchronized": True, "reason": "TIME_SYNC_OK", "source": source}


def _extract_w32tm_source(stdout: str) -> str | None:
    for line in stdout.splitlines():
        if line.startswith("Source:"):
            return line.split(":", 1)[1].strip()
    return None


def _duration_ms(started: str, ended: str) -> int:
    return int((_parse_utc(ended) - _parse_utc(started)).total_seconds() * 1000)


def _telemetry_latency_ms(
    execution: ProcessExecution,
    telemetry: TelemetryValidation,
) -> int | None:
    if telemetry.event is None:
        return None
    return int(
        (_parse_utc(telemetry.event.utc_time) - _parse_utc(execution.started_at_utc))
        .total_seconds()
        * 1000
    )


def _selected_timeout_seconds(values: list[int]) -> int:
    if not values:
        return MAXIMUM_STABLE_TIMEOUT_SECONDS
    return max(30, int(max(values) / 1000) + 10)


def _integer_measurements(
    observations: list[dict[str, object]],
    key: str,
) -> list[int]:
    values: list[int] = []
    for observation in observations:
        value = observation.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            values.append(int(value))
    return values


def _summary(values: list[int]) -> dict[str, int | None]:
    if not values:
        return {"minimum": None, "median": None, "maximum": None}
    return {
        "minimum": min(values),
        "median": int(median(values)),
        "maximum": max(values),
    }


def _parse_utc(value: str) -> datetime:
    normalized = value.strip().replace("Z", "+00:00")
    if " " in normalized and "T" not in normalized:
        normalized = normalized.replace(" ", "T") + "+00:00"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)
