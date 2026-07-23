from __future__ import annotations

import json
import shutil
from dataclasses import asdict
from pathlib import Path
from typing import Any

from detfuzz.calibration import run_clock_preflight
from detfuzz.cases import V0_CASES
from detfuzz.classifier import classify_case, finalize_candidate
from detfuzz.detection import (
    V0_ENCODED_POWERSHELL_RULE,
    V0_SIGMA_RULE_PATH,
    evaluate_detection_rule,
)
from detfuzz.identity import expected_executable_sha256, validate_executable_identity
from detfuzz.models import (
    CaseObservation,
    Classification,
    DetectionResult,
    ExecutableIdentityValidation,
    MarkerValidation,
    PreparedCase,
    ProcessCorrelationCriteria,
    ProcessExecution,
    TelemetryValidation,
)
from detfuzz.oracle import validate_marker
from detfuzz.report import write_report_bundle
from detfuzz.runner import create_suite, execute_prepared_case, prepare_case
from detfuzz.telemetry import wait_for_process_create_event


def run_v0_suite(
    output_root: Path,
    host: str,
    powershell_path: str = "powershell.exe",
    timeout_seconds: int = 30,
    telemetry_timeout_seconds: int = 30,
    max_events: int = 5000,
    calibration_result_path: Path | None = None,
) -> dict[str, object]:
    calibration = _load_calibration_result(calibration_result_path)
    if calibration is not None:
        timeout_seconds = int(calibration["selected_timeouts_seconds"]["process"])
        telemetry_timeout_seconds = int(
            calibration["selected_timeouts_seconds"].get(
                "telemetry_query",
                calibration["selected_timeouts_seconds"].get("telemetry"),
            )
        )
    suite = create_suite(output_root)
    evidence_root = suite.suite_path / "evidence"
    evidence_root.mkdir()

    case_records: list[dict[str, object]] = []
    preliminary: dict[str, Classification] = {}
    suite_status = "COMPLETED"
    abort_reason: str | None = None
    preflight = run_clock_preflight(powershell_exe=powershell_path)
    expected_hash = expected_executable_sha256(powershell_path)

    if preflight["status"] != "PASS":
        suite_status = "PREFLIGHT_FAILED"
        abort_reason = str(preflight["reason"])
    elif expected_hash is None:
        suite_status = "PREFLIGHT_FAILED"
        abort_reason = "EXPECTED_EXECUTABLE_HASH_UNAVAILABLE"
    else:
        try:
            for case in V0_CASES:
                prepared = prepare_case(suite, case, powershell_path=powershell_path)
                execution = execute_prepared_case(prepared, timeout_seconds=timeout_seconds)
                marker = validate_marker(prepared, execution)
                telemetry = _query_telemetry(
                    prepared,
                    execution,
                    host,
                    max_events,
                    telemetry_timeout_seconds=telemetry_timeout_seconds,
                    powershell_path=powershell_path,
                )
                identity = validate_executable_identity(telemetry, expected_hash)
                detection = _evaluate_detection(telemetry)
                observation = _build_observation(
                    prepared=prepared,
                    execution=execution,
                    marker=marker,
                    telemetry=telemetry,
                    identity=identity,
                    detection=detection,
                )
                classification = classify_case(observation)
                preliminary[case.case_id] = classification

                record = _case_record(
                    prepared=prepared,
                    execution=execution,
                    marker=marker,
                    telemetry=telemetry,
                    identity=identity,
                    detection=detection,
                    classification=classification,
                )
                case_records.append(record)
                _write_case_evidence(
                    evidence_root,
                    record,
                    prepared,
                    execution,
                    marker,
                    telemetry,
                    identity,
                    detection,
                )

                if case.case_id == "B0" and classification != Classification.DETECTED:
                    suite_status = "ABORTED"
                    abort_reason = "OPENING_BASELINE_NOT_DETECTED"
                    break
        except Exception as error:  # noqa: BLE001 - guarantees partial report.
            suite_status = "ABORTED"
            abort_reason = f"UNEXPECTED_ERROR:{type(error).__name__}:{error}"

    closing = preliminary.get("B1", Classification.INDETERMINATE)
    finalized_cases = [
        _finalize_case_record(record, closing)
        for record in case_records
    ]
    if suite_status == "COMPLETED":
        suite_status, abort_reason = _suite_health(finalized_cases)

    suite_results = {
        "schema_version": "1.0",
        "suite_id": suite.suite_id,
        "suite_status": suite_status,
        "abort_reason": abort_reason,
        "environment": {
            "host": host,
            "telemetry": "Microsoft-Windows-Sysmon/Operational",
            "rule_id": V0_ENCODED_POWERSHELL_RULE.rule_id,
            "rule_slug": V0_ENCODED_POWERSHELL_RULE.slug,
            "rule_source": str(V0_SIGMA_RULE_PATH),
            "expected_powershell_sha256": expected_hash,
            "preflight": preflight,
            "calibration": calibration,
            "process_timeout_seconds": timeout_seconds,
            "telemetry_timeout_seconds": telemetry_timeout_seconds,
        },
        "cases": finalized_cases,
        "notes": [
            "Generated by detfuzz run-suite.",
            "Candidate bypasses are finalized only after B1 succeeds.",
        ],
    }

    suite_results_path = suite.suite_path / "suite-results.json"
    suite_results_path.write_text(
        json.dumps(suite_results, indent=2, sort_keys=True, default=str),
        encoding="utf-8",
    )
    report_paths = write_report_bundle(
        suite_results_path=suite_results_path,
        evidence_root=evidence_root,
        output_dir=suite.suite_path / "reports",
    )

    return {
        "suite_id": suite.suite_id,
        "suite_path": str(suite.suite_path),
        "suite_status": suite_status,
        "abort_reason": abort_reason,
        "suite_results": str(suite_results_path),
        "reports": {name: str(path) for name, path in report_paths.items()},
        "cases": finalized_cases,
    }


def _query_telemetry(
    prepared: PreparedCase,
    execution: ProcessExecution,
    host: str,
    max_events: int,
    telemetry_timeout_seconds: int = 30,
    powershell_path: str = "powershell.exe",
) -> TelemetryValidation:
    if execution.pid is None:
        return TelemetryValidation(False, "EXECUTION_PID_MISSING")

    criteria = ProcessCorrelationCriteria(
        host=host,
        pid=execution.pid,
        started_at_utc=execution.started_at_utc,
        ended_at_utc=execution.ended_at_utc,
        command_fragment=_command_fragment_for_case(prepared.case.case_id),
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


def _evaluate_detection(telemetry: TelemetryValidation) -> DetectionResult | None:
    if not telemetry.valid or telemetry.event is None:
        return None
    try:
        return evaluate_detection_rule(V0_ENCODED_POWERSHELL_RULE, telemetry.event)
    except Exception as error:  # noqa: BLE001 - classification preserves the failure.
        return DetectionResult(
            rule_id=V0_ENCODED_POWERSHELL_RULE.rule_id,
            matched=False,
            reason=f"DETECTION_ENGINE_ERROR:{type(error).__name__}:{error}",
            error=True,
        )


def _build_observation(
    prepared: PreparedCase,
    execution: ProcessExecution,
    marker: MarkerValidation,
    telemetry: TelemetryValidation,
    identity: ExecutableIdentityValidation,
    detection: DetectionResult | None,
) -> CaseObservation:
    return CaseObservation(
        case_id=prepared.case.case_id,
        infrastructure_error=execution.timed_out,
        exit_code=execution.exit_code,
        marker_valid=marker.valid,
        executable_identity_valid=identity.valid,
        telemetry_received=telemetry.event is not None,
        required_fields_present=telemetry.valid,
        detection_engine_error=False if detection is None else detection.error,
        rule_matched=False if detection is None else detection.matched,
        details={
            "marker_reason": marker.reason,
            "telemetry_reason": telemetry.reason,
            "executable_identity_reason": identity.reason,
            "detection_reason": "NOT_EVALUATED" if detection is None else detection.reason,
        },
    )


def _case_record(
    prepared: PreparedCase,
    execution: ProcessExecution,
    marker: MarkerValidation,
    telemetry: TelemetryValidation,
    identity: ExecutableIdentityValidation,
    detection: DetectionResult | None,
    classification: Classification,
) -> dict[str, object]:
    return {
        "case_id": prepared.case.case_id,
        "kind": prepared.case.kind.value,
        "transformation": prepared.case.transformation,
        "classification": classification.value,
        "preliminary_classification": classification.value,
        "command_line": prepared.command_line,
        "marker_path": str(prepared.marker_path),
        "pid": execution.pid,
        "exit_code": execution.exit_code,
        "started_at_utc": execution.started_at_utc,
        "ended_at_utc": execution.ended_at_utc,
        "marker_valid": marker.valid,
        "marker_reason": marker.reason,
        "telemetry_valid": telemetry.valid,
        "telemetry_reason": telemetry.reason,
        "executable_identity_valid": identity.valid,
        "executable_identity_reason": identity.reason,
        "expected_executable_sha256": identity.expected_sha256,
        "observed_executable_sha256": identity.observed_sha256,
        "detection_matched": None if detection is None else detection.matched,
        "rule_id": None if detection is None else detection.rule_id,
        "detection_reason": "NOT_EVALUATED" if detection is None else detection.reason,
    }


def _finalize_case_record(
    record: dict[str, object],
    closing: Classification,
) -> dict[str, object]:
    preliminary = Classification(str(record["preliminary_classification"]))
    final = finalize_candidate(preliminary, closing)
    updated = dict(record)
    updated["classification"] = final.value
    return updated


def _write_case_evidence(
    evidence_root: Path,
    record: dict[str, object],
    prepared: PreparedCase,
    execution: ProcessExecution,
    marker: MarkerValidation,
    telemetry: TelemetryValidation,
    identity: ExecutableIdentityValidation,
    detection: DetectionResult | None,
) -> None:
    case_dir = evidence_root / prepared.case.case_id
    case_dir.mkdir(parents=True, exist_ok=True)
    _write_json(case_dir / "case-record.json", record)
    _write_json(case_dir / "execution.json", asdict(execution))
    _write_json(case_dir / "marker-validation.json", asdict(marker))
    _write_json(case_dir / "telemetry-validation.json", asdict(telemetry))
    _write_json(case_dir / "executable-identity.json", asdict(identity))
    if detection is not None:
        _write_json(case_dir / "detection-result.json", asdict(detection))
    if telemetry.event is not None and telemetry.event.raw_xml:
        (case_dir / "matched-sysmon-event.xml").write_text(
            telemetry.event.raw_xml,
            encoding="utf-8",
        )
    if prepared.marker_path.exists():
        shutil.copy2(prepared.marker_path, case_dir / "effect.json")


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")


def _command_fragment_for_case(case_id: str) -> str:
    if case_id == "M1":
        return "-enc"
    return "EncodedCommand"


def _suite_health(cases: list[dict[str, object]]) -> tuple[str, str | None]:
    by_id = {str(case["case_id"]): case for case in cases}
    if by_id.get("NC1", {}).get("classification") != Classification.INVALID_MUTANT.value:
        return "PIPELINE_HEALTH_FAILED", "NEGATIVE_CONTROL_NOT_INVALID"
    if by_id.get("B1", {}).get("classification") != Classification.DETECTED.value:
        return "PIPELINE_HEALTH_FAILED", "CLOSING_BASELINE_NOT_DETECTED"
    return "COMPLETED", None


def _load_calibration_result(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    if payload.get("status") != "PASS":
        raise ValueError("calibration result must have status PASS")
    selected = payload.get("selected_timeouts_seconds")
    if not isinstance(selected, dict):
        raise ValueError("calibration result missing selected_timeouts_seconds")
    if "process" not in selected:
        raise ValueError("calibration result missing process timeout")
    if "telemetry_query" not in selected and "telemetry" not in selected:
        raise ValueError("calibration result missing telemetry timeout")
    return payload
