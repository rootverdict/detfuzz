from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from detfuzz.models import MarkerValidation, PreparedCase, ProcessExecution


def validate_marker(
    prepared: PreparedCase,
    execution: ProcessExecution | None = None,
) -> MarkerValidation:
    marker_path = prepared.marker_path

    if not marker_path.exists():
        if prepared.case.expected_marker:
            return MarkerValidation(False, False, "MARKER_MISSING")
        return MarkerValidation(True, False, "MARKER_ABSENT_AS_EXPECTED")

    if not prepared.case.expected_marker:
        return MarkerValidation(False, True, "UNEXPECTED_MARKER_PRESENT")

    try:
        content = json.loads(marker_path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError:
        return MarkerValidation(False, True, "MARKER_INVALID_JSON")

    if not isinstance(content, dict):
        return MarkerValidation(False, True, "MARKER_NOT_OBJECT")

    expected = {
        "run_id": prepared.suite_id,
        "case_id": prepared.case.case_id,
        "nonce": prepared.nonce,
        "result": "completed",
    }

    for key, expected_value in expected.items():
        if content.get(key) != expected_value:
            return MarkerValidation(
                False,
                True,
                f"MARKER_FIELD_MISMATCH:{key}",
                _string_dict(content),
            )

    if execution is not None and not _marker_was_touched_during_execution(
        marker_path, execution
    ):
        return MarkerValidation(
            False, True, "MARKER_TIMESTAMP_OUTSIDE_EXECUTION_WINDOW", _string_dict(content)
        )

    return MarkerValidation(True, True, "MARKER_VALID", _string_dict(content))


def _marker_was_touched_during_execution(
    marker_path: Path, execution: ProcessExecution
) -> bool:
    started_at = _parse_iso_utc(execution.started_at_utc)
    ended_at = _parse_iso_utc(execution.ended_at_utc)
    modified_at = datetime.fromtimestamp(marker_path.stat().st_mtime, tz=UTC)
    return started_at <= modified_at <= ended_at


def _parse_iso_utc(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _string_dict(value: dict[object, object]) -> dict[str, str]:
    return {str(key): str(item) for key, item in value.items()}
