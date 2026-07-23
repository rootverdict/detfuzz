from __future__ import annotations

import json
import shutil
from datetime import datetime
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

SUITE_REPORT_SCHEMA_VERSION = "1.0"
SUITE_REPORT_SCHEMA_PATH = (
    Path(__file__).resolve().parent
    / "contracts"
    / "detfuzz-suite-report-1.0.schema.json"
)


class SuiteReportContractError(ValueError):
    pass


def load_suite_report_schema() -> dict[str, Any]:
    payload = json.loads(SUITE_REPORT_SCHEMA_PATH.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise SuiteReportContractError("suite report schema must be a JSON object")
    return payload


def export_suite_report_schema(output: Path) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(SUITE_REPORT_SCHEMA_PATH, output)
    return output


def validate_suite_report_shape(report: dict[str, Any]) -> None:
    if not isinstance(report, dict):
        raise SuiteReportContractError("suite report must be a JSON object")

    required = {
        "schema_version",
        "generated_at_utc",
        "suite_id",
        "suite_status",
        "environment",
        "case_count",
        "classification_counts",
        "cases",
        "evidence_manifest",
    }
    missing = sorted(required - report.keys())
    if missing:
        raise SuiteReportContractError(
            "suite report missing required fields: " + ", ".join(missing)
        )
    if report["schema_version"] != SUITE_REPORT_SCHEMA_VERSION:
        raise SuiteReportContractError(
            f"unsupported suite report schema_version: {report['schema_version']}"
        )
    if not _is_date_time(report["generated_at_utc"]):
        raise SuiteReportContractError(
            "generated_at_utc must be an ISO-8601 date-time string"
        )
    if not isinstance(report["suite_id"], str) or not report["suite_id"]:
        raise SuiteReportContractError("suite_id must be a non-empty string")
    if (
        not isinstance(report["suite_status"], str)
        or not report["suite_status"].strip()
    ):
        raise SuiteReportContractError("suite_status must be a non-empty string")
    abort_reason = report.get("abort_reason")
    if abort_reason is not None and not isinstance(abort_reason, str):
        raise SuiteReportContractError("abort_reason must be a string or null")
    environment = report["environment"]
    if not isinstance(environment, dict):
        raise SuiteReportContractError("environment must be an object")
    for field in ("host", "telemetry"):
        if field in environment and not isinstance(environment[field], str):
            raise SuiteReportContractError(
                f"environment.{field} must be a string"
            )
    for field in ("rule_id", "rule_slug"):
        if field in environment and (
            not isinstance(environment[field], str)
            or not environment[field]
        ):
            raise SuiteReportContractError(
                f"environment.{field} must be a non-empty string"
            )

    case_count = report["case_count"]
    if (
        not isinstance(case_count, int)
        or isinstance(case_count, bool)
        or case_count < 0
    ):
        raise SuiteReportContractError("case_count must be a non-negative integer")

    cases = report["cases"]
    if not isinstance(cases, list):
        raise SuiteReportContractError("cases must be a list")
    if case_count != len(cases):
        raise SuiteReportContractError("case_count must equal the number of cases")

    observed_counts: dict[str, int] = {}
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            raise SuiteReportContractError(f"case {index} must be an object")
        for field in ("case_id", "classification"):
            if not isinstance(case.get(field), str) or not case[field]:
                raise SuiteReportContractError(
                    f"case {index}.{field} must be a non-empty string"
                )
        classification = case["classification"]
        observed_counts[classification] = observed_counts.get(classification, 0) + 1
        _validate_optional_case_fields(case, index)

    classification_counts = report["classification_counts"]
    if not isinstance(classification_counts, dict):
        raise SuiteReportContractError("classification_counts must be an object")
    for classification, count in classification_counts.items():
        if not isinstance(classification, str):
            raise SuiteReportContractError(
                "classification_counts keys must be strings"
            )
        if (
            not isinstance(count, int)
            or isinstance(count, bool)
            or count < 0
        ):
            raise SuiteReportContractError(
                f"classification_counts.{classification} must be a non-negative integer"
            )
    if classification_counts != observed_counts:
        raise SuiteReportContractError(
            "classification_counts must exactly match case classifications"
        )

    manifest = report["evidence_manifest"]
    if not isinstance(manifest, dict) or not isinstance(
        manifest.get("files"), (list, tuple)
    ):
        raise SuiteReportContractError("evidence_manifest.files must be a sequence")
    if set(manifest) != {"root", "files"}:
        raise SuiteReportContractError("evidence_manifest has unsupported fields")
    if not isinstance(manifest.get("root"), str):
        raise SuiteReportContractError("evidence_manifest.root must be a string")
    seen_paths: set[str] = set()
    for index, item in enumerate(manifest["files"]):
        if not isinstance(item, dict):
            raise SuiteReportContractError(
                f"evidence_manifest.files[{index}] must be an object"
            )
        if set(item) != {"path", "size_bytes", "sha256"}:
            raise SuiteReportContractError(
                f"evidence_manifest.files[{index}] has unsupported fields"
            )
        path = item.get("path")
        if not isinstance(path, str) or not _is_safe_relative_path(path):
            raise SuiteReportContractError(
                f"evidence_manifest.files[{index}].path must be a safe relative path"
            )
        normalized = path.replace("\\", "/").lower()
        if normalized in seen_paths:
            raise SuiteReportContractError(f"duplicate evidence path: {path}")
        seen_paths.add(normalized)
        sha256 = item.get("sha256")
        if (
            not isinstance(sha256, str)
            or len(sha256) != 64
            or any(character not in "0123456789abcdefABCDEF" for character in sha256)
        ):
            raise SuiteReportContractError(
                f"evidence_manifest.files[{index}].sha256 must be 64 hexadecimal characters"
            )
        size = item.get("size_bytes")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise SuiteReportContractError(
                f"evidence_manifest.files[{index}].size_bytes must be a non-negative integer"
            )

    notes = report.get("notes")
    if notes is not None and (
        not isinstance(notes, list)
        or any(not isinstance(note, str) for note in notes)
    ):
        raise SuiteReportContractError("notes must be an array of strings")


def _validate_optional_case_fields(case: dict[str, Any], index: int) -> None:
    for field in (
        "marker_valid",
        "telemetry_valid",
        "executable_identity_valid",
        "detection_matched",
    ):
        value = case.get(field)
        if field in case and value is not None and not isinstance(value, bool):
            raise SuiteReportContractError(
                f"case {index}.{field} must be a boolean or null"
            )

    rule_id = case.get("rule_id")
    if "rule_id" in case and rule_id is not None and not isinstance(rule_id, str):
        raise SuiteReportContractError(
            f"case {index}.rule_id must be a string or null"
        )
    if "detection_reason" in case and not isinstance(
        case["detection_reason"],
        str,
    ):
        raise SuiteReportContractError(
            f"case {index}.detection_reason must be a string"
        )


def _is_date_time(value: object) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    normalized = value.strip().replace("Z", "+00:00")
    if "T" not in normalized and " " not in normalized:
        return False
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _is_safe_relative_path(value: str) -> bool:
    normalized = value.replace("\\", "/")
    posix_path = PurePosixPath(normalized)
    windows_path = PureWindowsPath(normalized)
    return (
        bool(normalized)
        and not posix_path.is_absolute()
        and not windows_path.is_absolute()
        and not windows_path.drive
        and ".." not in posix_path.parts
    )
