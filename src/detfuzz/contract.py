from __future__ import annotations

import json
import shutil
from pathlib import Path
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
    if not isinstance(report["suite_id"], str) or not report["suite_id"]:
        raise SuiteReportContractError("suite_id must be a non-empty string")
    if (
        not isinstance(report["suite_status"], str)
        or not report["suite_status"].strip()
    ):
        raise SuiteReportContractError("suite_status must be a non-empty string")
    cases = report["cases"]
    if not isinstance(cases, list):
        raise SuiteReportContractError("cases must be a list")
    if report["case_count"] != len(cases):
        raise SuiteReportContractError("case_count must equal the number of cases")

    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            raise SuiteReportContractError(f"case {index} must be an object")
        for field in ("case_id", "classification"):
            if not isinstance(case.get(field), str) or not case[field]:
                raise SuiteReportContractError(
                    f"case {index}.{field} must be a non-empty string"
                )

    manifest = report["evidence_manifest"]
    if not isinstance(manifest, dict) or not isinstance(
        manifest.get("files"), (list, tuple)
    ):
        raise SuiteReportContractError("evidence_manifest.files must be a sequence")
    seen_paths: set[str] = set()
    for index, item in enumerate(manifest["files"]):
        if not isinstance(item, dict):
            raise SuiteReportContractError(
                f"evidence_manifest.files[{index}] must be an object"
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


def _is_safe_relative_path(value: str) -> bool:
    normalized = value.replace("\\", "/")
    path = Path(normalized)
    return bool(normalized) and not path.is_absolute() and ".." not in path.parts
