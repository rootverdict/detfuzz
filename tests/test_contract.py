import json
import tempfile
import unittest
from pathlib import Path

from detfuzz.contract import (
    SUITE_REPORT_SCHEMA_VERSION,
    SuiteReportContractError,
    export_suite_report_schema,
    load_suite_report_schema,
    validate_suite_report_shape,
)


class SuiteReportContractTests(unittest.TestCase):
    def test_packaged_schema_matches_supported_version(self) -> None:
        schema = load_suite_report_schema()

        self.assertEqual(
            schema["properties"]["schema_version"]["const"],
            SUITE_REPORT_SCHEMA_VERSION,
        )

    def test_export_contract_copies_valid_json_schema(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            output = Path(root) / "detfuzz-suite-report-1.0.schema.json"

            exported = export_suite_report_schema(output)

            self.assertEqual(exported, output)
            self.assertEqual(
                json.loads(output.read_text(encoding="utf-8")),
                load_suite_report_schema(),
            )

    def test_report_shape_rejects_evidence_path_traversal(self) -> None:
        report = {
            "schema_version": "1.0",
            "generated_at_utc": "2026-07-23T00:00:00+00:00",
            "suite_id": "suite",
            "suite_status": "COMPLETED",
            "environment": {},
            "case_count": 0,
            "classification_counts": {},
            "cases": [],
            "evidence_manifest": {
                "root": "evidence",
                "files": [
                    {
                        "path": "../outside.txt",
                        "size_bytes": 1,
                        "sha256": "0" * 64,
                    }
                ],
            },
        }

        with self.assertRaises(SuiteReportContractError):
            validate_suite_report_shape(report)

    def test_report_shape_rejects_null_suite_status(self) -> None:
        report = {
            "schema_version": "1.0",
            "generated_at_utc": "2026-07-23T00:00:00+00:00",
            "suite_id": "suite",
            "suite_status": None,
            "environment": {},
            "case_count": 0,
            "classification_counts": {},
            "cases": [],
            "evidence_manifest": {"root": "evidence", "files": []},
        }

        with self.assertRaisesRegex(
            SuiteReportContractError,
            "suite_status must be a non-empty string",
        ):
            validate_suite_report_shape(report)


if __name__ == "__main__":
    unittest.main()
