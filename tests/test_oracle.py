import json
import os
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from detfuzz.cases import V1_CASES
from detfuzz.models import ProcessExecution
from detfuzz.oracle import validate_marker
from detfuzz.runner import create_suite, prepare_case


class MarkerOracleTests(unittest.TestCase):
    def test_valid_marker_passes_exact_content_check(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            suite = create_suite(Path(root))
            prepared = prepare_case(suite, V1_CASES[0])
            prepared.marker_path.write_text(
                json.dumps(
                    {
                        "run_id": prepared.suite_id,
                        "case_id": "B0",
                        "nonce": prepared.nonce,
                        "result": "completed",
                    }
                ),
                encoding="utf-8",
            )

            result = validate_marker(prepared)

            self.assertTrue(result.valid)
            self.assertEqual(result.reason, "MARKER_VALID")

    def test_missing_expected_marker_fails(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            suite = create_suite(Path(root))
            prepared = prepare_case(suite, V1_CASES[0])

            result = validate_marker(prepared)

            self.assertFalse(result.valid)
            self.assertEqual(result.reason, "MARKER_MISSING")

    def test_negative_control_without_marker_passes(self) -> None:
        nc1 = next(case for case in V1_CASES if case.case_id == "NC1")

        with tempfile.TemporaryDirectory() as root:
            suite = create_suite(Path(root))
            prepared = prepare_case(suite, nc1)

            result = validate_marker(prepared)

            self.assertTrue(result.valid)
            self.assertEqual(result.reason, "MARKER_ABSENT_AS_EXPECTED")

    def test_unexpected_negative_control_marker_fails(self) -> None:
        nc1 = next(case for case in V1_CASES if case.case_id == "NC1")

        with tempfile.TemporaryDirectory() as root:
            suite = create_suite(Path(root))
            prepared = prepare_case(suite, nc1)
            prepared.marker_path.write_text("{}", encoding="utf-8")

            result = validate_marker(prepared)

            self.assertFalse(result.valid)
            self.assertEqual(result.reason, "UNEXPECTED_MARKER_PRESENT")

    def test_nonce_mismatch_fails(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            suite = create_suite(Path(root))
            prepared = prepare_case(suite, V1_CASES[0])
            prepared.marker_path.write_text(
                json.dumps(
                    {
                        "run_id": prepared.suite_id,
                        "case_id": "B0",
                        "nonce": "wrong",
                        "result": "completed",
                    }
                ),
                encoding="utf-8",
            )

            result = validate_marker(prepared)

            self.assertFalse(result.valid)
            self.assertEqual(result.reason, "MARKER_FIELD_MISMATCH:nonce")

    def test_marker_timestamp_must_be_inside_execution_window(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            suite = create_suite(Path(root))
            prepared = prepare_case(suite, V1_CASES[0])
            prepared.marker_path.write_text(
                json.dumps(
                    {
                        "run_id": prepared.suite_id,
                        "case_id": "B0",
                        "nonce": prepared.nonce,
                        "result": "completed",
                    }
                ),
                encoding="utf-8",
            )
            execution = ProcessExecution(
                case_id="B0",
                command_line=prepared.command_line,
                pid=100,
                started_at_utc="2000-01-01T00:00:00+00:00",
                ended_at_utc="2000-01-01T00:00:01+00:00",
                exit_code=0,
                stdout="",
                stderr="",
            )

            result = validate_marker(prepared, execution)

            self.assertFalse(result.valid)
            self.assertEqual(result.reason, "MARKER_TIMESTAMP_OUTSIDE_EXECUTION_WINDOW")

    def test_marker_timestamp_allows_small_filesystem_clock_drift(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            suite = create_suite(Path(root))
            prepared = prepare_case(suite, V1_CASES[0])
            prepared.marker_path.write_text(
                json.dumps(
                    {
                        "run_id": prepared.suite_id,
                        "case_id": "B0",
                        "nonce": prepared.nonce,
                        "result": "completed",
                    }
                ),
                encoding="utf-8",
            )
            now = datetime.now(UTC)
            os.utime(prepared.marker_path, (now.timestamp() + 0.5,) * 2)
            execution = ProcessExecution(
                case_id="B0",
                command_line=prepared.command_line,
                pid=100,
                started_at_utc=(now - timedelta(seconds=1)).isoformat(),
                ended_at_utc=now.isoformat(),
                exit_code=0,
                stdout="",
                stderr="",
            )

            result = validate_marker(prepared, execution)

            self.assertTrue(result.valid)
            self.assertEqual(result.reason, "MARKER_VALID")


if __name__ == "__main__":
    unittest.main()
