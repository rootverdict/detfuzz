import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from detfuzz.models import (
    DetectionResult,
    MarkerValidation,
    ProcessExecution,
    SysmonEvent,
    TelemetryValidation,
)
from detfuzz.suite import _evaluate_detection, run_v0_suite


class SuiteRunnerTests(unittest.TestCase):
    def test_detection_evaluator_failure_becomes_detection_engine_error(self) -> None:
        telemetry = TelemetryValidation(
            valid=True,
            reason="TELEMETRY_COMPLETE",
            event=SysmonEvent(
                event_id=1,
                provider="Microsoft-Windows-Sysmon",
                utc_time="2026-07-21T00:00:00Z",
                computer="host",
                record_id="1",
                fields={},
            ),
        )

        with patch(
            "detfuzz.suite.evaluate_detection_rule",
            side_effect=ValueError("bad operator"),
        ):
            result = _evaluate_detection(telemetry)

        self.assertIsNotNone(result)
        self.assertTrue(result.error)
        self.assertIn("DETECTION_ENGINE_ERROR:ValueError", result.reason)

    def test_run_v0_suite_executes_all_cases_and_finalizes_candidate_bypass(self) -> None:
        def fake_execute(prepared, timeout_seconds=30):
            return ProcessExecution(
                case_id=prepared.case.case_id,
                command_line=prepared.command_line,
                pid=1000 + len(prepared.case.case_id),
                started_at_utc="2026-07-21T00:00:00+00:00",
                ended_at_utc="2026-07-21T00:00:01+00:00",
                exit_code=1 if prepared.case.case_id == "NC1" else 0,
                stdout="",
                stderr="",
            )

        def fake_marker(prepared, execution):
            reason = (
                "MARKER_VALID" if prepared.case.case_id != "NC1" else "MARKER_ABSENT_AS_EXPECTED"
            )
            return MarkerValidation(
                valid=prepared.case.case_id != "NC1" or execution.exit_code != 0,
                exists=prepared.case.case_id != "NC1",
                reason=reason,
            )

        def fake_telemetry(
            prepared,
            execution,
            host,
            max_events,
            telemetry_timeout_seconds=30,
            powershell_path="powershell.exe",
        ):
            return TelemetryValidation(
                valid=True,
                reason="TELEMETRY_COMPLETE",
                event=SysmonEvent(
                    event_id=1,
                    provider="Microsoft-Windows-Sysmon",
                    utc_time="2026-07-21T00:00:00Z",
                    computer=host,
                    record_id=prepared.case.case_id,
                    fields={
                        "Hashes": "SHA256=ABC123",
                        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    },
                ),
            )

        def fake_detection(telemetry):
            case_id = telemetry.event.record_id
            return DetectionResult(
                rule_id="rule",
                matched=case_id != "M1",
                reason="RULE_MATCHED" if case_id != "M1" else "RULE_NOT_MATCHED",
            )

        def passing_preflight(powershell_exe):
            return {"status": "PASS", "reason": "CLOCK_SYNC_OK"}

        with tempfile.TemporaryDirectory() as root:
            with (
                patch("detfuzz.suite.run_clock_preflight", passing_preflight),
                patch("detfuzz.suite.expected_executable_sha256", lambda path: "ABC123"),
                patch("detfuzz.suite.execute_prepared_case", fake_execute),
                patch("detfuzz.suite.validate_marker", fake_marker),
                patch("detfuzz.suite._query_telemetry", fake_telemetry),
                patch("detfuzz.suite._evaluate_detection", fake_detection),
            ):
                result = run_v0_suite(Path(root), host="DetFuzz-Win11-Lab")

            classifications = {case["case_id"]: case["classification"] for case in result["cases"]}

            self.assertEqual(result["suite_status"], "COMPLETED")
            self.assertEqual(len(result["cases"]), 8)
            self.assertEqual(classifications["B0"], "DETECTED")
            self.assertEqual(classifications["M1"], "VALID_BYPASS")
            self.assertEqual(classifications["NC1"], "INVALID_MUTANT")
            self.assertEqual(classifications["B1"], "DETECTED")
            self.assertTrue(Path(result["suite_results"]).exists())
            self.assertTrue(Path(result["reports"]["json_report"]).exists())

    def test_run_v0_suite_aborts_when_opening_baseline_is_not_detected(self) -> None:
        def fake_execute(prepared, timeout_seconds=30):
            return ProcessExecution(
                case_id=prepared.case.case_id,
                command_line=prepared.command_line,
                pid=1234,
                started_at_utc="2026-07-21T00:00:00+00:00",
                ended_at_utc="2026-07-21T00:00:01+00:00",
                exit_code=0,
                stdout="",
                stderr="",
            )

        def passing_preflight(powershell_exe):
            return {"status": "PASS", "reason": "CLOCK_SYNC_OK"}

        def fake_telemetry(
            prepared,
            execution,
            host,
            max_events,
            telemetry_timeout_seconds=30,
            powershell_path="powershell.exe",
        ):
            return TelemetryValidation(
                True,
                "TELEMETRY_COMPLETE",
                SysmonEvent(
                    1,
                    "Microsoft-Windows-Sysmon",
                    "",
                    host,
                    "1",
                    {
                        "Hashes": "SHA256=ABC123",
                        "Image": (
                            r"C:\Windows\System32\WindowsPowerShell"
                            r"\v1.0\powershell.exe"
                        ),
                    },
                ),
            )

        with tempfile.TemporaryDirectory() as root:
            with (
                patch("detfuzz.suite.run_clock_preflight", passing_preflight),
                patch("detfuzz.suite.expected_executable_sha256", lambda path: "ABC123"),
                patch("detfuzz.suite.execute_prepared_case", fake_execute),
                patch(
                    "detfuzz.suite.validate_marker",
                    lambda prepared, execution: MarkerValidation(True, True, "MARKER_VALID"),
                ),
                patch(
                    "detfuzz.suite._query_telemetry",
                    fake_telemetry,
                ),
                patch(
                    "detfuzz.suite._evaluate_detection",
                    lambda telemetry: DetectionResult("rule", False, "RULE_NOT_MATCHED"),
                ),
            ):
                result = run_v0_suite(Path(root), host="DetFuzz-Win11-Lab")

            self.assertEqual(result["suite_status"], "ABORTED")
            self.assertEqual(result["abort_reason"], "OPENING_BASELINE_NOT_DETECTED")
            self.assertEqual(len(result["cases"]), 1)

    def test_run_v0_suite_fails_health_when_negative_control_is_not_invalid(self) -> None:
        result = self._run_suite_with_detection_overrides({})

        self.assertEqual(result["suite_status"], "PIPELINE_HEALTH_FAILED")
        self.assertEqual(result["abort_reason"], "NEGATIVE_CONTROL_NOT_INVALID")

    def test_run_v0_suite_fails_health_when_closing_baseline_is_not_detected(self) -> None:
        result = self._run_suite_with_detection_overrides({"B1": False, "__nc1_invalid__": True})

        self.assertEqual(result["suite_status"], "PIPELINE_HEALTH_FAILED")
        self.assertEqual(result["abort_reason"], "CLOSING_BASELINE_NOT_DETECTED")

    def test_run_v0_suite_writes_partial_report_on_unexpected_error(self) -> None:
        def fail_execute(prepared, timeout_seconds=30):
            raise RuntimeError("boom")

        with tempfile.TemporaryDirectory() as root:
            with (
                patch(
                    "detfuzz.suite.run_clock_preflight",
                    lambda powershell_exe: {"status": "PASS", "reason": "CLOCK_SYNC_OK"},
                ),
                patch("detfuzz.suite.expected_executable_sha256", lambda path: "ABC123"),
                patch("detfuzz.suite.execute_prepared_case", fail_execute),
            ):
                result = run_v0_suite(Path(root), host="DetFuzz-Win11-Lab")

            self.assertEqual(result["suite_status"], "ABORTED")
            self.assertIn("UNEXPECTED_ERROR:RuntimeError:boom", result["abort_reason"])
            self.assertTrue(Path(result["suite_results"]).exists())
            self.assertTrue(Path(result["reports"]["json_report"]).exists())

    def _run_suite_with_detection_overrides(
        self,
        overrides: dict[str, bool],
    ) -> dict[str, object]:
        def fake_execute(prepared, timeout_seconds=30):
            return ProcessExecution(
                case_id=prepared.case.case_id,
                command_line=prepared.command_line,
                pid=1234,
                started_at_utc="2026-07-21T00:00:00+00:00",
                ended_at_utc="2026-07-21T00:00:01+00:00",
                exit_code=1
                if prepared.case.case_id == "NC1" and overrides.get("__nc1_invalid__")
                else 0,
                stdout="",
                stderr="",
            )

        def fake_telemetry(
            prepared,
            execution,
            host,
            max_events,
            telemetry_timeout_seconds=30,
            powershell_path="powershell.exe",
        ):
            return TelemetryValidation(
                True,
                "TELEMETRY_COMPLETE",
                SysmonEvent(
                    1,
                    "Microsoft-Windows-Sysmon",
                    "2026-07-21T00:00:00Z",
                    host,
                    prepared.case.case_id,
                    {
                        "Hashes": "SHA256=ABC123",
                        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    },
                ),
            )

        def fake_detection(telemetry):
            case_id = telemetry.event.record_id
            matched = overrides.get(case_id, True)
            return DetectionResult(
                rule_id="rule",
                matched=matched,
                reason="RULE_MATCHED" if matched else "RULE_NOT_MATCHED",
            )

        with tempfile.TemporaryDirectory() as root:
            with (
                patch(
                    "detfuzz.suite.run_clock_preflight",
                    lambda powershell_exe: {"status": "PASS", "reason": "CLOCK_SYNC_OK"},
                ),
                patch("detfuzz.suite.expected_executable_sha256", lambda path: "ABC123"),
                patch("detfuzz.suite.execute_prepared_case", fake_execute),
                patch(
                    "detfuzz.suite.validate_marker",
                    lambda prepared, execution: MarkerValidation(
                        True,
                        prepared.case.case_id != "NC1",
                        "MARKER_ABSENT_AS_EXPECTED"
                        if prepared.case.case_id == "NC1"
                        else "MARKER_VALID",
                    ),
                ),
                patch("detfuzz.suite._query_telemetry", fake_telemetry),
                patch("detfuzz.suite._evaluate_detection", fake_detection),
            ):
                return run_v0_suite(Path(root), host="DetFuzz-Win11-Lab")


if __name__ == "__main__":
    unittest.main()
