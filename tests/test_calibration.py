import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import cast
from unittest.mock import patch

from detfuzz.calibration import calibrate_timeouts, run_clock_preflight
from detfuzz.models import MarkerValidation, ProcessExecution, SysmonEvent, TelemetryValidation


class CalibrationTests(unittest.TestCase):
    def test_clock_preflight_passes_when_target_clock_is_close(self) -> None:
        def fake_runner(*args, **kwargs):
            command = args[0]
            if "w32tm /query /status" in command:
                return subprocess.CompletedProcess(
                    args=args,
                    returncode=0,
                    stdout="Source: time.windows.com\nLeap Indicator: 0(no warning)",
                    stderr="",
                )
            return subprocess.CompletedProcess(
                args=args,
                returncode=0,
                stdout="2026-07-21T00:00:00+00:00",
                stderr="",
            )

        with patch("detfuzz.calibration.datetime") as fake_datetime:
            from datetime import UTC, datetime

            fake_datetime.now.return_value = datetime(2026, 7, 21, 0, 0, 0, tzinfo=UTC)
            fake_datetime.fromisoformat.side_effect = datetime.fromisoformat
            result = run_clock_preflight(command_runner=fake_runner)

        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["reason"], "CLOCK_SYNC_OK")

    def test_clock_preflight_fails_when_offset_is_too_large(self) -> None:
        def fake_runner(*args, **kwargs):
            command = args[0]
            if "w32tm /query /status" in command:
                return subprocess.CompletedProcess(
                    args=args,
                    returncode=0,
                    stdout="Source: time.windows.com\nLeap Indicator: 0(no warning)",
                    stderr="",
                )
            return subprocess.CompletedProcess(
                args=args,
                returncode=0,
                stdout="2026-07-21T00:00:10+00:00",
                stderr="",
            )

        with patch("detfuzz.calibration.datetime") as fake_datetime:
            from datetime import UTC, datetime

            fake_datetime.now.return_value = datetime(2026, 7, 21, 0, 0, 0, tzinfo=UTC)
            fake_datetime.fromisoformat.side_effect = datetime.fromisoformat
            result = run_clock_preflight(command_runner=fake_runner)

        self.assertEqual(result["status"], "PREFLIGHT_FAILED")
        self.assertEqual(result["reason"], "CLOCK_UNSYNCED")

    def test_clock_preflight_reports_missing_powershell(self) -> None:
        def missing_runner(*args, **kwargs):
            raise FileNotFoundError("powershell missing")

        result = run_clock_preflight(command_runner=missing_runner)

        self.assertEqual(result["status"], "PREFLIGHT_FAILED")
        self.assertIn("CLOCK_QUERY_ERROR:FileNotFoundError", str(result["reason"]))

    def test_calibrate_timeouts_writes_output_and_selects_timeout(self) -> None:
        calls = {"count": 0}
        telemetry_timeouts = []

        def fake_execute(prepared, timeout_seconds=30):
            calls["count"] += 1
            return ProcessExecution(
                case_id="B0",
                command_line=prepared.command_line,
                pid=2000 + calls["count"],
                started_at_utc=f"2026-07-21T00:00:0{calls['count']}+00:00",
                ended_at_utc=f"2026-07-21T00:00:0{calls['count']}.500000+00:00",
                exit_code=0,
                stdout="",
                stderr="",
            )

        def fake_telemetry(
            prepared_case_id,
            execution,
            host,
            max_events,
            telemetry_timeout_seconds,
        ):
            telemetry_timeouts.append(telemetry_timeout_seconds)
            return TelemetryValidation(
                True,
                "TELEMETRY_COMPLETE",
                SysmonEvent(
                    event_id=1,
                    provider="Microsoft-Windows-Sysmon",
                    utc_time=execution.ended_at_utc,
                    computer=host,
                    record_id=str(execution.pid),
                    fields={
                        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                        "CommandLine": "powershell.exe -NoProfile -EncodedCommand AAAA",
                    },
                ),
            )

        with tempfile.TemporaryDirectory() as root:
            with (
                patch("detfuzz.calibration.execute_prepared_case", fake_execute),
                patch(
                    "detfuzz.calibration.validate_marker",
                    lambda prepared, execution: MarkerValidation(True, True, "MARKER_VALID"),
                ),
                patch("detfuzz.calibration._query_calibration_telemetry", fake_telemetry),
            ):
                result = calibrate_timeouts(Path(root), host="DetFuzz-Win11-Lab", runs=2)

            self.assertEqual(result["status"], "PASS")
            self.assertEqual(result["runs_completed"], 2)
            selected = cast(dict[str, int], result["selected_timeouts_seconds"])
            self.assertEqual(selected["process"], 30)
            self.assertEqual(telemetry_timeouts, [120, 120])
            self.assertTrue(Path(str(result["output_path"])).exists())

    def test_calibrate_timeouts_fails_when_telemetry_is_missing(self) -> None:
        def fake_execute(prepared, timeout_seconds=30):
            return ProcessExecution(
                case_id="B0",
                command_line=prepared.command_line,
                pid=2001,
                started_at_utc="2026-07-21T00:00:01+00:00",
                ended_at_utc="2026-07-21T00:00:01.500000+00:00",
                exit_code=0,
                stdout="",
                stderr="",
            )

        def fake_query(
            prepared_case_id,
            execution,
            host,
            max_events,
            telemetry_timeout_seconds,
        ):
            return TelemetryValidation(
                False,
                "NO_MATCHING_PROCESS_CREATE_EVENT",
                None,
            )

        with tempfile.TemporaryDirectory() as root:
            with (
                patch("detfuzz.calibration.execute_prepared_case", fake_execute),
                patch(
                    "detfuzz.calibration.validate_marker",
                    lambda prepared, execution: MarkerValidation(True, True, "MARKER_VALID"),
                ),
                patch(
                    "detfuzz.calibration._query_calibration_telemetry",
                    fake_query,
                ),
            ):
                result = calibrate_timeouts(Path(root), host="DetFuzz-Win11-Lab", runs=1)

            self.assertEqual(result["status"], "CALIBRATION_FAILED")
            self.assertEqual(result["reason"], "CALIBRATION_HEALTH_CHECK_FAILED")


if __name__ == "__main__":
    unittest.main()
