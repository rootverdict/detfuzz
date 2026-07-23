import argparse
import contextlib
import io
import unittest
from unittest.mock import patch

from detfuzz.cli import clock_preflight, run_benign, run_suite


class CliExitStatusTests(unittest.TestCase):
    def test_failed_clock_preflight_exits_nonzero(self) -> None:
        args = argparse.Namespace(powershell_path="powershell.exe")

        with (
            patch(
                "detfuzz.cli.run_clock_preflight",
                return_value={"status": "PREFLIGHT_FAILED", "reason": "test"},
            ),
            contextlib.redirect_stdout(io.StringIO()),
            self.assertRaises(SystemExit) as raised,
        ):
            clock_preflight(args)

        self.assertEqual(raised.exception.code, 1)

    def test_failed_suite_exits_nonzero(self) -> None:
        args = argparse.Namespace(
            output_root=None,
            host="host",
            powershell_path="powershell.exe",
            timeout_seconds=30,
            telemetry_timeout_seconds=30,
            max_events=5000,
            calibration_result=None,
        )

        with (
            patch(
                "detfuzz.cli.run_v0_suite",
                return_value={"suite_status": "ABORTED"},
            ),
            contextlib.redirect_stdout(io.StringIO()),
            self.assertRaises(SystemExit) as raised,
        ):
            run_suite(args)

        self.assertEqual(raised.exception.code, 1)

    def test_unhealthy_benign_suite_exits_nonzero(self) -> None:
        args = argparse.Namespace(
            output_root=None,
            host="host",
            powershell_path="powershell.exe",
            timeout_seconds=30,
            telemetry_timeout_seconds=30,
            max_events=5000,
        )

        with (
            patch(
                "detfuzz.cli.run_benign_fixtures",
                return_value={"suite_status": "PIPELINE_HEALTH_FAILED"},
            ),
            contextlib.redirect_stdout(io.StringIO()),
            self.assertRaises(SystemExit) as raised,
        ):
            run_benign(args)

        self.assertEqual(raised.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
