import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from detfuzz.benign import (
    V01_BENIGN_FIXTURES,
    command_line_for_benign_fixture,
    prepare_benign_fixture,
    run_benign_fixtures,
)
from detfuzz.models import (
    DetectionResult,
    ProcessExecution,
    SysmonEvent,
    TelemetryValidation,
)
from detfuzz.runner import create_suite


class BenignFixtureTests(unittest.TestCase):
    def test_plain_fixture_uses_command_without_encoded_command(self) -> None:
        fixture = V01_BENIGN_FIXTURES[0]

        command_line, command_fragment = command_line_for_benign_fixture(fixture)

        self.assertIn("-Command", command_line)
        self.assertNotIn("-EncodedCommand", command_line)
        self.assertEqual(command_fragment, "-Command")

    def test_encoded_fixture_uses_encoded_command(self) -> None:
        fixture = V01_BENIGN_FIXTURES[1]

        command_line, command_fragment = command_line_for_benign_fixture(fixture)

        self.assertIn("-EncodedCommand", command_line)
        self.assertEqual(command_fragment, "-EncodedCommand")

    def test_prepare_benign_fixture_creates_exact_fixture_path(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            suite = create_suite(Path(root))
            prepared = prepare_benign_fixture(suite, V01_BENIGN_FIXTURES[0])

            self.assertEqual(prepared.fixture.fixture_id, "BF0")
            self.assertEqual(prepared.fixture_path, suite.suite_path / "BF0")
            self.assertTrue(prepared.fixture_path.exists())

    def test_run_benign_fixtures_reports_benign_alerts(self) -> None:
        def fake_execute(prepared, timeout_seconds=30):
            return ProcessExecution(
                case_id=prepared.fixture.fixture_id,
                command_line=prepared.command_line,
                pid=2000 + len(prepared.fixture.fixture_id),
                started_at_utc="2026-07-21T00:00:00+00:00",
                ended_at_utc="2026-07-21T00:00:01+00:00",
                exit_code=0,
                stdout="",
                stderr="",
            )

        def fake_telemetry(prepared, execution, host, max_events, powershell_path):
            return TelemetryValidation(
                valid=True,
                reason="TELEMETRY_COMPLETE",
                event=SysmonEvent(
                    event_id=1,
                    provider="Microsoft-Windows-Sysmon",
                    utc_time="2026-07-21T00:00:00Z",
                    computer=host,
                    record_id=prepared.fixture.fixture_id,
                    fields={},
                ),
            )

        def fake_detection(telemetry):
            fixture_id = telemetry.event.record_id
            matched = fixture_id in {"BF1", "BF2"}
            return DetectionResult(
                rule_id="rule",
                matched=matched,
                reason="RULE_MATCHED" if matched else "RULE_NOT_MATCHED",
            )

        with tempfile.TemporaryDirectory() as root:
            with patch(
                "detfuzz.benign.execute_benign_fixture",
                fake_execute,
            ), patch(
                "detfuzz.benign._query_fixture_telemetry",
                fake_telemetry,
            ), patch(
                "detfuzz.benign._evaluate_fixture_detection",
                fake_detection,
            ):
                result = run_benign_fixtures(
                    Path(root),
                    host="DetFuzz-Win11-Lab",
                )

            classifications = {
                fixture["case_id"]: fixture["classification"]
                for fixture in result["fixtures"]
            }

            self.assertEqual(result["suite_status"], "COMPLETED")
            self.assertEqual(classifications["BF0"], "BENIGN_NO_ALERT")
            self.assertEqual(classifications["BF1"], "BENIGN_ALERT")
            self.assertEqual(classifications["BF2"], "BENIGN_ALERT")
            self.assertTrue(Path(result["benign_results"]).exists())
            self.assertTrue(Path(result["reports"]["json_report"]).exists())


if __name__ == "__main__":
    unittest.main()
