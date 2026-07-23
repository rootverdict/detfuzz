import unittest

from detfuzz.identity import extract_hash_value, validate_executable_identity
from detfuzz.models import SysmonEvent, TelemetryValidation


class IdentityTests(unittest.TestCase):
    def test_extract_hash_value_reads_requested_algorithm(self) -> None:
        self.assertEqual(
            extract_hash_value("MD5=AA,SHA256=BB,IMPHASH=CC", "SHA256"),
            "BB",
        )

    def test_validate_executable_identity_matches_sysmon_sha256(self) -> None:
        telemetry = TelemetryValidation(
            True,
            "TELEMETRY_COMPLETE",
            SysmonEvent(
                event_id=1,
                provider="Microsoft-Windows-Sysmon",
                utc_time="2026-07-21T00:00:00Z",
                computer="DetFuzz-Win11-Lab",
                record_id="1",
                fields={"Hashes": "MD5=AA,SHA256=ABC123", "Image": "powershell.exe"},
            ),
        )

        result = validate_executable_identity(telemetry, "abc123")

        self.assertTrue(result.valid)
        self.assertEqual(result.reason, "EXECUTABLE_IDENTITY_MATCH")

    def test_validate_executable_identity_rejects_mismatch(self) -> None:
        telemetry = TelemetryValidation(
            True,
            "TELEMETRY_COMPLETE",
            SysmonEvent(
                event_id=1,
                provider="Microsoft-Windows-Sysmon",
                utc_time="2026-07-21T00:00:00Z",
                computer="DetFuzz-Win11-Lab",
                record_id="1",
                fields={"Hashes": "SHA256=DEF456", "Image": "powershell.exe"},
            ),
        )

        result = validate_executable_identity(telemetry, "ABC123")

        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "EXECUTABLE_IDENTITY_MISMATCH")


if __name__ == "__main__":
    unittest.main()
