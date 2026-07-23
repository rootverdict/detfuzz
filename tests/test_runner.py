import base64
import tempfile
import unittest
from pathlib import Path

from detfuzz.cases import V0_CASES
from detfuzz.models import CaseKind, CaseSpec
from detfuzz.payloads import encode_powershell_command, marker_payload
from detfuzz.runner import create_suite, prepare_case


class PayloadTests(unittest.TestCase):
    def test_powershell_payload_is_encoded_as_utf16le_base64(self) -> None:
        encoded = encode_powershell_command("Write-Output 'ok'")

        decoded = base64.b64decode(encoded).decode("utf-16le")

        self.assertEqual(decoded, "Write-Output 'ok'")

    def test_marker_payload_contains_exact_identifiers(self) -> None:
        payload = marker_payload(
            suite_id="suite-1",
            case_id="M1",
            nonce="abc123",
            marker_path=r"C:\DetFuzz\runs\suite-1\M1\effect.json",
        )

        self.assertIn("suite-1", payload)
        self.assertIn("M1", payload)
        self.assertIn("abc123", payload)
        self.assertIn("effect.json", payload)
        self.assertIn("ConvertTo-Json", payload)


class RunnerPreparationTests(unittest.TestCase):
    def test_create_suite_uses_fresh_directory(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            suite = create_suite(Path(root))

            self.assertTrue(suite.suite_path.exists())
            self.assertEqual(suite.suite_path.parent, Path(root).resolve())

    def test_prepare_case_creates_exact_case_path_and_marker_path(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            suite = create_suite(Path(root))
            prepared = prepare_case(suite, V0_CASES[1])

            self.assertEqual(prepared.case.case_id, "M1")
            self.assertEqual(prepared.case_path, suite.suite_path / "M1")
            self.assertEqual(prepared.marker_path, prepared.case_path / "effect.json")
            self.assertTrue(prepared.case_path.exists())

    def test_every_v0_case_builds_an_allow_listed_command(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            suite = create_suite(Path(root))

            for case in V0_CASES:
                prepared = prepare_case(suite, case)
                self.assertTrue(prepared.command_line.startswith("powershell.exe "))
                self.assertIn("-NoProfile", prepared.command_line)
                self.assertIn("-NonInteractive", prepared.command_line)

    def test_negative_control_uses_invalid_base64_and_expects_no_marker(self) -> None:
        nc1 = next(case for case in V0_CASES if case.case_id == "NC1")

        with tempfile.TemporaryDirectory() as root:
            suite = create_suite(Path(root))
            prepared = prepare_case(suite, nc1)

            self.assertFalse(nc1.expected_marker)
            self.assertIn("!!!invalid-base64!!!", prepared.command_line)

    def test_non_inventory_case_is_rejected(self) -> None:
        rogue = CaseSpec(
            case_id="ROGUE",
            kind=CaseKind.MUTATION,
            transformation="not part of v0",
            expected_marker=True,
        )

        with tempfile.TemporaryDirectory() as root:
            suite = create_suite(Path(root))

            with self.assertRaises(ValueError):
                prepare_case(suite, rogue)


if __name__ == "__main__":
    unittest.main()
