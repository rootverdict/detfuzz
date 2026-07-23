import importlib.util
import unittest
from pathlib import Path

from detfuzz.detection import (
    V0_ENCODED_POWERSHELL_RULE,
    V0_SIGMA_RULE_PATH,
    evaluate_detection_rule,
    extract_rule_dependencies_from_sigma_dict,
    load_detection_rule_from_sigma,
    load_sigma_with_pysigma,
)
from detfuzz.telemetry import parse_sysmon_event_xml

SAMPLE_EVENT = """\
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" />
    <EventID>1</EventID>
    <EventRecordID>491</EventRecordID>
    <TimeCreated SystemTime="2026-07-20T18:08:47.1234567Z" />
    <Computer>DetFuzz-Win11-Lab</Computer>
  </System>
  <EventData>
    <Data Name="UtcTime">2026-07-20 18:08:47.123</Data>
    <Data Name="ProcessGuid">{abc}</Data>
    <Data Name="ProcessId">4242</Data>
    <Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    <Data Name="CommandLine">powershell.exe -NoProfile -EncodedCommand AAAA</Data>
    <Data Name="ParentImage">C:\\Windows\\System32\\cmd.exe</Data>
    <Data Name="Hashes">SHA256=abc123</Data>
  </EventData>
</Event>
"""


class DetectionTests(unittest.TestCase):
    def test_v0_rule_matches_encoded_command_event(self) -> None:
        event = parse_sysmon_event_xml(SAMPLE_EVENT)

        result = evaluate_detection_rule(V0_ENCODED_POWERSHELL_RULE, event)

        self.assertTrue(result.matched)
        self.assertEqual(result.reason, "RULE_MATCHED")

    def test_v0_rule_does_not_match_alias_only_command(self) -> None:
        event = parse_sysmon_event_xml(
            SAMPLE_EVENT.replace("-EncodedCommand", "-enc")
        )

        result = evaluate_detection_rule(V0_ENCODED_POWERSHELL_RULE, event)

        self.assertFalse(result.matched)
        self.assertEqual(result.reason, "RULE_NOT_MATCHED")

    def test_extract_dependencies_from_sigma_dict(self) -> None:
        sigma_rule = {
            "id": "rule-1",
            "title": "Encoded PowerShell",
            "detection": {
                "selection": {
                    "Image|endswith": r"\powershell.exe",
                    "CommandLine|contains": "-EncodedCommand",
                },
                "condition": "selection",
            },
        }

        rule = extract_rule_dependencies_from_sigma_dict(sigma_rule)

        self.assertEqual(rule.rule_id, "rule-1")
        self.assertEqual(len(rule.dependencies), 2)
        self.assertEqual(rule.dependencies[0].field, "Image")
        self.assertEqual(rule.dependencies[0].operator, "endswith")

    def test_pysigma_loader_fails_clearly_when_dependency_missing(self) -> None:
        if importlib.util.find_spec("sigma") is not None:
            self.skipTest("pySigma is installed")
        with self.assertRaisesRegex(RuntimeError, "pySigma is not installed"):
            load_sigma_with_pysigma(Path("missing.yml"))

    def test_real_sigma_rule_loads_with_pysigma_when_installed(self) -> None:
        if importlib.util.find_spec("sigma") is None:
            self.skipTest("pySigma is not installed")

        rule = load_detection_rule_from_sigma(
            V0_SIGMA_RULE_PATH,
            allow_parser_fallback=False,
        )

        self.assertEqual(rule.rule_id, "d4f8c4e4-984d-4f5f-9f6c-1cc6b37f2f62")
        self.assertEqual(rule.slug, "detfuzz-v0-powershell-encoded-command")


if __name__ == "__main__":
    unittest.main()
