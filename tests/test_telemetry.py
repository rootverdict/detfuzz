import subprocess
import unittest

from detfuzz.models import ProcessCorrelationCriteria, ProcessExecution
from detfuzz.telemetry import (
    correlate_process_create_event,
    event_matches_process,
    parse_sysmon_event_xml,
    parse_sysmon_event_xml_many,
    query_and_correlate_process_create,
    query_sysmon_process_create_xml,
    validate_process_create_event,
    wait_for_process_create_event,
)

SAMPLE_SYSMON_XML = """\
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


class TelemetryTests(unittest.TestCase):
    def test_parse_sysmon_event_xml_extracts_event_data_fields(self) -> None:
        event = parse_sysmon_event_xml(SAMPLE_SYSMON_XML)

        self.assertEqual(event.provider, "Microsoft-Windows-Sysmon")
        self.assertEqual(event.event_id, 1)
        self.assertEqual(event.computer, "DetFuzz-Win11-Lab")
        self.assertEqual(event.record_id, "491")
        self.assertEqual(event.fields["ProcessId"], "4242")
        self.assertIn("powershell.exe", event.fields["Image"])

    def test_parse_sysmon_event_xml_many_reads_line_delimited_events(self) -> None:
        events = parse_sysmon_event_xml_many(SAMPLE_SYSMON_XML + "\n" + SAMPLE_SYSMON_XML)

        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].fields["ProcessId"], "4242")

    def test_validate_process_create_requires_core_fields(self) -> None:
        event = parse_sysmon_event_xml(SAMPLE_SYSMON_XML)

        result = validate_process_create_event(event)

        self.assertTrue(result.valid)
        self.assertEqual(result.reason, "TELEMETRY_COMPLETE")

    def test_validate_process_create_reports_missing_fields(self) -> None:
        event = parse_sysmon_event_xml(
            SAMPLE_SYSMON_XML.replace('<Data Name="Hashes">SHA256=abc123</Data>', "")
        )

        result = validate_process_create_event(event)

        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "REQUIRED_FIELDS_MISSING")
        self.assertEqual(result.missing_fields, ("Hashes",))

    def test_correlate_process_create_matches_pid_image_and_command(self) -> None:
        event = parse_sysmon_event_xml(SAMPLE_SYSMON_XML)
        execution = ProcessExecution(
            case_id="B0",
            command_line="powershell.exe -NoProfile -EncodedCommand AAAA",
            pid=4242,
            started_at_utc="2026-07-20T18:08:46+00:00",
            ended_at_utc="2026-07-20T18:08:48+00:00",
            exit_code=0,
            stdout="",
            stderr="",
        )

        result = correlate_process_create_event([event], execution, "-EncodedCommand")

        self.assertTrue(result.valid)
        self.assertEqual(result.reason, "TELEMETRY_COMPLETE")

    def test_event_matches_process_checks_host_pid_image_command_and_time(self) -> None:
        event = parse_sysmon_event_xml(SAMPLE_SYSMON_XML)
        criteria = ProcessCorrelationCriteria(
            host="DetFuzz-Win11-Lab",
            pid=4242,
            started_at_utc="2026-07-20T18:08:46+00:00",
            ended_at_utc="2026-07-20T18:08:48+00:00",
            command_fragment="-EncodedCommand",
        )

        self.assertTrue(event_matches_process(event, criteria))

    def test_event_matching_rejects_event_outside_execution_window(self) -> None:
        event = parse_sysmon_event_xml(SAMPLE_SYSMON_XML)
        criteria = ProcessCorrelationCriteria(
            host="DetFuzz-Win11-Lab",
            pid=4242,
            started_at_utc="2026-07-20T18:10:00+00:00",
            ended_at_utc="2026-07-20T18:10:01+00:00",
            command_fragment="-EncodedCommand",
        )

        self.assertFalse(event_matches_process(event, criteria))

    def test_correlated_event_reports_missing_required_hash_algorithm(self) -> None:
        event_without_sha256 = SAMPLE_SYSMON_XML.replace(
            "SHA256=abc123",
            "MD5=abc123",
        )

        def fake_runner(*args, **kwargs):
            return subprocess.CompletedProcess(
                args=args,
                returncode=0,
                stdout=event_without_sha256,
                stderr="",
            )

        criteria = ProcessCorrelationCriteria(
            host="DetFuzz-Win11-Lab",
            pid=4242,
            started_at_utc="2026-07-20T18:08:46+00:00",
            ended_at_utc="2026-07-20T18:08:48+00:00",
            command_fragment="-EncodedCommand",
        )

        result = query_and_correlate_process_create(
            criteria,
            command_runner=fake_runner,
        )

        self.assertFalse(result.valid)
        self.assertIsNotNone(result.event)
        self.assertEqual(result.reason, "REQUIRED_HASH_ALGORITHM_MISSING")

    def test_correlate_process_create_fails_when_pid_does_not_match(self) -> None:
        event = parse_sysmon_event_xml(SAMPLE_SYSMON_XML)
        execution = ProcessExecution(
            case_id="B0",
            command_line="powershell.exe -NoProfile -EncodedCommand AAAA",
            pid=9999,
            started_at_utc="2026-07-20T18:08:46+00:00",
            ended_at_utc="2026-07-20T18:08:48+00:00",
            exit_code=0,
            stdout="",
            stderr="",
        )

        result = correlate_process_create_event([event], execution, "-EncodedCommand")

        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "NO_MATCHING_PROCESS_CREATE_EVENT")

    def test_query_sysmon_process_create_xml_uses_powershell_get_winevent(self) -> None:
        calls = []

        def fake_runner(*args, **kwargs):
            calls.append((args, kwargs))
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="xml", stderr="")

        output = query_sysmon_process_create_xml(command_runner=fake_runner)

        self.assertEqual(output, "xml")
        command = " ".join(calls[0][0][0])
        self.assertIn("powershell.exe", command)
        self.assertIn("Get-WinEvent", command)
        self.assertIn("Microsoft-Windows-Sysmon/Operational", command)

    def test_query_and_correlate_process_create_validates_matching_event(self) -> None:
        def fake_runner(*args, **kwargs):
            return subprocess.CompletedProcess(
                args=args,
                returncode=0,
                stdout=SAMPLE_SYSMON_XML,
                stderr="",
            )

        criteria = ProcessCorrelationCriteria(
            host="DetFuzz-Win11-Lab",
            pid=4242,
            started_at_utc="2026-07-20T18:08:46+00:00",
            ended_at_utc="2026-07-20T18:08:48+00:00",
            command_fragment="-EncodedCommand",
        )

        result = query_and_correlate_process_create(
            criteria, command_runner=fake_runner
        )

        self.assertTrue(result.valid)
        self.assertEqual(result.reason, "TELEMETRY_COMPLETE")

    def test_wait_for_process_create_event_polls_until_event_arrives(self) -> None:
        calls = {"count": 0}

        def fake_runner(*args, **kwargs):
            calls["count"] += 1
            # First poll returns malformed XML; the loop must tolerate the
            # ParseError and retry rather than crash, then correlate on retry.
            stdout = "<broken><" if calls["count"] == 1 else SAMPLE_SYSMON_XML
            return subprocess.CompletedProcess(
                args=args,
                returncode=0,
                stdout=stdout,
                stderr="",
            )

        criteria = ProcessCorrelationCriteria(
            host="DetFuzz-Win11-Lab",
            pid=4242,
            started_at_utc="2026-07-20T18:08:46+00:00",
            ended_at_utc="2026-07-20T18:08:48+00:00",
            command_fragment="-EncodedCommand",
        )

        result = wait_for_process_create_event(
            criteria,
            command_runner=fake_runner,
            timeout_seconds=2,
            poll_interval_seconds=0,
        )

        self.assertTrue(result.valid)
        self.assertEqual(calls["count"], 2)

    def test_wait_for_process_create_event_reports_missing_query_executable(self) -> None:
        def missing_runner(*args, **kwargs):
            raise FileNotFoundError("powershell missing")

        criteria = ProcessCorrelationCriteria(
            host="DetFuzz-Win11-Lab",
            pid=4242,
            started_at_utc="2026-07-20T18:08:46+00:00",
            ended_at_utc="2026-07-20T18:08:48+00:00",
            command_fragment="-EncodedCommand",
        )

        result = wait_for_process_create_event(
            criteria,
            command_runner=missing_runner,
            timeout_seconds=1,
            poll_interval_seconds=0,
        )

        self.assertFalse(result.valid)
        self.assertEqual(
            result.reason,
            "TELEMETRY_TIMEOUT:TELEMETRY_QUERY_FAILED",
        )

    def test_parse_sysmon_event_xml_rejects_entity_expansion(self) -> None:
        """xml.etree expands internal entities, so a DTD must never be parsed.

        Verified against the real vector rather than a string check: without the
        DOCTYPE guard this payload parses and &c; expands to 1000 characters,
        which is the first three levels of a billion-laughs amplification.
        """
        billion_laughs = (
            '<?xml version="1.0"?>\n'
            "<!DOCTYPE lolz [\n"
            ' <!ENTITY a "AAAAAAAAAA">\n'
            ' <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">\n'
            ' <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">\n'
            "]>\n"
            "<Event><Data>&c;</Data></Event>"
        )

        for parse in (parse_sysmon_event_xml, parse_sysmon_event_xml_many):
            with self.subTest(parser=parse.__name__):
                with self.assertRaises(ValueError) as raised:
                    parse(billion_laughs)
                self.assertIn("DOCTYPE", str(raised.exception))

    def test_parse_sysmon_event_xml_rejects_doctype_case_insensitively(self) -> None:
        for spelling in ("<!DOCTYPE", "<!doctype", "<!DocType"):
            with self.subTest(spelling=spelling):
                with self.assertRaises(ValueError):
                    parse_sysmon_event_xml(f'{spelling} Event [] >\n<Event />')

    def test_parse_sysmon_event_xml_still_accepts_normal_events(self) -> None:
        """The guard must not reject legitimate Sysmon telemetry."""
        event = parse_sysmon_event_xml(SAMPLE_SYSMON_XML)

        self.assertEqual(event.event_id, 1)
        self.assertEqual(len(parse_sysmon_event_xml_many(SAMPLE_SYSMON_XML)), 1)

        # A well-formed but non-Sysmon document with no numeric EventID must not
        # crash the parser; it falls back to the -1 sentinel and is later
        # rejected as WRONG_EVENT_ID by validation.
        no_event_id = parse_sysmon_event_xml("<Event><System /></Event>")
        self.assertEqual(no_event_id.event_id, -1)


if __name__ == "__main__":
    unittest.main()
