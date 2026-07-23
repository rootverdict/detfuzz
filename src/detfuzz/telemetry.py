from __future__ import annotations

import subprocess
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from detfuzz.models import (
    ProcessCorrelationCriteria,
    ProcessExecution,
    SysmonEvent,
    TelemetryValidation,
)

SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"
PROCESS_CREATE_EVENT_ID = 1
REQUIRED_PROCESS_CREATE_FIELDS = (
    "UtcTime",
    "ProcessGuid",
    "ProcessId",
    "Image",
    "CommandLine",
    "ParentImage",
    "Hashes",
)


def parse_sysmon_event_xml(xml_text: str) -> SysmonEvent:
    stripped_xml = xml_text.strip()
    root = ET.fromstring(stripped_xml)
    namespace = _namespace(root.tag)

    def system_text(name: str) -> str:
        node = root.find(f"./{namespace}System/{namespace}{name}")
        return "" if node is None or node.text is None else node.text

    provider_node = root.find(f"./{namespace}System/{namespace}Provider")
    provider = "" if provider_node is None else provider_node.attrib.get("Name", "")
    event_id = int(system_text("EventID"))

    time_node = root.find(f"./{namespace}System/{namespace}TimeCreated")
    utc_time = "" if time_node is None else time_node.attrib.get("SystemTime", "")
    computer = system_text("Computer")
    record_id = system_text("EventRecordID")

    fields: dict[str, str] = {}
    for data in root.findall(f"./{namespace}EventData/{namespace}Data"):
        name = data.attrib.get("Name")
        if name:
            fields[name] = "" if data.text is None else data.text

    return SysmonEvent(
        event_id=event_id,
        provider=provider,
        utc_time=utc_time,
        computer=computer,
        record_id=record_id,
        fields=fields,
        raw_xml=stripped_xml,
    )


def parse_sysmon_event_xml_many(xml_text: str) -> list[SysmonEvent]:
    stripped = xml_text.strip()
    if not stripped:
        return []

    try:
        return [parse_sysmon_event_xml(stripped)]
    except ET.ParseError:
        pass

    wrapped = ET.fromstring(f"<Events>{stripped}</Events>")
    return [
        parse_sysmon_event_xml(ET.tostring(child, encoding="unicode"))
        for child in list(wrapped)
    ]


def validate_process_create_event(
    event: SysmonEvent,
    required_fields: tuple[str, ...] = REQUIRED_PROCESS_CREATE_FIELDS,
) -> TelemetryValidation:
    if event.provider != SYSMON_PROVIDER:
        return TelemetryValidation(False, "WRONG_PROVIDER", event)

    if event.event_id != PROCESS_CREATE_EVENT_ID:
        return TelemetryValidation(False, "WRONG_EVENT_ID", event)

    missing = tuple(field for field in required_fields if not event.fields.get(field))
    if missing:
        return TelemetryValidation(False, "REQUIRED_FIELDS_MISSING", event, missing)

    return TelemetryValidation(True, "TELEMETRY_COMPLETE", event)


def correlate_process_create_event(
    events: list[SysmonEvent],
    execution: ProcessExecution,
    command_fragment: str,
    image_suffix: str = r"\powershell.exe",
) -> TelemetryValidation:
    if execution.pid is None:
        return TelemetryValidation(False, "EXECUTION_PID_MISSING")

    criteria = ProcessCorrelationCriteria(
        host="",
        pid=execution.pid,
        started_at_utc=execution.started_at_utc,
        ended_at_utc=execution.ended_at_utc,
        image_suffix=image_suffix,
        command_fragment=command_fragment,
    )
    candidates = [event for event in events if event_matches_process(event, criteria)]

    if not candidates:
        return TelemetryValidation(False, "NO_MATCHING_PROCESS_CREATE_EVENT")

    return validate_process_create_event(candidates[0])


def event_matches_process(
    event: SysmonEvent,
    criteria: ProcessCorrelationCriteria,
    clock_tolerance_seconds: int = 5,
) -> bool:
    if event.event_id != PROCESS_CREATE_EVENT_ID or event.provider != SYSMON_PROVIDER:
        return False

    if criteria.host and event.computer.lower() != criteria.host.lower():
        return False

    if event.fields.get("ProcessId") != str(criteria.pid):
        return False

    if not event.fields.get("Image", "").lower().endswith(
        criteria.image_suffix.lower()
    ):
        return False

    if criteria.command_fragment.lower() not in event.fields.get(
        "CommandLine", ""
    ).lower():
        return False

    if criteria.required_hash_algorithm:
        expected_prefix = criteria.required_hash_algorithm.upper() + "="
        if expected_prefix not in event.fields.get("Hashes", "").upper():
            return False

    return _event_inside_window(
        event,
        criteria.started_at_utc,
        criteria.ended_at_utc,
        clock_tolerance_seconds,
    )


def query_sysmon_process_create_xml(
    powershell_exe: str = "powershell.exe",
    max_events: int = 200,
    command_runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> str:
    script = (
        "$ErrorActionPreference = 'Stop'; "
        "Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' "
        f"-MaxEvents {max_events} | "
        "Where-Object { $_.Id -eq 1 } | "
        "ForEach-Object { $_.ToXml() }"
    )
    completed = command_runner(
        [
            powershell_exe,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "Sysmon query failed")
    return completed.stdout


def query_and_correlate_process_create(
    criteria: ProcessCorrelationCriteria,
    powershell_exe: str = "powershell.exe",
    max_events: int = 200,
    command_runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> TelemetryValidation:
    xml_text = query_sysmon_process_create_xml(
        powershell_exe=powershell_exe,
        max_events=max_events,
        command_runner=command_runner,
    )
    events = parse_sysmon_event_xml_many(xml_text)
    candidates = [event for event in events if event_matches_process(event, criteria)]
    if not candidates:
        return TelemetryValidation(False, "NO_MATCHING_PROCESS_CREATE_EVENT")
    return validate_process_create_event(candidates[0])


def wait_for_process_create_event(
    criteria: ProcessCorrelationCriteria,
    powershell_exe: str = "powershell.exe",
    max_events: int = 200,
    timeout_seconds: int = 30,
    poll_interval_seconds: float = 0.5,
    command_runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    sleeper: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> TelemetryValidation:
    deadline = monotonic() + timeout_seconds
    last_result = TelemetryValidation(False, "TELEMETRY_POLL_NOT_STARTED")

    while True:
        try:
            result = query_and_correlate_process_create(
                criteria,
                powershell_exe=powershell_exe,
                max_events=max_events,
                command_runner=command_runner,
            )
        except RuntimeError:
            result = TelemetryValidation(False, "TELEMETRY_QUERY_FAILED")

        if result.event is not None:
            return result

        last_result = result
        remaining = deadline - monotonic()
        if remaining <= 0:
            return TelemetryValidation(
                False,
                f"TELEMETRY_TIMEOUT:{last_result.reason}",
                last_result.event,
                last_result.missing_fields,
            )
        sleeper(min(poll_interval_seconds, remaining))


def _namespace(tag: str) -> str:
    if tag.startswith("{"):
        return tag.split("}", 1)[0] + "}"
    return ""


def _event_inside_window(
    event: SysmonEvent,
    started_at_utc: str,
    ended_at_utc: str,
    tolerance_seconds: int,
) -> bool:
    event_time = _parse_event_time(event.utc_time or event.fields.get("UtcTime", ""))
    started_at = _parse_event_time(started_at_utc)
    ended_at = _parse_event_time(ended_at_utc)
    tolerance = timedelta(seconds=tolerance_seconds)
    return started_at - tolerance <= event_time <= ended_at + tolerance


def _parse_event_time(value: str) -> datetime:
    normalized = value.strip().replace("Z", "+00:00")
    if " " in normalized and "T" not in normalized:
        normalized = normalized.replace(" ", "T") + "+00:00"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)
