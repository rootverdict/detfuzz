"""DetFuzz local core package."""

from detfuzz.benign import V1_BENIGN_FIXTURES, run_benign_fixtures
from detfuzz.calibration import calibrate_timeouts, run_clock_preflight
from detfuzz.cases import V1_CASES
from detfuzz.classifier import classify_case
from detfuzz.detection import V1_ENCODED_POWERSHELL_RULE, evaluate_detection_rule
from detfuzz.models import CaseObservation, Classification, ProcessCorrelationCriteria
from detfuzz.oracle import validate_marker
from detfuzz.report import build_evidence_manifest, write_report_bundle
from detfuzz.runner import create_suite, prepare_case
from detfuzz.suite import run_v1_suite
from detfuzz.telemetry import (
    parse_sysmon_event_xml,
    query_and_correlate_process_create,
    validate_process_create_event,
)
from detfuzz.version import __version__

__all__ = [
    "CaseObservation",
    "Classification",
    "ProcessCorrelationCriteria",
    "V1_BENIGN_FIXTURES",
    "V1_ENCODED_POWERSHELL_RULE",
    "V1_CASES",
    "__version__",
    "calibrate_timeouts",
    "classify_case",
    "create_suite",
    "evaluate_detection_rule",
    "build_evidence_manifest",
    "parse_sysmon_event_xml",
    "prepare_case",
    "query_and_correlate_process_create",
    "run_benign_fixtures",
    "run_v1_suite",
    "run_clock_preflight",
    "validate_marker",
    "validate_process_create_event",
    "write_report_bundle",
]
