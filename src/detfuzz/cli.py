from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from detfuzz.benign import (
    V01_BENIGN_FIXTURES,
    prepare_benign_fixture,
    run_benign_fixtures,
)
from detfuzz.calibration import calibrate_timeouts, run_clock_preflight
from detfuzz.cases import V0_CASES
from detfuzz.classifier import classify_case, finalize_candidate
from detfuzz.detection import V0_ENCODED_POWERSHELL_RULE, evaluate_detection_rule
from detfuzz.models import CaseObservation, ProcessCorrelationCriteria
from detfuzz.report import result_to_json, write_report_bundle
from detfuzz.runner import create_suite, prepare_case
from detfuzz.suite import run_v0_suite
from detfuzz.telemetry import parse_sysmon_event_xml, query_and_correlate_process_create


SIMULATION_NOTE = "SIMULATED - not from a real run"
PREPARED_ONLY_NOTE = "PHASE_2_PREPARED_ONLY - commands generated but not executed"


def simulated_observation(case_id: str) -> CaseObservation:
    if case_id == "NC1":
        return CaseObservation(case_id=case_id, exit_code=1, marker_valid=False)

    return CaseObservation(case_id=case_id, rule_matched=case_id in {"B0", "B1"})


def simulate_report() -> None:
    observations = [simulated_observation(case.case_id) for case in V0_CASES]
    classified = {
        observation.case_id: classify_case(observation) for observation in observations
    }
    closing = classified["B1"]

    for observation in observations:
        classification = finalize_candidate(classified[observation.case_id], closing)
        print(result_to_json(observation, classification, note=SIMULATION_NOTE))


def prepare_suite(root: Path, powershell_path: str) -> None:
    suite = create_suite(root)
    prepared_cases = [
        prepare_case(suite, case, powershell_path=powershell_path) for case in V0_CASES
    ]
    payload = {
        "note": PREPARED_ONLY_NOTE,
        "suite_id": suite.suite_id,
        "suite_path": str(suite.suite_path),
        "cases": [
            {
                "case_id": prepared.case.case_id,
                "kind": prepared.case.kind.value,
                "transformation": prepared.case.transformation,
                "case_path": str(prepared.case_path),
                "marker_path": str(prepared.marker_path),
                "expected_marker": prepared.case.expected_marker,
                "command_line": prepared.command_line,
            }
            for prepared in prepared_cases
        ],
    }
    print(json.dumps(payload, indent=2, sort_keys=True))


def prepare_benign_fixtures(root: Path, powershell_path: str) -> None:
    suite = create_suite(root)
    prepared_fixtures = [
        prepare_benign_fixture(suite, fixture, powershell_path=powershell_path)
        for fixture in V01_BENIGN_FIXTURES
    ]
    payload = {
        "note": PREPARED_ONLY_NOTE,
        "suite_id": suite.suite_id,
        "suite_path": str(suite.suite_path),
        "fixtures": [
            {
                "fixture_id": prepared.fixture.fixture_id,
                "description": prepared.fixture.description,
                "invocation": prepared.fixture.invocation,
                "fixture_path": str(prepared.fixture_path),
                "predicted_v0_rule_match": prepared.fixture.predicted_v0_rule_match,
                "command_line": prepared.command_line,
            }
            for prepared in prepared_fixtures
        ],
    }
    print(json.dumps(payload, indent=2, sort_keys=True))


def validate_telemetry(args: argparse.Namespace) -> None:
    criteria = ProcessCorrelationCriteria(
        host=args.host,
        pid=args.pid,
        started_at_utc=args.started,
        ended_at_utc=args.ended,
        image_suffix=args.image_suffix,
        command_fragment=args.command_fragment,
        required_hash_algorithm=args.required_hash_algorithm,
    )
    result = query_and_correlate_process_create(
        criteria,
        powershell_exe=args.powershell_path,
        max_events=args.max_events,
    )
    print(json.dumps(asdict(result), indent=2, sort_keys=True, default=str))


def evaluate_detection(args: argparse.Namespace) -> None:
    event = parse_sysmon_event_xml(args.xml.read_text(encoding="utf-8"))
    result = evaluate_detection_rule(V0_ENCODED_POWERSHELL_RULE, event)
    print(json.dumps(asdict(result), indent=2, sort_keys=True))


def build_report(args: argparse.Namespace) -> None:
    paths = write_report_bundle(args.suite_results, args.evidence_root, args.output_dir)
    payload = {name: str(path) for name, path in paths.items()}
    print(json.dumps(payload, indent=2, sort_keys=True))


def run_suite(args: argparse.Namespace) -> None:
    result = run_v0_suite(
        output_root=args.output_root,
        host=args.host,
        powershell_path=args.powershell_path,
        timeout_seconds=args.timeout_seconds,
        telemetry_timeout_seconds=args.telemetry_timeout_seconds,
        max_events=args.max_events,
        calibration_result_path=args.calibration_result,
    )
    print(json.dumps(result, indent=2, sort_keys=True, default=str))


def clock_preflight(args: argparse.Namespace) -> None:
    result = run_clock_preflight(powershell_exe=args.powershell_path)
    print(json.dumps(result, indent=2, sort_keys=True, default=str))


def calibrate(args: argparse.Namespace) -> None:
    result = calibrate_timeouts(
        output_root=args.output_root,
        host=args.host,
        runs=args.runs,
        powershell_path=args.powershell_path,
        process_timeout_seconds=args.process_timeout_seconds,
        max_events=args.max_events,
    )
    print(json.dumps(result, indent=2, sort_keys=True, default=str))


def run_benign(args: argparse.Namespace) -> None:
    result = run_benign_fixtures(
        output_root=args.output_root,
        host=args.host,
        powershell_path=args.powershell_path,
        timeout_seconds=args.timeout_seconds,
        max_events=args.max_events,
    )
    print(json.dumps(result, indent=2, sort_keys=True, default=str))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="detfuzz")
    subcommands = parser.add_subparsers(dest="command")

    subcommands.add_parser(
        "simulate-report",
        help="Print fake classifier output for local development.",
    )

    prepare = subcommands.add_parser(
        "prepare-suite",
        help="Create v0 case directories and print allow-listed PowerShell commands.",
    )
    prepare.add_argument(
        "--root",
        type=Path,
        default=Path("artifacts") / "runs",
        help="Directory where the fresh suite folder will be created.",
    )
    prepare.add_argument(
        "--powershell-path",
        default="powershell.exe",
        help="PowerShell executable path to place in generated commands.",
    )

    benign_prepare = subcommands.add_parser(
        "prepare-benign-fixtures",
        help="Create v0.1 benign fixture directories and print safe commands.",
    )
    benign_prepare.add_argument(
        "--root",
        type=Path,
        default=Path("artifacts") / "benign",
        help="Directory where the fresh benign suite folder will be created.",
    )
    benign_prepare.add_argument(
        "--powershell-path",
        default="powershell.exe",
        help="PowerShell executable path to place in generated commands.",
    )

    validate = subcommands.add_parser(
        "validate-telemetry",
        help="Query Sysmon and validate one Process Create event.",
    )
    validate.add_argument("--host", required=True, help="Expected Sysmon Computer name.")
    validate.add_argument("--pid", required=True, type=int, help="Expected process PID.")
    validate.add_argument(
        "--started",
        required=True,
        help="Execution start time in UTC ISO-8601 format.",
    )
    validate.add_argument(
        "--ended",
        required=True,
        help="Execution end time in UTC ISO-8601 format.",
    )
    validate.add_argument(
        "--command-fragment",
        default="EncodedCommand",
        help="Expected command-line fragment.",
    )
    validate.add_argument(
        "--image-suffix",
        default=r"\powershell.exe",
        help="Expected executable image suffix.",
    )
    validate.add_argument(
        "--required-hash-algorithm",
        default="SHA256",
        help="Required hash algorithm prefix in Sysmon Hashes.",
    )
    validate.add_argument(
        "--max-events",
        default=200,
        type=int,
        help="Number of recent Sysmon events to inspect.",
    )
    validate.add_argument(
        "--powershell-path",
        default="powershell.exe",
        help="PowerShell executable used to query Sysmon.",
    )

    detection = subcommands.add_parser(
        "evaluate-detection",
        help="Evaluate the v0 detection rule against a saved Sysmon XML event.",
    )
    detection.add_argument(
        "--xml",
        type=Path,
        required=True,
        help="Path to a saved Sysmon Event XML file.",
    )

    report = subcommands.add_parser(
        "build-report",
        help="Build JSON and Markdown reports from suite results and evidence files.",
    )
    report.add_argument(
        "--suite-results",
        type=Path,
        required=True,
        help="Path to suite results JSON.",
    )
    report.add_argument(
        "--evidence-root",
        type=Path,
        required=True,
        help="Directory containing evidence files to hash.",
    )
    report.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Directory where reports will be written.",
    )

    suite = subcommands.add_parser(
        "run-suite",
        help="Run the full DetFuzz v0 sequence and write evidence reports.",
    )
    suite.add_argument(
        "--output-root",
        type=Path,
        required=True,
        help="Root directory where the suite folder will be created.",
    )
    suite.add_argument(
        "--host",
        required=True,
        help="Expected Sysmon Computer name.",
    )
    suite.add_argument(
        "--powershell-path",
        default="powershell.exe",
        help="PowerShell executable used for test cases.",
    )
    suite.add_argument(
        "--timeout-seconds",
        type=int,
        default=30,
        help="Per-case process timeout.",
    )
    suite.add_argument(
        "--telemetry-timeout-seconds",
        type=int,
        default=30,
        help="Maximum time to poll for each matching Sysmon event.",
    )
    suite.add_argument(
        "--calibration-result",
        type=Path,
        default=None,
        help="Optional timeout-calibration JSON whose selected timeouts override defaults.",
    )
    suite.add_argument(
        "--max-events",
        type=int,
        default=5000,
        help="Number of recent Sysmon events to inspect per case.",
    )

    preflight = subcommands.add_parser(
        "clock-preflight",
        help="Check UTC clock offset before running timing-sensitive tests.",
    )
    preflight.add_argument(
        "--powershell-path",
        default="powershell.exe",
        help="PowerShell executable used for target clock query.",
    )

    calibration = subcommands.add_parser(
        "calibrate-timeouts",
        help="Run repeated B0 baselines and measure process/telemetry timing.",
    )
    calibration.add_argument(
        "--output-root",
        type=Path,
        required=True,
        help="Root directory where the calibration suite folder will be created.",
    )
    calibration.add_argument("--host", required=True, help="Expected Sysmon Computer name.")
    calibration.add_argument(
        "--runs",
        type=int,
        default=20,
        help="Number of B0 calibration runs.",
    )
    calibration.add_argument(
        "--powershell-path",
        default="powershell.exe",
        help="PowerShell executable used for test cases.",
    )
    calibration.add_argument(
        "--process-timeout-seconds",
        type=int,
        default=30,
        help="Per-process timeout during calibration.",
    )
    calibration.add_argument(
        "--max-events",
        type=int,
        default=5000,
        help="Number of recent Sysmon events to inspect per calibration run.",
    )

    benign = subcommands.add_parser(
        "run-benign-fixtures",
        help="Run v0.1 benign PowerShell fixtures and report benign alerts.",
    )
    benign.add_argument(
        "--output-root",
        type=Path,
        required=True,
        help="Root directory where the benign fixture suite folder will be created.",
    )
    benign.add_argument("--host", required=True, help="Expected Sysmon Computer name.")
    benign.add_argument(
        "--powershell-path",
        default="powershell.exe",
        help="PowerShell executable used for benign fixtures.",
    )
    benign.add_argument(
        "--timeout-seconds",
        type=int,
        default=30,
        help="Per-fixture process timeout.",
    )
    benign.add_argument(
        "--max-events",
        type=int,
        default=5000,
        help="Number of recent Sysmon events to inspect per fixture.",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command in {None, "simulate-report"}:
        simulate_report()
        return

    if args.command == "prepare-suite":
        prepare_suite(args.root, args.powershell_path)
        return

    if args.command == "prepare-benign-fixtures":
        prepare_benign_fixtures(args.root, args.powershell_path)
        return

    if args.command == "validate-telemetry":
        validate_telemetry(args)
        return

    if args.command == "evaluate-detection":
        evaluate_detection(args)
        return

    if args.command == "build-report":
        build_report(args)
        return

    if args.command == "run-suite":
        run_suite(args)
        return

    if args.command == "clock-preflight":
        clock_preflight(args)
        return

    if args.command == "calibrate-timeouts":
        calibrate(args)
        return

    if args.command == "run-benign-fixtures":
        run_benign(args)
        return

    parser.error(f"unsupported command: {args.command}")


if __name__ == "__main__":
    main()
