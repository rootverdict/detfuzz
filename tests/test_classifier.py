import unittest

from detfuzz.classifier import classify_case, finalize_candidate
from detfuzz.models import CaseObservation, Classification


class ClassifierTests(unittest.TestCase):
    def test_detected_when_rule_matches_after_valid_execution(self) -> None:
        observation = CaseObservation(case_id="B0", rule_matched=True)

        self.assertEqual(classify_case(observation), Classification.DETECTED)

    def test_invalid_mutant_when_exit_code_fails(self) -> None:
        observation = CaseObservation(case_id="NC1", exit_code=1, marker_valid=False)

        self.assertEqual(classify_case(observation), Classification.INVALID_MUTANT)

    def test_invalid_mutant_when_marker_is_missing_or_wrong(self) -> None:
        observation = CaseObservation(case_id="M1", marker_valid=False)

        self.assertEqual(classify_case(observation), Classification.INVALID_MUTANT)

    def test_telemetry_failure_when_no_process_event_arrives(self) -> None:
        observation = CaseObservation(case_id="M1", telemetry_received=False)

        self.assertEqual(classify_case(observation), Classification.TELEMETRY_FAILURE)

    def test_telemetry_incomplete_when_required_fields_missing(self) -> None:
        observation = CaseObservation(case_id="M1", required_fields_present=False)

        self.assertEqual(classify_case(observation), Classification.TELEMETRY_INCOMPLETE)

    def test_detection_engine_error_is_separate_from_bypass(self) -> None:
        observation = CaseObservation(case_id="M1", detection_engine_error=True)

        self.assertEqual(classify_case(observation), Classification.DETECTION_ENGINE_ERROR)

    def test_no_match_after_valid_execution_is_candidate_bypass(self) -> None:
        observation = CaseObservation(case_id="M1", rule_matched=False)

        self.assertEqual(
            classify_case(observation), Classification.CANDIDATE_VALID_BYPASS
        )

    def test_candidate_becomes_valid_bypass_when_closing_baseline_detects(self) -> None:
        result = finalize_candidate(
            Classification.CANDIDATE_VALID_BYPASS, Classification.DETECTED
        )

        self.assertEqual(result, Classification.VALID_BYPASS)

    def test_candidate_becomes_indeterminate_when_closing_baseline_fails(self) -> None:
        result = finalize_candidate(
            Classification.CANDIDATE_VALID_BYPASS, Classification.TELEMETRY_FAILURE
        )

        self.assertEqual(result, Classification.INDETERMINATE)


if __name__ == "__main__":
    unittest.main()
