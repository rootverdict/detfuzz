from __future__ import annotations

from detfuzz.models import CaseObservation, Classification


def classify_case(observation: CaseObservation) -> Classification:
    """Classify one case using the DetFuzz v0 decision model."""
    if observation.infrastructure_error:
        return Classification.INFRASTRUCTURE_ERROR

    if observation.exit_code != 0:
        return Classification.INVALID_MUTANT

    if not observation.marker_valid:
        return Classification.INVALID_MUTANT

    if not observation.executable_identity_valid:
        return Classification.INVALID_MUTANT

    if not observation.telemetry_received:
        return Classification.TELEMETRY_FAILURE

    if not observation.required_fields_present:
        return Classification.TELEMETRY_INCOMPLETE

    if observation.detection_engine_error:
        return Classification.DETECTION_ENGINE_ERROR

    if observation.rule_matched:
        return Classification.DETECTED

    return Classification.CANDIDATE_VALID_BYPASS


def finalize_candidate(
    candidate: Classification, closing_baseline: Classification
) -> Classification:
    """Promote or downgrade a candidate bypass after the closing control."""
    if candidate != Classification.CANDIDATE_VALID_BYPASS:
        return candidate

    if closing_baseline == Classification.DETECTED:
        return Classification.VALID_BYPASS

    return Classification.INDETERMINATE
