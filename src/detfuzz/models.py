from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path


class Classification(StrEnum):
    INFRASTRUCTURE_ERROR = "INFRASTRUCTURE_ERROR"
    INVALID_MUTANT = "INVALID_MUTANT"
    TELEMETRY_FAILURE = "TELEMETRY_FAILURE"
    TELEMETRY_INCOMPLETE = "TELEMETRY_INCOMPLETE"
    DETECTION_ENGINE_ERROR = "DETECTION_ENGINE_ERROR"
    DETECTED = "DETECTED"
    CANDIDATE_VALID_BYPASS = "CANDIDATE_VALID_BYPASS"
    VALID_BYPASS = "VALID_BYPASS"
    INDETERMINATE = "INDETERMINATE"


class CaseKind(StrEnum):
    BASELINE = "baseline"
    MUTATION = "mutation"
    NEGATIVE_CONTROL = "negative_control"


@dataclass(frozen=True)
class CaseSpec:
    case_id: str
    kind: CaseKind
    transformation: str
    expected_marker: bool


@dataclass(frozen=True)
class CaseObservation:
    case_id: str
    infrastructure_error: bool = False
    exit_code: int | None = 0
    marker_valid: bool = True
    executable_identity_valid: bool = True
    telemetry_received: bool = True
    required_fields_present: bool = True
    detection_engine_error: bool = False
    rule_matched: bool = False
    details: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class SuiteContext:
    suite_id: str
    suite_path: Path


@dataclass(frozen=True)
class PreparedCase:
    case: CaseSpec
    suite_id: str
    case_path: Path
    marker_path: Path
    nonce: str
    encoded_payload: str
    command_line: str


@dataclass(frozen=True)
class ProcessExecution:
    case_id: str
    command_line: str
    pid: int | None
    started_at_utc: str
    ended_at_utc: str
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool = False


@dataclass(frozen=True)
class MarkerValidation:
    valid: bool
    exists: bool
    reason: str
    content: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class SysmonEvent:
    event_id: int
    provider: str
    utc_time: str
    computer: str
    record_id: str
    fields: dict[str, str]
    raw_xml: str = ""


@dataclass(frozen=True)
class TelemetryValidation:
    valid: bool
    reason: str
    event: SysmonEvent | None = None
    missing_fields: tuple[str, ...] = ()


@dataclass(frozen=True)
class ExecutableIdentityValidation:
    valid: bool
    reason: str
    expected_sha256: str | None = None
    observed_sha256: str | None = None
    image: str | None = None


@dataclass(frozen=True)
class ProcessCorrelationCriteria:
    host: str
    pid: int
    started_at_utc: str
    ended_at_utc: str
    image_suffix: str = r"\powershell.exe"
    command_fragment: str = "EncodedCommand"
    required_hash_algorithm: str = "SHA256"


@dataclass(frozen=True)
class RuleDependency:
    field: str
    operator: str
    value: str


@dataclass(frozen=True)
class DetectionRule:
    rule_id: str
    title: str
    dependencies: tuple[RuleDependency, ...]
    slug: str = ""


@dataclass(frozen=True)
class DetectionResult:
    rule_id: str
    matched: bool
    reason: str
    dependency_results: dict[str, bool] = field(default_factory=dict)
    error: bool = False


@dataclass(frozen=True)
class EvidenceFile:
    path: str
    size_bytes: int
    sha256: str


@dataclass(frozen=True)
class EvidenceManifest:
    root: str
    files: tuple[EvidenceFile, ...]
