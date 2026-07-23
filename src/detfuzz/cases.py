from __future__ import annotations

from detfuzz.models import CaseKind, CaseSpec

V0_CASES: tuple[CaseSpec, ...] = (
    CaseSpec(
        case_id="B0",
        kind=CaseKind.BASELINE,
        transformation="standard -EncodedCommand",
        expected_marker=True,
    ),
    CaseSpec(
        case_id="M1",
        kind=CaseKind.MUTATION,
        transformation="-EncodedCommand alias changed to -enc",
        expected_marker=True,
    ),
    CaseSpec(
        case_id="M2",
        kind=CaseKind.MUTATION,
        transformation="valid capitalization variation",
        expected_marker=True,
    ),
    CaseSpec(
        case_id="M3",
        kind=CaseKind.MUTATION,
        transformation="valid whitespace variation",
        expected_marker=True,
    ),
    CaseSpec(
        case_id="M4",
        kind=CaseKind.MUTATION,
        transformation="valid quoting variation",
        expected_marker=True,
    ),
    CaseSpec(
        case_id="M5",
        kind=CaseKind.MUTATION,
        transformation="valid parameter-order variation",
        expected_marker=True,
    ),
    CaseSpec(
        case_id="NC1",
        kind=CaseKind.NEGATIVE_CONTROL,
        transformation="corrupted Base64 payload",
        expected_marker=False,
    ),
    CaseSpec(
        case_id="B1",
        kind=CaseKind.BASELINE,
        transformation="standard -EncodedCommand closing control",
        expected_marker=True,
    ),
)
