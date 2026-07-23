from __future__ import annotations

import hashlib
import hmac
import shutil
from pathlib import Path

from detfuzz.models import ExecutableIdentityValidation, TelemetryValidation


def expected_executable_sha256(executable_path: str) -> str | None:
    resolved = _resolve_executable(executable_path)
    if resolved is None:
        return None

    digest = hashlib.sha256()
    with resolved.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def validate_executable_identity(
    telemetry: TelemetryValidation,
    expected_sha256: str | None,
) -> ExecutableIdentityValidation:
    if expected_sha256 is None:
        return ExecutableIdentityValidation(False, "EXPECTED_EXECUTABLE_HASH_UNAVAILABLE")
    if telemetry.event is None:
        return ExecutableIdentityValidation(False, "TELEMETRY_EVENT_MISSING", expected_sha256)

    observed = extract_hash_value(telemetry.event.fields.get("Hashes", ""), "SHA256")
    if observed is None:
        return ExecutableIdentityValidation(
            False,
            "OBSERVED_SHA256_MISSING",
            expected_sha256=expected_sha256,
            image=telemetry.event.fields.get("Image"),
        )

    valid = hmac.compare_digest(expected_sha256.upper(), observed.upper())
    return ExecutableIdentityValidation(
        valid,
        "EXECUTABLE_IDENTITY_MATCH" if valid else "EXECUTABLE_IDENTITY_MISMATCH",
        expected_sha256=expected_sha256.upper(),
        observed_sha256=observed.upper(),
        image=telemetry.event.fields.get("Image"),
    )


def extract_hash_value(hashes_field: str, algorithm: str) -> str | None:
    prefix = algorithm.upper() + "="
    for part in hashes_field.split(","):
        stripped = part.strip()
        if stripped.upper().startswith(prefix):
            return stripped.split("=", 1)[1]
    return None


def _resolve_executable(executable_path: str) -> Path | None:
    path = Path(executable_path)
    if path.is_file():
        return path

    resolved = shutil.which(executable_path)
    if resolved is None:
        return None
    return Path(resolved)
