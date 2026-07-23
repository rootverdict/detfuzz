from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from detfuzz.contract import validate_suite_report_shape
from detfuzz.models import (
    CaseObservation,
    Classification,
    EvidenceFile,
    EvidenceManifest,
)


def result_to_json(
    observation: CaseObservation,
    classification: Classification,
    note: str | None = None,
) -> str:
    payload = {
        "case_id": observation.case_id,
        "classification": classification.value,
        "observation": asdict(observation),
    }
    if note is not None:
        payload["note"] = note
    return json.dumps(payload, indent=2, sort_keys=True)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_evidence_manifest(root: Path) -> EvidenceManifest:
    resolved_root = root.resolve()
    files: list[EvidenceFile] = []

    if not resolved_root.exists():
        raise FileNotFoundError(f"evidence root does not exist: {resolved_root}")

    for path in sorted(item for item in resolved_root.rglob("*") if item.is_file()):
        relative = path.relative_to(resolved_root).as_posix()
        files.append(
            EvidenceFile(
                path=relative,
                size_bytes=path.stat().st_size,
                sha256=sha256_file(path),
            )
        )

    return EvidenceManifest(root=str(resolved_root), files=tuple(files))


def load_suite_results(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict):
        raise ValueError("suite results must be a JSON object")
    if not payload.get("suite_id"):
        raise ValueError("suite results missing suite_id")
    if not isinstance(payload.get("cases"), list):
        raise ValueError("suite results missing cases list")
    return payload


def build_suite_report(
    suite_results: dict[str, Any],
    manifest: EvidenceManifest,
    generated_at_utc: str | None = None,
) -> dict[str, Any]:
    generated = generated_at_utc or datetime.now(UTC).isoformat()
    cases = suite_results["cases"]
    classifications = _classification_counts(cases)
    suite_status = suite_results.get("suite_status")
    if suite_status is None:
        suite_status = "UNKNOWN"
    elif not isinstance(suite_status, str) or not suite_status.strip():
        raise ValueError("suite_status must be a non-empty string when provided")
    return {
        "schema_version": "1.0",
        "generated_at_utc": generated,
        "suite_id": suite_results["suite_id"],
        "suite_status": suite_status,
        "abort_reason": suite_results.get("abort_reason"),
        "environment": suite_results.get("environment", {}),
        "case_count": len(cases),
        "classification_counts": classifications,
        "cases": cases,
        "evidence_manifest": asdict(manifest),
        "notes": suite_results.get("notes", []),
    }


def render_markdown_report(report: dict[str, Any]) -> str:
    lines = [
        "# DetFuzz Evidence Report",
        "",
        f"Suite ID: `{report['suite_id']}`",
        f"Suite status: `{report.get('suite_status', 'UNKNOWN')}`",
        f"Generated UTC: `{report['generated_at_utc']}`",
        f"Case count: `{report['case_count']}`",
        "",
        "## Classification Summary",
        "",
    ]

    for classification, count in sorted(report["classification_counts"].items()):
        lines.append(f"- `{classification}`: {count}")

    lines.extend(["", "## Cases", ""])

    for case in report["cases"]:
        case_id = case.get("case_id", "unknown")
        classification = case.get("classification", "UNKNOWN")
        lines.append(f"- `{case_id}`: `{classification}`")

    lines.extend(["", "## Evidence Manifest", ""])
    files = report["evidence_manifest"]["files"]
    if not files:
        lines.append("No evidence files were found.")
    else:
        for file_info in files:
            lines.append(
                f"- `{file_info['path']}` "
                f"({file_info['size_bytes']} bytes, sha256 `{file_info['sha256']}`)"
            )

    notes = report.get("notes", [])
    if notes:
        lines.extend(["", "## Notes", ""])
        for note in notes:
            lines.append(f"- {note}")

    lines.append("")
    return "\n".join(lines)


def write_report_bundle(
    suite_results_path: Path,
    evidence_root: Path,
    output_dir: Path,
) -> dict[str, Path]:
    suite_results = load_suite_results(suite_results_path)
    manifest = build_evidence_manifest(evidence_root)
    report = build_suite_report(suite_results, manifest)
    validate_suite_report_shape(report)

    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "suite-report.json"
    markdown_path = output_dir / "suite-report.md"
    manifest_path = output_dir / "evidence-manifest.json"

    json_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    markdown_path.write_text(render_markdown_report(report), encoding="utf-8")
    manifest_path.write_text(
        json.dumps(asdict(manifest), indent=2, sort_keys=True),
        encoding="utf-8",
    )

    return {
        "json_report": json_path,
        "markdown_report": markdown_path,
        "evidence_manifest": manifest_path,
    }


def _classification_counts(cases: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for case in cases:
        classification = str(case.get("classification", "UNKNOWN"))
        counts[classification] = counts.get(classification, 0) + 1
    return counts
