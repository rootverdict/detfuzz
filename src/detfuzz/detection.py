from __future__ import annotations

from pathlib import Path
from typing import Any

from detfuzz.models import DetectionResult, DetectionRule, RuleDependency, SysmonEvent


V0_SIGMA_RULE_PATH = (
    Path(__file__).resolve().parent
    / "configs"
    / "v0-powershell-encoded-command.sigma.yml"
)


def evaluate_detection_rule(
    rule: DetectionRule,
    event: SysmonEvent,
    case_sensitive: bool = False,
) -> DetectionResult:
    dependency_results = {
        _dependency_key(dependency): evaluate_dependency(
            event, dependency, case_sensitive=case_sensitive
        )
        for dependency in rule.dependencies
    }
    matched = all(dependency_results.values())
    return DetectionResult(
        rule_id=rule.rule_id,
        matched=matched,
        reason="RULE_MATCHED" if matched else "RULE_NOT_MATCHED",
        dependency_results=dependency_results,
    )


def evaluate_dependency(
    event: SysmonEvent,
    dependency: RuleDependency,
    case_sensitive: bool = False,
) -> bool:
    observed = event.fields.get(dependency.field, "")
    expected = dependency.value
    if not case_sensitive:
        observed = observed.lower()
        expected = expected.lower()

    match dependency.operator:
        case "equals":
            return observed == expected
        case "contains":
            return expected in observed
        case "startswith":
            return observed.startswith(expected)
        case "endswith":
            return observed.endswith(expected)
        case _:
            raise ValueError(f"unsupported dependency operator: {dependency.operator}")


def extract_rule_dependencies_from_sigma_dict(
    sigma_rule: dict[str, Any],
    selection_name: str = "selection",
) -> DetectionRule:
    detection = sigma_rule.get("detection")
    if not isinstance(detection, dict):
        raise ValueError("Sigma rule missing detection mapping")

    selection = detection.get(selection_name)
    if not isinstance(selection, dict):
        raise ValueError(f"Sigma rule missing detection.{selection_name} mapping")

    dependencies = tuple(
        _dependency_from_sigma_field(field_expression, value)
        for field_expression, value in selection.items()
    )
    return DetectionRule(
        rule_id=str(sigma_rule.get("id", "unknown-rule")),
        title=str(sigma_rule.get("title", "Untitled Sigma rule")),
        dependencies=dependencies,
        slug=str(sigma_rule.get("detfuzz_slug", sigma_rule.get("name", ""))),
    )


def load_detection_rule_from_sigma(
    path: Path,
    allow_parser_fallback: bool = True,
) -> DetectionRule:
    try:
        sigma_collection = load_sigma_with_pysigma(path)
    except RuntimeError:
        if not allow_parser_fallback:
            raise
        return extract_rule_dependencies_from_sigma_dict(_load_minimal_sigma_yaml(path))

    sigma_rule = _sigma_collection_to_dict(sigma_collection, path)
    if not sigma_rule.get("detfuzz_slug"):
        sigma_rule["detfuzz_slug"] = _load_minimal_sigma_yaml(path).get(
            "detfuzz_slug",
            "",
        )
    return extract_rule_dependencies_from_sigma_dict(sigma_rule)


def load_sigma_with_pysigma(path: Path):
    try:
        from sigma.collection import SigmaCollection
    except ImportError as error:
        raise RuntimeError(
            "pySigma is not installed. Install pySigma before loading Sigma YAML."
        ) from error

    return SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))


def _sigma_collection_to_dict(sigma_collection: object, path: Path) -> dict[str, Any]:
    if hasattr(sigma_collection, "to_dicts"):
        rules = sigma_collection.to_dicts()
        if rules:
            return rules[0]

    rules = getattr(sigma_collection, "rules", None)
    if rules:
        first = rules[0]
        if hasattr(first, "to_dict"):
            return first.to_dict()

    # pySigma has already parsed the file at this point. The fallback keeps the
    # local v0 dependency extraction small and deterministic across pySigma
    # versions with different object APIs.
    return _load_minimal_sigma_yaml(path)


def _load_minimal_sigma_yaml(path: Path) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    detection: dict[str, Any] = {}
    selection: dict[str, str] = {}
    in_detection = False
    in_selection = False

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue

        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()

        if indent == 0:
            in_detection = stripped == "detection:"
            in_selection = False
            if stripped == "detection:":
                payload["detection"] = detection
                continue
            if ":" in stripped:
                key, value = stripped.split(":", 1)
                payload[key] = _strip_yaml_scalar(value.strip())
            continue

        if in_detection and indent == 2 and stripped == "selection:":
            detection["selection"] = selection
            in_selection = True
            continue

        if in_detection and in_selection and indent == 4 and ":" in stripped:
            key, value = stripped.split(":", 1)
            selection[key.strip()] = _strip_yaml_scalar(value.strip())

    if "detection" not in payload:
        raise ValueError(f"Sigma rule missing detection block: {path}")
    return payload


def _strip_yaml_scalar(value: str) -> str:
    if (
        (value.startswith("'") and value.endswith("'"))
        or (value.startswith('"') and value.endswith('"'))
    ):
        return value[1:-1]
    return value


def _dependency_from_sigma_field(field_expression: str, value: object) -> RuleDependency:
    parts = field_expression.split("|")
    field = parts[0]
    operator = parts[1] if len(parts) > 1 else "equals"

    if isinstance(value, list):
        if len(value) != 1:
            raise ValueError("v0 dependency extraction expects one value per field")
        value = value[0]

    return RuleDependency(field=field, operator=operator, value=str(value))


def _dependency_key(dependency: RuleDependency) -> str:
    return f"{dependency.field}|{dependency.operator}|{dependency.value}"


V0_ENCODED_POWERSHELL_RULE = load_detection_rule_from_sigma(V0_SIGMA_RULE_PATH)
