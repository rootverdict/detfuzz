from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace


@dataclass(frozen=True)
class PowerShellInvocation:
    executable: str
    options: tuple[str, ...]
    encoded_parameter: str
    payload: str
    separator: str = " "
    quote_parameter: bool = False

    def render(self) -> str:
        parameter = (
            f'"{self.encoded_parameter}"'
            if self.quote_parameter
            else self.encoded_parameter
        )
        return self.separator.join(
            (self.executable, *self.options, parameter, self.payload)
        )


MutationOperator = Callable[[PowerShellInvocation], PowerShellInvocation]


def _use_alias(invocation: PowerShellInvocation) -> PowerShellInvocation:
    return replace(invocation, encoded_parameter="-enc")


def _change_capitalization(
    invocation: PowerShellInvocation,
) -> PowerShellInvocation:
    return replace(invocation, encoded_parameter="-eNcOdEdCoMmAnD")


def _expand_whitespace(invocation: PowerShellInvocation) -> PowerShellInvocation:
    return replace(invocation, separator="    ")


def _quote_parameter(invocation: PowerShellInvocation) -> PowerShellInvocation:
    return replace(invocation, quote_parameter=True)


def _reorder_options(invocation: PowerShellInvocation) -> PowerShellInvocation:
    return replace(invocation, options=tuple(reversed(invocation.options)))


MUTATION_OPERATORS: dict[str, MutationOperator] = {
    "M1": _use_alias,
    "M2": _change_capitalization,
    "M3": _expand_whitespace,
    "M4": _quote_parameter,
    "M5": _reorder_options,
}


def build_v0_command(
    case_id: str,
    executable: str,
    encoded_payload: str,
) -> str:
    payload = "!!!invalid-base64!!!" if case_id == "NC1" else encoded_payload
    invocation = PowerShellInvocation(
        executable=executable,
        options=("-NoProfile", "-NonInteractive"),
        encoded_parameter="-EncodedCommand",
        payload=payload,
    )

    operator = MUTATION_OPERATORS.get(case_id)
    if operator is not None:
        invocation = operator(invocation)
    elif case_id not in {"B0", "B1", "NC1"}:
        raise ValueError(f"case is not allow-listed: {case_id}")

    return invocation.render()
