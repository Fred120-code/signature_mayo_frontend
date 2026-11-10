"""Structured, UI-independent trace records for MAYO scheme operations."""

from dataclasses import dataclass, field
from typing import Literal, TypeAlias

TraceData: TypeAlias = dict[
    str,
    str | int | bool | list[int] | list[list[int]] | None,
]
Dimensions: TypeAlias = dict[str, tuple[int, ...]]


@dataclass(frozen=True)
class TraceStep:
    """One pedagogical step recorded during a cryptographic operation.

    Attributes:
        number: One-based position in the containing trace.
        name: Stable machine-readable step identifier.
        description: Short explanation intended for display to a learner.
        data: Small, non-sensitive values associated with the step.
        dimensions: Names and shapes of relevant matrices or vectors.
        status: Outcome such as ``completed``, ``inconsistent``, or ``solved``.
        attempt: One-based signing attempt, or ``None`` for signature-wide steps.
        operation: Operation that produced this event.
    """

    number: int
    name: str
    description: str
    data: TraceData = field(default_factory=dict)
    dimensions: Dimensions = field(default_factory=dict)
    status: str = "completed"
    attempt: int | None = None
    operation: Literal["sign", "verify"] = "sign"

    @property
    def scope(self) -> Literal["signature", "attempt", "verification"]:
        """Return whether this step applies to Sign, an attempt, or Verify."""
        if self.operation == "verify":
            return "verification"
        return "attempt" if self.attempt is not None else "signature"


def _serialize_steps(steps: list[TraceStep]) -> dict[str, list[dict[str, object]]]:
    """Convert ordered trace steps to JSON-compatible built-in values."""
    return {
        "steps": [
            {
                "number": step.number,
                "name": step.name,
                "description": step.description,
                "data": step.data,
                "dimensions": {
                    name: list(shape)
                    for name, shape in step.dimensions.items()
                },
                "status": step.status,
                "attempt": step.attempt,
                "operation": step.operation,
                "scope": step.scope,
            }
            for step in steps
        ]
    }


@dataclass
class SignTrace:
    """Ordered trace of a single MAYO signature-generation operation."""

    steps: list[TraceStep] = field(default_factory=list)

    def add_step(
        self,
        name: str,
        description: str,
        *,
        data: TraceData | None = None,
        dimensions: Dimensions | None = None,
        status: str = "completed",
        attempt: int | None = None,
    ) -> TraceStep:
        """Append a step and assign its one-based sequence number."""
        step = TraceStep(
            number=len(self.steps) + 1,
            name=name,
            description=description,
            data={} if data is None else data,
            dimensions={} if dimensions is None else dimensions,
            status=status,
            attempt=attempt,
        )
        self.steps.append(step)
        return step

    def to_dict(self) -> dict[str, list[dict[str, object]]]:
        """Return the ordered trace as JSON-compatible built-in values."""
        return _serialize_steps(self.steps)


@dataclass
class VerifyTrace:
    """Ordered, UI-independent trace of a single Verify operation."""

    steps: list[TraceStep] = field(default_factory=list)

    def add_step(
        self,
        name: str,
        description: str,
        *,
        data: TraceData | None = None,
        dimensions: Dimensions | None = None,
        status: str = "completed",
    ) -> TraceStep:
        """Append a verification event and assign its one-based sequence."""
        step = TraceStep(
            number=len(self.steps) + 1,
            name=name,
            description=description,
            data={} if data is None else data,
            dimensions={} if dimensions is None else dimensions,
            status=status,
            operation="verify",
        )
        self.steps.append(step)
        return step

    def to_dict(self) -> dict[str, list[dict[str, object]]]:
        """Return the ordered verification trace as JSON-compatible values."""
        return _serialize_steps(self.steps)


class SignTraceError(RuntimeError):
    """Signing failure that preserves the trace when tracing was requested."""

    def __init__(self, message: str, trace: SignTrace) -> None:
        super().__init__(message)
        self.trace = trace
