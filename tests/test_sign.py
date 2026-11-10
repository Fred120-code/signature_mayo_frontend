"""Tests for sample-solution and signature generation."""

import json

import pytest

import scheme.sign as sign_module

from core.matrix import matrix_vector_multiply
from crypto.hashing import derive_key_material
from keys.expand_public import expand_public_key, generate_P1_P2
from keys.expand_secret import decode_O, expand_secret_key
from keys.keygen import compute_P3, encode_P3
from keys.parameters import (
    K,
    M,
    O_DIM,
    SALT_BYTES,
    SEED_PK_BYTES,
    SEED_SK_BYTES,
    V,
)
from scheme.sample_solution import sample_solution
from scheme.sign import sign
from scheme.verify import verify


def test_sample_solution_solves_and_rejects_inconsistent_systems() -> None:
    """SampleSolution returns a satisfying vector or None for inconsistency."""
    matrix = [[1, 0, 1], [0, 1, 1]]
    target = [5, 3]
    random_vector = [2, 4, 6]
    solution = sample_solution(matrix, target, random_vector)

    assert solution is not None
    assert matrix_vector_multiply(matrix, solution) == target
    assert sample_solution([[1, 1], [1, 1]], [1, 2], [0, 0]) is None


def test_sample_solution_rejects_compatible_rank_deficient_system() -> None:
    """SampleSolution rejects systems whose rank is below their row count."""
    matrix = [[1, 1], [2, 2]]
    target = [1, 2]

    assert sample_solution(matrix, target, [0, 0]) is None


def test_signature_uses_existing_encoding_and_length() -> None:
    """Signing yields the MAYO1 321-byte vector-plus-salt format."""
    seed_sk = bytes(range(SEED_SK_BYTES))
    expanded_secret = expand_secret_key(seed_sk)
    signature = sign(expanded_secret, "MAYO test message")

    assert isinstance(signature, bytes)
    expected_signature_bytes = (V + O_DIM) * K // 2 + SALT_BYTES
    assert expected_signature_bytes == 321
    assert len(signature) == expected_signature_bytes


def test_sign_trace_is_complete_safe_and_does_not_change_signature(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tracing preserves signing output and omits secret key material."""
    seed_sk = bytes(range(SEED_SK_BYTES))
    expanded_secret = expand_secret_key(seed_sk)
    message = b"trace-enabled MAYO test message"
    monkeypatch.setattr(
        sign_module,
        "random_bytes",
        lambda length: bytes([0xA5]) * length,
    )

    signature_without_trace = sign(expanded_secret, message)
    result_with_trace = sign(expanded_secret, message, return_trace=True)
    assert isinstance(result_with_trace, tuple)
    signature_with_trace, trace = result_with_trace

    assert signature_with_trace == signature_without_trace
    assert len(signature_with_trace) == 321

    seed_pk, encoded_o = derive_key_material(
        seed_sk,
        SEED_SK_BYTES,
        SEED_PK_BYTES,
        V,
        O_DIM,
    )
    O = decode_O(encoded_o)
    P1, P2 = generate_P1_P2(seed_pk)
    compact_public_key = seed_pk + encode_P3(compute_P3(O, P1, P2))
    expanded_public_key = expand_public_key(compact_public_key)
    assert verify(expanded_public_key, message, signature_with_trace) == 0

    step_names = [step.name for step in trace.steps]
    expected_prefix = [
        "secret_key_prepared",
        "message_digest",
        "salt_generated",
        "target_and_lambda_derived",
        "emulsifier_loaded",
    ]
    attempt_steps = [
        "attempt_values_generated",
        "intermediate_matrices_built",
        "linear_system_built",
        "sample_solution",
    ]
    assert step_names[:len(expected_prefix)] == expected_prefix
    assert step_names[-1] == "signature_encoded"
    traced_attempt_steps = step_names[len(expected_prefix):-1]
    assert len(traced_attempt_steps) % len(attempt_steps) == 0
    assert all(
        traced_attempt_steps[index:index + len(attempt_steps)] == attempt_steps
        for index in range(0, len(traced_attempt_steps), len(attempt_steps))
    )
    assert [step.number for step in trace.steps] == list(
        range(1, len(trace.steps) + 1)
    )
    assert all(
        step.scope == "signature" and step.attempt is None
        for step in trace.steps[:5] + trace.steps[-1:]
    )
    assert all(
        step.scope == "attempt" and step.attempt == 1
        for step in trace.steps[5:-1]
    )
    assert trace.steps[-2].status == "solved"
    assert trace.steps[-1].status == "completed"

    intermediate_step = trace.steps[6]
    assert intermediate_step.data["W_vector_count"] == K * M
    assert "W_matrix_count" not in intermediate_step.data
    assert intermediate_step.dimensions["W"] == (K, M, V)

    trace_dict = trace.to_dict()
    serialized_trace = json.dumps(trace_dict)
    assert isinstance(json.loads(serialized_trace), dict)
    assert seed_sk.hex() not in serialized_trace
    assert expanded_secret.hex() not in serialized_trace
    assert trace_dict["steps"][6]["dimensions"]["W"] == [K, M, V]
    assert trace_dict["steps"][6]["scope"] == "attempt"
    assert trace_dict["steps"][6]["attempt"] == 1
    assert trace_dict["steps"][6]["operation"] == "sign"

    trace_text = repr(trace)
    assert seed_sk.hex() not in trace_text
    assert expanded_secret.hex() not in trace_text
    assert trace.steps[6].data["coefficients_recorded"] is False
    assert trace.steps[7].data["coefficients_recorded"] is False


def test_sign_trace_records_inconsistent_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The trace records why a failed attempt is retried."""
    seed_sk = bytes(range(SEED_SK_BYTES))
    expanded_secret = expand_secret_key(seed_sk)
    sample_count = 0

    def fail_once_then_return_solution(
        matrix: list[list[int]],
        target: list[int],
        random_vector: list[int],
    ) -> list[int] | None:
        nonlocal sample_count
        sample_count += 1
        if sample_count == 1:
            return None
        return [0] * len(random_vector)

    monkeypatch.setattr(
        sign_module,
        "random_bytes",
        lambda length: bytes([0xA5]) * length,
    )
    monkeypatch.setattr(
        sign_module,
        "sample_solution",
        fail_once_then_return_solution,
    )

    signature, trace = sign(expanded_secret, b"retry trace", return_trace=True)

    solution_steps = [
        step for step in trace.steps if step.name == "sample_solution"
    ]
    assert len(solution_steps) == 2
    attempt_steps = [
        step
        for step in trace.steps
        if step.scope == "attempt"
    ]
    attempt_step_names = [
        "attempt_values_generated",
        "intermediate_matrices_built",
        "linear_system_built",
        "sample_solution",
    ]
    assert [step.name for step in attempt_steps] == attempt_step_names * 2
    assert [step.attempt for step in attempt_steps] == [1] * 4 + [2] * 4
    assert [step.number for step in trace.steps] == list(
        range(1, len(trace.steps) + 1)
    )
    assert all(
        step.scope == "signature" and step.attempt is None
        for step in trace.steps
        if step.name in {
            "secret_key_prepared",
            "message_digest",
            "salt_generated",
            "target_and_lambda_derived",
            "emulsifier_loaded",
            "signature_encoded",
        }
    )
    assert solution_steps[0].status == "inconsistent"
    assert solution_steps[0].scope == "attempt"
    assert solution_steps[0].attempt == 1
    assert solution_steps[0].data["reason"] == "system_inconsistent"
    assert solution_steps[0].data["attempt"] == 1
    assert solution_steps[1].status == "solved"
    assert solution_steps[1].scope == "attempt"
    assert solution_steps[1].attempt == 2
    assert solution_steps[1].data["attempt"] == 2
    assert len(signature) == 321


def test_sign_rejects_malformed_secret_key() -> None:
    """Sign propagates invalid expanded-key input as a value error."""
    with pytest.raises(ValueError):
        sign(b"short", b"message")
