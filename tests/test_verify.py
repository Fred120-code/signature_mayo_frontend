"""Tests for independent MAYO signature verification."""

import json
from typing import cast

import pytest

import scheme.verify as verify_module

from crypto.hashing import derive_key_material
from keys.expand_public import expand_public_key, generate_P1_P2
from keys.expand_secret import decode_O, expand_secret_key
from keys.keygen import compute_P3, encode_P3
from keys.parameters import (
    K,
    M,
    N,
    O_DIM,
    SEED_PK_BYTES,
    SEED_SK_BYTES,
    V,
)
from scheme.sign import sign
from scheme.verify import verify


def _compact_public_key(seed_sk: bytes) -> bytes:
    """Build a compact public key deterministically from a secret seed."""
    seed_pk, encoded_O = derive_key_material(
        seed_sk,
        SEED_SK_BYTES,
        SEED_PK_BYTES,
        V,
        O_DIM,
    )
    O = decode_O(encoded_O)
    P1, P2 = generate_P1_P2(seed_pk)
    return seed_pk + encode_P3(compute_P3(O, P1, P2))


@pytest.fixture(scope="module")
def signed_message() -> tuple[bytes, bytes, bytes, bytes]:
    """Prepare a deterministic key pair and one valid signature."""
    seed_sk = bytes(range(SEED_SK_BYTES))
    cpk = _compact_public_key(seed_sk)
    epk = expand_public_key(cpk)
    esk = expand_secret_key(seed_sk)
    message = b"independent MAYO verification test"
    return epk, esk, message, sign(esk, message)


def test_valid_signature_is_accepted(
    signed_message: tuple[bytes, bytes, bytes, bytes],
) -> None:
    """Verify accepts a signature generated for the original message."""
    epk, _, message, signature = signed_message
    assert len(signature) == 321
    assert verify(epk, message, signature) == 0


def test_verify_trace_records_ordered_success_without_sensitive_values(
    signed_message: tuple[bytes, bytes, bytes, bytes],
) -> None:
    """Verify trace records the pedagogical path and serializes safely."""
    epk, _, message, signature = signed_message

    result = verify(epk, message, signature, return_trace=True)

    assert isinstance(result, tuple)
    status, trace = result
    assert type(status) is int
    assert status == 0
    expected_names = [
        "message_normalized",
        "public_key_parsed",
        "signature_length_checked",
        "signature_split",
        "signature_vector_decoded",
        "signature_blocks_partitioned",
        "message_digest_computed",
        "target_and_lambda_derived",
        "emulsifier_loaded",
        "quadratic_form_evaluated",
        "lambda_contributions_added",
        "verification_compared",
    ]
    assert [step.name for step in trace.steps] == expected_names
    assert [step.number for step in trace.steps] == list(
        range(1, len(expected_names) + 1)
    )
    assert all(
        step.operation == "verify"
        and step.scope == "verification"
        and step.attempt is None
        for step in trace.steps
    )
    assert trace.steps[-1].status == "accepted"
    assert trace.steps[-1].data["valid"] is True
    assert trace.steps[4].dimensions["signature_vector"] == (K * N,)
    assert trace.steps[7].dimensions["Lambda"] == (M, N)
    assert trace.steps[9].dimensions["result"] == (M,)

    serialized = json.dumps(trace.to_dict())
    assert isinstance(json.loads(serialized), dict)
    assert message.decode() not in serialized
    assert epk.hex() not in serialized
    assert signature.hex() not in serialized
    assert "digest_preview" not in serialized
    assert "lambda_preview" not in serialized
    assert "salt_hex" not in serialized


def test_modified_message_is_rejected(
    signed_message: tuple[bytes, bytes, bytes, bytes],
) -> None:
    """Verify rejects the same signature for a changed message."""
    epk, _, message, signature = signed_message
    assert verify(epk, message + b"!", signature) == -1


def test_modified_message_trace_explains_verification_mismatch(
    signed_message: tuple[bytes, bytes, bytes, bytes],
) -> None:
    """A mathematically rejected signature has a stable trace reason."""
    epk, _, message, signature = signed_message

    status, trace = verify(epk, message + b"!", signature, return_trace=True)

    assert status == -1
    assert trace.steps[-1].name == "verification_compared"
    assert trace.steps[-1].status == "rejected"
    assert trace.steps[-1].data["error_code"] == "verification_mismatch"
    assert trace.steps[-1].data["valid"] is False


def test_modified_signature_is_rejected(
    signed_message: tuple[bytes, bytes, bytes, bytes],
) -> None:
    """Verify rejects tampered signature bytes."""
    epk, _, message, signature = signed_message
    damaged = bytearray(signature)
    damaged[10] ^= 1
    assert verify(epk, message, bytes(damaged)) == -1


def test_modified_signature_trace_reports_mismatch(
    signed_message: tuple[bytes, bytes, bytes, bytes],
) -> None:
    """A changed signature is rejected with a mismatch event."""
    epk, _, message, signature = signed_message
    damaged = bytearray(signature)
    damaged[10] ^= 1

    status, trace = verify(epk, message, bytes(damaged), return_trace=True)

    assert status == -1
    assert trace.steps[-1].data["error_code"] == "verification_mismatch"


def test_modified_salt_is_rejected(
    signed_message: tuple[bytes, bytes, bytes, bytes],
) -> None:
    """Verify rejects a signature with a modified salt."""
    epk, _, message, signature = signed_message
    damaged = bytearray(signature)
    damaged[-1] ^= 1
    assert verify(epk, message, bytes(damaged)) == -1


def test_other_public_key_is_rejected(
    signed_message: tuple[bytes, bytes, bytes, bytes],
) -> None:
    """Verify rejects a signature checked against another public key."""
    _, _, message, signature = signed_message
    other_seed = bytes(reversed(range(SEED_SK_BYTES)))
    other_epk = expand_public_key(_compact_public_key(other_seed))
    assert verify(other_epk, message, signature) == -1


def test_other_public_key_trace_reports_mismatch(
    signed_message: tuple[bytes, bytes, bytes, bytes],
) -> None:
    """A signature checked with another key reaches the math mismatch."""
    _, _, message, signature = signed_message
    other_seed = bytes(reversed(range(SEED_SK_BYTES)))
    other_epk = expand_public_key(_compact_public_key(other_seed))

    status, trace = verify(other_epk, message, signature, return_trace=True)

    assert status == -1
    assert trace.steps[-1].data["error_code"] == "verification_mismatch"


def test_malformed_signature_and_key_are_rejected(
    signed_message: tuple[bytes, bytes, bytes, bytes],
) -> None:
    """Malformed lengths and key encodings return the invalid-signature result."""
    epk, _, message, signature = signed_message
    assert verify(epk, message, b"") == -1
    assert verify(b"", message, b"bad") == -1
    assert verify(epk, message, signature[:-1]) == -1
    assert verify(epk, message, signature + b"\x00") == -1
    assert verify(epk + b"\x00", message, signature) == -1


def test_early_rejections_return_partial_verify_trace(
    signed_message: tuple[bytes, bytes, bytes, bytes],
) -> None:
    """Length and key-format failures retain their trace prefix."""
    epk, _, message, signature = signed_message

    length_result = verify(epk, message, signature[:-1], return_trace=True)
    assert isinstance(length_result, tuple)
    status, trace = length_result
    assert status == -1
    assert [step.name for step in trace.steps] == [
        "message_normalized",
        "public_key_parsed",
        "signature_length_checked",
    ]
    assert trace.steps[-1].status == "rejected"
    assert trace.steps[-1].data["error_code"] == "signature_length_error"

    key_result = verify(b"", message, signature, return_trace=True)
    assert isinstance(key_result, tuple)
    key_status, key_trace = key_result
    assert key_status == -1
    assert key_trace.steps[-1].name == "public_key_parsed"
    assert key_trace.steps[-1].data["error_code"] == "public_key_format_error"

    p3_bytes = M * O_DIM * (O_DIM + 1) // 4
    truncated_epk = epk[:-p3_bytes]
    truncated_result = verify(
        truncated_epk,
        message,
        signature,
        return_trace=True,
    )
    assert isinstance(truncated_result, tuple)
    truncated_status, truncated_trace = truncated_result
    assert truncated_status == -1
    assert truncated_trace.steps[-1].data["error_code"] == (
        "public_key_format_error"
    )


def test_decode_and_derivation_failures_have_safe_reason_codes(
    signed_message: tuple[bytes, bytes, bytes, bytes],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Expected decode and derivation errors do not expose exception text."""
    epk, _, message, signature = signed_message

    def fail_decode(*_: object) -> list[int]:
        raise ValueError("sensitive decoder details")

    monkeypatch.setattr(verify_module, "decode_vector", fail_decode)
    status, trace = verify(epk, message, signature, return_trace=True)
    assert status == -1
    assert trace.steps[-1].data["error_code"] == "signature_decode_error"
    assert "sensitive decoder details" not in json.dumps(trace.to_dict())

    monkeypatch.undo()

    def fail_derivation(*_: object) -> tuple[list[int], list[list[int]]]:
        raise ValueError("sensitive derivation details")

    monkeypatch.setattr(verify_module, "derive_t_and_lambda", fail_derivation)
    status, trace = verify(epk, message, signature, return_trace=True)
    assert status == -1
    assert trace.steps[-1].data["error_code"] == "derivation_error"
    assert "sensitive derivation details" not in json.dumps(trace.to_dict())


@pytest.mark.parametrize(
    ("epk", "message", "signature"),
    [
        (None, b"message", b"signature"),
        (b"epk", None, b"signature"),
        (b"epk", b"message", None),
        (b"epk", 123, b"signature"),
        (bytearray(b"epk"), b"message", b"signature"),
    ],
)
def test_malformed_argument_types_are_rejected(
    epk: object,
    message: object,
    signature: object,
) -> None:
    """Verify rejects inputs that do not match its public argument types."""
    assert verify(
        cast(bytes, epk),
        cast(bytes | str, message),
        cast(bytes, signature),
    ) == -1


def test_unencodable_message_is_rejected(
    signed_message: tuple[bytes, bytes, bytes, bytes],
) -> None:
    """Verify returns the invalid-signature result for invalid UTF-8 text."""
    epk, _, _, signature = signed_message
    assert verify(epk, "\ud800", signature) == -1


def test_invalid_input_trace_is_available(
    signed_message: tuple[bytes, bytes, bytes, bytes],
) -> None:
    """Input validation failures retain a safe trace event."""
    epk, _, _, signature = signed_message

    status, trace = verify(epk, "\ud800", signature, return_trace=True)

    assert status == -1
    assert len(trace.steps) == 1
    assert trace.steps[0].name == "message_normalized"
    assert trace.steps[0].data["error_code"] == "message_encoding_error"


def test_invalid_argument_type_trace_is_available() -> None:
    """Wrong Python argument types are rejected with a safe trace."""
    status, trace = verify(
        cast(bytes, None),
        b"message",
        b"signature",
        return_trace=True,
    )

    assert status == -1
    assert trace.steps[0].name == "input_rejected"
    assert trace.steps[0].data["error_code"] == "input_type_error"


def test_unexpected_internal_error_is_not_swallowed(
    signed_message: tuple[bytes, bytes, bytes, bytes],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unexpected failures in public-key parsing remain visible to callers."""
    epk, _, message, signature = signed_message

    def raise_internal_error(_: bytes) -> None:
        raise RuntimeError("unexpected parser failure")

    monkeypatch.setattr(verify_module, "parse_epk", raise_internal_error)
    with pytest.raises(RuntimeError, match="unexpected parser failure"):
        verify(epk, message, signature)
