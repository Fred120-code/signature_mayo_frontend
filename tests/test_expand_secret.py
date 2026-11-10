"""Tests for secret-key expansion and the encoded linking matrices."""

import pytest

from crypto.encoding import encode_matrices, encode_vector
from crypto.hashing import derive_key_material
from keys.expand_public import generate_P1_P2
from keys.expand_secret import (
    compute_L,
    decode_L,
    decode_O,
    encode_L,
    expand_secret_key,
    parse_esk,
    symmetric_P1,
)
from keys.parameters import (
    M,
    O_DIM,
    SEED_PK_BYTES,
    SEED_SK_BYTES,
    V,
)


def test_symmetric_p1_has_zero_diagonal() -> None:
    """The upper-triangular input yields P1 + P1 transpose."""
    result = symmetric_P1([[3, 5], [0, 9]])
    assert result == [[0, 5], [5, 0]]


def test_linking_matrices_and_encoding_round_trip() -> None:
    """Computed L matrices retain their dimensions through encoding."""
    seed_sk = bytes(range(SEED_SK_BYTES))
    seed_pk, encoded_O = derive_key_material(
        seed_sk,
        SEED_SK_BYTES,
        SEED_PK_BYTES,
        V,
        O_DIM,
    )
    O = decode_O(encoded_O)
    P1, P2 = generate_P1_P2(seed_pk)
    linking_matrices = compute_L(O, P1, P2)

    assert len(linking_matrices) == M
    assert all(len(matrix) == V for matrix in linking_matrices)
    assert all(
        len(row) == O_DIM
        for matrix in linking_matrices
        for row in matrix
    )
    expected_encoded_L = b"".join(
        encode_vector(
            [
                linking_matrices[matrix_index][row][col]
                for matrix_index in range(M)
            ]
        )
        for row in range(V)
        for col in range(O_DIM)
    )
    assert encode_L(linking_matrices) == expected_encoded_L
    assert encode_L(linking_matrices) == encode_matrices(
        linking_matrices,
        V,
        O_DIM,
    )
    assert decode_L(encode_L(linking_matrices)) == linking_matrices


def test_expand_and_parse_secret_key() -> None:
    """Expanded secret keys retain their format and parse back to components."""
    csk = bytes(range(SEED_SK_BYTES))
    esk = expand_secret_key(csk)
    seed_sk, O, P1, L = parse_esk(esk)

    assert len(esk) == 69856
    assert seed_sk == csk
    assert len(O) == V and len(O[0]) == O_DIM
    assert len(P1) == M
    assert len(L) == M


def test_secret_key_parsing_rejects_invalid_lengths() -> None:
    """Secret-key expansion and parsing reject malformed encoded inputs."""
    with pytest.raises(ValueError):
        expand_secret_key(b"short")
    with pytest.raises(ValueError):
        parse_esk(b"short")
