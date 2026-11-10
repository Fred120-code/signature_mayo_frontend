"""Tests for MAYO parameter validation and key generation."""

import pytest

from core.matrix import matrix_multiply, matrix_transpose
from keys.expand_public import generate_P1_P2
from keys.expand_secret import decode_O
from keys.keygen import compute_P3, generate_keypair
from keys.parameters import (
    DIGEST_BYTES,
    K,
    M,
    N,
    O_DIM,
    Q,
    SALT_BYTES,
    SEED_PK_BYTES,
    SEED_SK_BYTES,
    V,
    check_parameters,
)
from crypto.hashing import derive_key_material
from crypto.randomness import random_bytes


@pytest.fixture(scope="module")
def generated_material() -> tuple[list[list[int]], list, list, list]:
    """Construct deterministic O, P1, P2, and P3 values for these tests."""
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
    P3 = compute_P3(O, P1, P2)
    return O, P1, P2, P3


def test_parameters_and_seed_lengths() -> None:
    """MAYO1 parameters and their dimension relationships are configured."""
    check_parameters()
    assert (Q, N, M, O_DIM, K, V) == (16, 66, 64, 8, 9, 58)
    assert V == N - O_DIM
    assert N == V + O_DIM
    assert K * O_DIM >= M
    assert (SEED_SK_BYTES, SEED_PK_BYTES, DIGEST_BYTES, SALT_BYTES) == (
        24,
        16,
        32,
        24,
    )
    assert len(random_bytes(SEED_SK_BYTES)) == SEED_SK_BYTES
    assert len(random_bytes(SEED_PK_BYTES)) == SEED_PK_BYTES


def test_decode_o_dimensions_and_values(
    generated_material: tuple[list[list[int]], list, list, list],
) -> None:
    """The decoded secret oil matrix has the configured shape and field."""
    O = generated_material[0]
    assert len(O) == V
    assert all(len(row) == O_DIM for row in O)
    assert all(0 <= value < Q for row in O for value in row)


def test_generate_p1_and_p2_dimensions(
    generated_material: tuple[list[list[int]], list, list, list],
) -> None:
    """Generated P1 matrices are upper triangular and P2 has expected shape."""
    _, P1, P2, _ = generated_material
    assert len(P1) == len(P2) == M
    assert all(len(matrix) == V for matrix in P1)
    assert all(len(row) == V for matrix in P1 for row in matrix)
    assert all(len(matrix) == V for matrix in P2)
    assert all(len(row) == O_DIM for matrix in P2 for row in matrix)
    assert all(
        P1[index][row][col] == 0
        for index in range(M)
        for row in range(V)
        for col in range(row)
    )


def test_compute_p3_dimensions_and_upper_triangle(
    generated_material: tuple[list[list[int]], list, list, list],
) -> None:
    """P3 matrices have the expected shape, field values, and triangular form."""
    P3 = generated_material[3]
    assert len(P3) == M
    assert all(len(matrix) == O_DIM for matrix in P3)
    assert all(len(row) == O_DIM for matrix in P3 for row in matrix)
    assert all(
        P3[index][row][col] == 0
        for index in range(M)
        for row in range(O_DIM)
        for col in range(row)
    )
    assert all(0 <= value < Q for matrix in P3 for row in matrix for value in row)


def test_p3_trapdoor_property(
    generated_material: tuple[list[list[int]], list, list, list],
) -> None:
    """Oil-space vectors evaluate to zero for each generated public polynomial."""
    O, P1, P2, P3 = generated_material
    for sample in ([1] * O_DIM, list(range(O_DIM)), [15 - i for i in range(O_DIM)]):
        oil_vector = [[value] for value in sample]
        vinegar_vector = matrix_multiply(O, oil_vector)
        vinegar_T = matrix_transpose(vinegar_vector)
        oil_T = matrix_transpose(oil_vector)

        for index in range(M):
            vinegar_term = matrix_multiply(
                vinegar_T,
                matrix_multiply(P1[index], vinegar_vector),
            )[0][0]
            mixed_term = matrix_multiply(
                vinegar_T,
                matrix_multiply(P2[index], oil_vector),
            )[0][0]
            oil_term = matrix_multiply(
                oil_T,
                matrix_multiply(P3[index], oil_vector),
            )[0][0]
            assert vinegar_term ^ mixed_term ^ oil_term == 0


def test_generate_keypair_sizes() -> None:
    """Key generation yields MAYO1 compact public and secret key lengths."""
    cpk, csk = generate_keypair()
    assert len(cpk) == 1168
    assert len(csk) == 24


def test_compute_p3_rejects_wrong_matrix_count() -> None:
    """Key generation rejects mismatched P1/P2 collection sizes."""
    with pytest.raises(ValueError):
        compute_P3([], [], [])
