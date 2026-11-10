"""MAYO compact key-pair generation."""

from core.matrix import Matrix, matrix_add, matrix_multiply, matrix_transpose
from core.quadratic import upper_triangle
from crypto.encoding import encode_matrices
from crypto.hashing import derive_key_material
from crypto.randomness import random_bytes
from keys.expand_public import generate_P1_P2
from keys.expand_secret import decode_O
from keys.parameters import (
    M,
    O_DIM,
    SEED_SK_BYTES,
    SEED_PK_BYTES,
    V,
)

def compute_P3(
    O: Matrix,
    P1: list[Matrix],
    P2: list[Matrix],
) -> list[Matrix]:
    """Compute the upper-triangular P3 matrices for a generated public key.

    Args:
        O: Secret oil matrix of size ``V x O_DIM``.
        P1: The ``M`` upper-triangular matrices of size ``V x V``.
        P2: The ``M`` matrices of size ``V x O_DIM``.

    Returns:
        The ``M`` upper-triangular matrices of size ``O_DIM x O_DIM``.

    Raises:
        ValueError: If P1 or P2 does not contain exactly ``M`` matrices.
    """
    if len(P1) != M or len(P2) != M:
        raise ValueError("Nombre incorrect de matrices P1 ou P2")

    O_T = matrix_transpose(O)
    P3 = []
    for index in range(M):
        temp = matrix_multiply(O_T, P1[index])
        A = matrix_multiply(temp, O)
        B = matrix_multiply(O_T, P2[index])
        P3.append(upper_triangle(matrix_add(A, B)))

    return P3


def encode_P3(P3: list[Matrix]) -> bytes:
    """Encode the upper triangle of P3 in its original interleaved order.

    Args:
        P3: Exactly ``M`` matrices of size ``O_DIM x O_DIM``.

    Returns:
        Packed public-key P3 bytes.

    Raises:
        ValueError: If the matrix count or a field element is invalid.
    """
    if len(P3) != M:
        raise ValueError("Nombre incorrect de matrices P3")

    return encode_matrices(P3, O_DIM, O_DIM, triangular=True)


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate the compact MAYO public and secret keys.

    Returns:
        A tuple ``(cpk, csk)`` containing the compact public and secret keys.
    """
    seed_sk = random_bytes(SEED_SK_BYTES)
    seed_pk, encoded_O = derive_key_material(
        seed_sk,
        SEED_SK_BYTES,
        SEED_PK_BYTES,
        V,
        O_DIM,
    )
    O = decode_O(encoded_O)
    P1, P2 = generate_P1_P2(seed_pk)
    encoded_P3 = encode_P3(compute_P3(O, P1, P2))

    return seed_pk + encoded_P3, seed_sk
