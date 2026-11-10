"""Quadratic-form helpers used by MAYO key generation and verification."""

from core.field import add
from core.matrix import (
    Matrix,
    Vector,
    matrix_vector_multiply,
    vector_add,
    vector_dot,
)


def upper_triangle(A: Matrix) -> Matrix:
    """Apply MAYO's ``Upper`` transformation to a square matrix.

    For entries above the diagonal, the result is the sum of the
    corresponding transposed entries. Diagonal entries are preserved and
    entries below the diagonal are zeroed.

    Args:
        A: Non-empty square matrix over GF(16).

    Returns:
        A new upper-triangular matrix.

    Raises:
        ValueError: If ``A`` is empty or is not square.
    """
    if not A or not A[0]:
        raise ValueError("Matrice vide")

    if any(len(row) != len(A) for row in A):
        raise ValueError("La matrice doit etre carree")

    size = len(A)
    return [
        [
            (A[i][j] ^ A[j][i]) if j > i
            else (A[i][j] if j == i else 0)
            for j in range(size)
        ]
        for i in range(size)
    ]


def evaluate_quadratic_form(
    P1: list[Matrix],
    P2: list[Matrix],
    P3: list[Matrix],
    s_blocks: list[Vector],
    V: int,
    O_DIM: int,
    K: int,
    M_poly: int,
    E: list[list[Matrix]],
) -> Vector:
    """Evaluate the expanded public quadratic map at the signature blocks.

    ``P1``, ``P2``, and ``P3`` are used exactly as stored, including their
    triangular representation. For each pair of blocks ``i <= j``, the
    associated bilinear contribution is multiplied by ``E[i][j]`` and
    accumulated over GF(16).

    Args:
        P1: Public matrices of size ``V x V``.
        P2: Public matrices of size ``V x O_DIM``.
        P3: Public matrices of size ``O_DIM x O_DIM``.
        s_blocks: ``K`` vectors, each of length ``V + O_DIM``.
        V: Number of vinegar variables in a block.
        O_DIM: Number of oil variables in a block.
        K: Number of signature blocks.
        M_poly: Number of quadratic polynomials.
        E: ``K x K`` table of ``M_poly x M_poly`` matrices.

    Returns:
        The evaluated vector of length ``M_poly``.
    """
    W = []

    for sj in s_blocks:
        vj = sj[:V]
        xj = sj[V:]
        Wj = []

        for polynomial_index in range(M_poly):
            top = vector_add(
                matrix_vector_multiply(P1[polynomial_index], vj),
                matrix_vector_multiply(P2[polynomial_index], xj),
            )
            bottom = matrix_vector_multiply(P3[polynomial_index], xj)
            Wj.append(top + bottom)

        W.append(Wj)

    y = [0] * M_poly
    for i in range(K):
        for j in range(i, K):
            u = []
            for polynomial_index in range(M_poly):
                value = vector_dot(s_blocks[i], W[j][polynomial_index])
                if i != j:
                    value = add(
                        value,
                        vector_dot(s_blocks[j], W[i][polynomial_index]),
                    )
                u.append(value)

            y = vector_add(y, matrix_vector_multiply(E[i][j], u))

    return y
