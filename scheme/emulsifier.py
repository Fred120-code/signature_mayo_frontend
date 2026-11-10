"""Construction and caching of MAYO emulsifier matrices E[i][j]."""

from core.field import add, multiply
from core.matrix import Matrix
from keys.parameters import K, M

F_TAIL: list[int] = [8, 0, 2, 8]
_E_CACHE: list[list[Matrix]] | None = None


def ell_index(i: int, j: int, k: int) -> int:
    """Return the polynomial-power index assigned to the pair ``(i, j)``.

    Args:
        i: First block index.
        j: Second block index, with ``i <= j``.
        k: Number of signature blocks.

    Returns:
        The zero-based index of the pair in the existing traversal order.
    """
    return sum(k - ii for ii in range(i)) + (k - 1 - j)


def z_power_matrices(
    m: int,
    count: int,
    tail: list[int] = F_TAIL,
) -> list[Matrix]:
    """Construct multiplication-by-``z^l`` matrices modulo the polynomial.

    Args:
        m: Degree of the polynomial and matrix dimension.
        count: Number of consecutive power matrices to construct.
        tail: Coefficients ``[f0, f1, f2, f3]`` of the polynomial tail.

    Returns:
        The matrices ``[E_0, ..., E_(count-1)]``.
    """
    identity = [
        [1 if row == col else 0 for col in range(m)]
        for row in range(m)
    ]
    result = [identity]

    for _ in range(count - 1):
        last = result[-1]
        overflow = last[m - 1]
        new = [[0] * m] + [row[:] for row in last[:m - 1]]

        for row, coefficient in enumerate(tail):
            if coefficient:
                new[row] = [
                    add(a, multiply(coefficient, b))
                    for a, b in zip(new[row], overflow)
                ]

        result.append(new)

    return result


def build_E(
    m: int,
    k: int,
    tail: list[int] = F_TAIL,
) -> list[list[Matrix]]:
    """Build the symmetric ``k x k`` table of emulsifier matrices.

    Args:
        m: Degree of the polynomial and dimension of each matrix.
        k: Number of signature blocks.
        tail: Coefficients of the polynomial tail.

    Returns:
        The table whose entries are ``m x m`` multiplication matrices.
    """
    powers = z_power_matrices(m, k * (k + 1) // 2, tail)
    E = [[powers[0] for _ in range(k)] for _ in range(k)]

    for i in range(k):
        for j in range(i, k):
            E[i][j] = powers[ell_index(i, j, k)]
            E[j][i] = E[i][j]

    return E


def get_E() -> list[list[Matrix]]:
    """Return the cached MAYO1 emulsifier table, constructing it once.

    Returns:
        The ``K x K`` table of ``M x M`` emulsifier matrices.
    """
    global _E_CACHE
    if _E_CACHE is None:
        _E_CACHE = build_E(M, K)
    return _E_CACHE


__all__ = [
    "F_TAIL",
    "ell_index",
    "z_power_matrices",
    "build_E",
    "get_E",
]
