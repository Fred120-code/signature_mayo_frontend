"""MAYO sampling strategy for solving a linear system over GF(16)."""

from core.linear_algebra import matrix_rank, solve_linear_system
from core.matrix import (
    Matrix,
    Vector,
    matrix_vector_multiply,
    vector_add,
    vector_subtract,
)


def sample_solution(A: Matrix, y: Vector, r: Vector) -> Vector | None:
    """Solve ``A*x = y`` using ``r`` for the free-variable components.

    The method first solves ``A*x0 = y - A*r`` with free variables set to
    zero, then returns ``x0 + r``. This preserves the existing SampleSolution
    behavior.

    Args:
        A: Coefficient matrix.
        y: Right-hand-side vector.
        r: Random vector containing values for free-variable components.

    Returns:
        A solution vector, or ``None`` if the system is inconsistent or does
        not have full row rank.
    """
    if matrix_rank(A) != len(A):
        return None

    Ar = matrix_vector_multiply(A, r)
    x0 = solve_linear_system(A, vector_subtract(y, Ar))

    if x0 is None:
        return None

    return vector_add(x0, r)
