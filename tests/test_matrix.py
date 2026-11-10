"""Tests for matrix, vector, linear-algebra, and quadratic helpers."""

import pytest

from core.linear_algebra import matrix_rank, solve_linear_system
from core.matrix import (
    matrix_add,
    matrix_multiply,
    matrix_transpose,
    matrix_vector_multiply,
    vector_add,
    vector_dot,
    vector_subtract,
    zero_matrix,
)
from core.quadratic import upper_triangle


def test_matrix_operations_over_gf16() -> None:
    """Basic matrix operations preserve dimensions and field arithmetic."""
    identity = [[1, 0], [0, 1]]
    matrix = [[5, 6], [7, 8]]
    assert matrix_add(identity, matrix) == [[4, 6], [7, 9]]
    assert matrix_transpose(matrix) == [[5, 7], [6, 8]]
    assert matrix_multiply(identity, matrix) == matrix
    assert matrix_vector_multiply(identity, [5, 6]) == [5, 6]
    assert zero_matrix(2, 3) == [[0, 0, 0], [0, 0, 0]]


def test_vector_operations_over_gf16() -> None:
    """Vector addition, subtraction, and dot product use GF(16)."""
    assert vector_add([1, 2], [3, 4]) == [2, 6]
    assert vector_subtract([1, 2], [3, 4]) == [2, 6]
    assert vector_dot([1, 0], [5, 6]) == 5


def test_linear_system_solver_and_inconsistent_system() -> None:
    """The solver returns a valid solution or None for inconsistency."""
    coefficients = [[1, 1], [1, 0]]
    target = [3, 5]
    solution = solve_linear_system(coefficients, target)
    assert solution is not None
    assert matrix_vector_multiply(coefficients, solution) == target
    assert solve_linear_system([[1, 1], [1, 1]], [1, 2]) is None


def test_matrix_rank_over_gf16() -> None:
    """Matrix rank counts independent rows over GF(16)."""
    assert matrix_rank([[1, 0], [0, 1]]) == 2
    assert matrix_rank([[1, 1], [2, 2]]) == 1


def test_matrix_operations_reject_invalid_dimensions() -> None:
    """Matrix and vector operations reject incompatible dimensions."""
    with pytest.raises(ValueError):
        matrix_add([[1]], [[1, 2]])
    with pytest.raises(ValueError):
        matrix_multiply([[1, 2]], [[1, 2]])
    with pytest.raises(ValueError):
        matrix_vector_multiply([[1, 2]], [1])
    with pytest.raises(ValueError):
        vector_add([1], [1, 2])
    with pytest.raises(ValueError):
        solve_linear_system([[1, 2]], [1, 2])


def test_upper_triangle_transformation() -> None:
    """Upper preserves the diagonal, combines upper entries, and clears below."""
    assert upper_triangle([[1, 2], [3, 4]]) == [[1, 1], [0, 4]]
