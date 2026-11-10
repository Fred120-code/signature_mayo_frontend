"""General matrix and vector operations over GF(16)."""

from core.field import add, multiply, subtract

Matrix = list[list[int]]
Vector = list[int]


def zero_matrix(rows: int, cols: int) -> Matrix:
    """Create a zero-filled matrix.

    Args:
        rows: Number of rows.
        cols: Number of columns.

    Returns:
        A matrix with the requested dimensions.
    """
    return [[0 for _ in range(cols)] for _ in range(rows)]


def matrix_add(A: Matrix, B: Matrix) -> Matrix:
    """Add two equally sized matrices element by element.

    Args:
        A: First matrix.
        B: Second matrix, with the same dimensions as ``A``.

    Returns:
        A new matrix containing the field-wise sum.

    Raises:
        ValueError: If the matrices have different dimensions.
    """
    if len(A) != len(B):
        raise ValueError("Les matrices doivent avoir le meme nombre de lignes")

    if any(len(row_a) != len(row_b) for row_a, row_b in zip(A, B)):
        raise ValueError("Les matrices doivent avoir les memes dimensions")

    return [
        [add(a, b) for a, b in zip(row_a, row_b)]
        for row_a, row_b in zip(A, B)
    ]


def matrix_transpose(A: Matrix) -> Matrix:
    """Return the transpose of a non-empty rectangular matrix.

    Args:
        A: Matrix to transpose.

    Returns:
        A new matrix with rows and columns exchanged.

    Raises:
        ValueError: If the matrix is empty or has inconsistent row lengths.
    """
    if not A or not A[0]:
        raise ValueError("La matrice ne doit pas etre vide")

    if any(len(row) != len(A[0]) for row in A):
        raise ValueError("Matrice invalide : lignes de tailles differentes")

    return [[A[i][j] for i in range(len(A))] for j in range(len(A[0]))]


def matrix_multiply(A: Matrix, B: Matrix) -> Matrix:
    """Multiply compatible, non-empty matrices over GF(16).

    Args:
        A: Left-hand matrix.
        B: Right-hand matrix.

    Returns:
        The matrix product ``A * B``.

    Raises:
        ValueError: If either matrix is empty, ragged, or dimensionally
            incompatible with the other.
    """
    if not A or not B or not A[0] or not B[0]:
        raise ValueError("Les matrices ne doivent pas etre vides")

    if any(len(row) != len(A[0]) for row in A):
        raise ValueError("La matrice A est invalide")

    if any(len(row) != len(B[0]) for row in B):
        raise ValueError("La matrice B est invalide")

    rows_A = len(A)
    cols_A = len(A[0])
    rows_B = len(B)
    cols_B = len(B[0])

    if cols_A != rows_B:
        raise ValueError("Dimensions incompatibles")

    C = [[0 for _ in range(cols_B)] for _ in range(rows_A)]

    for i in range(rows_A):
        for j in range(cols_B):
            total = 0
            for k in range(cols_A):
                total = add(total, multiply(A[i][k], B[k][j]))
            C[i][j] = total

    return C


def matrix_vector_multiply(A: Matrix, x: Vector) -> Vector:
    """Multiply a non-empty matrix by a vector over GF(16).

    Args:
        A: Matrix whose column count equals the length of ``x``.
        x: Right-hand vector.

    Returns:
        The product vector ``A * x``.

    Raises:
        ValueError: If ``A`` is empty, ragged, or dimensionally incompatible
            with ``x``.
    """
    if not A or not A[0]:
        raise ValueError("La matrice ne doit pas etre vide")

    if any(len(row) != len(A[0]) for row in A):
        raise ValueError("Matrice invalide")

    if len(A[0]) != len(x):
        raise ValueError("Dimensions incompatibles")

    result = []
    for row in A:
        total = 0
        for a, b in zip(row, x):
            total = add(total, multiply(a, b))
        result.append(total)

    return result


def vector_add(a: Vector, b: Vector) -> Vector:
    """Add two same-length vectors over GF(16).

    Args:
        a: First vector.
        b: Second vector.

    Returns:
        A new vector containing the field-wise sum.

    Raises:
        ValueError: If the vectors have different lengths.
    """
    if len(a) != len(b):
        raise ValueError("Les vecteurs doivent avoir la meme longueur")

    return [add(x, y) for x, y in zip(a, b)]


def vector_subtract(a: Vector, b: Vector) -> Vector:
    """Subtract two same-length vectors over GF(16).

    Args:
        a: First vector.
        b: Second vector.

    Returns:
        A new vector containing the field-wise difference.

    Raises:
        ValueError: If the vectors have different lengths.
    """
    if len(a) != len(b):
        raise ValueError("Les vecteurs doivent avoir la meme longueur")

    return [subtract(x, y) for x, y in zip(a, b)]


def vector_dot(a: Vector, b: Vector) -> int:
    """Compute the field dot product of two same-length vectors.

    Args:
        a: First vector.
        b: Second vector.

    Returns:
        The scalar field product sum.

    Raises:
        ValueError: If the vectors have different lengths.
    """
    if len(a) != len(b):
        raise ValueError("Les vecteurs doivent avoir la meme longueur")

    total = 0
    for x, y in zip(a, b):
        total = add(total, multiply(x, y))

    return total
