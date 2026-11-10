"""Encoding and decoding helpers for GF(16) elements and vectors."""

from core.field import FIELD_SIZE


def decode_nibbles(data: bytes) -> list[int]:
    """Decode each byte into low-nibble then high-nibble field elements.

    Args:
        data: Bytes containing two packed GF(16) elements per byte.

    Returns:
        The unpacked elements in the existing low-then-high order.
    """
    elements = []
    for byte in data:
        elements.append(byte & 0x0F)
        elements.append((byte >> 4) & 0x0F)
    return elements


def encode_nibbles(elements: list[int]) -> bytes:
    """Pack GF(16) elements two per byte, low nibble first.

    An odd final element is packed with a zero high nibble, matching the
    existing key and signature encoding convention.

    Args:
        elements: Field elements to encode.

    Returns:
        The packed byte representation.

    Raises:
        ValueError: If any element is outside GF(16).
    """
    encoded = bytearray()

    for index in range(0, len(elements), 2):
        low = elements[index]
        if not 0 <= low < FIELD_SIZE:
            raise ValueError("Element invalide dans F16")

        if index + 1 < len(elements):
            high = elements[index + 1]
            if not 0 <= high < FIELD_SIZE:
                raise ValueError("Element invalide dans F16")
        else:
            high = 0

        encoded.append(low | (high << 4))

    return bytes(encoded)


def decode_vector(dim: int, data: bytes) -> list[int]:
    """Decode the first ``dim`` GF(16) elements from packed bytes.

    Extra decoded elements are ignored, as in the original signing module.

    Args:
        dim: Number of elements in the requested vector.
        data: Packed vector bytes.

    Returns:
        A vector containing ``dim`` field elements.

    Raises:
        ValueError: If the input does not contain enough elements.
    """
    elements = decode_nibbles(data)
    if len(elements) < dim:
        raise ValueError("Données insuffisantes pour décoder le vecteur")
    return elements[:dim]


def encode_vector(vector: list[int]) -> bytes:
    """Encode a vector of GF(16) elements in the existing nibble format.

    Args:
        vector: Field elements to pack.

    Returns:
        The low-nibble-first packed bytes.

    Raises:
        ValueError: If a vector element is outside GF(16).
    """
    for value in vector:
        if not 0 <= value < FIELD_SIZE:
            raise ValueError("Élément invalide dans F16 pour l'encodage du vecteur")
    return encode_nibbles(vector)


def _matrix_coordinates(
    rows: int,
    cols: int,
    triangular: bool,
) -> list[tuple[int, int]]:
    if rows < 0 or cols < 0:
        raise ValueError("Les dimensions des matrices ne peuvent pas etre negatives")
    if triangular and rows != cols:
        raise ValueError("Une matrice triangulaire doit être carree")

    return [
        (row, col)
        for row in range(rows)
        for col in range(cols)
        if not triangular or row <= col
    ]


def encode_bitsliced_vector(vector: list[int]) -> bytes:
    """Encode ``m`` GF(16) elements in bitsliced form (spec, Algorithm 4).

    Elements ``8*i .. 8*i+7`` give one byte per bit plane. Plane ``p`` is
    stored at offset ``p * m / 8``, and element ``8*i + j`` is bit ``j``.

    Args:
        vector: ``m`` field elements, with ``m`` a multiple of 8.

    Returns:
        ``m / 2`` bytes.

    Raises:
        ValueError: If ``m`` is not a multiple of 8 or an element is invalid.
    """
    m = len(vector)
    if m == 0 or m % 8:
        raise ValueError("Le nombre de matrices doit etre un multiple de 8")
    for value in vector:
        if not 0 <= value < FIELD_SIZE:
            raise ValueError("Element invalide dans F16")

    step = m // 8
    encoded = bytearray(m // 2)
    for i in range(step):
        planes = [0, 0, 0, 0]
        for j in range(7, -1, -1):
            element = vector[i * 8 + j]
            for plane in range(4):
                planes[plane] = planes[plane] * 2 + ((element >> plane) & 1)
        for plane in range(4):
            encoded[plane * step + i] = planes[plane]
    return bytes(encoded)


def decode_bitsliced_vector(m: int, data: bytes) -> list[int]:
    """Inverse of :func:`encode_bitsliced_vector`.

    Args:
        m: Number of field elements, a multiple of 8.
        data: Exactly ``m / 2`` bytes.

    Returns:
        The ``m`` decoded field elements.

    Raises:
        ValueError: If ``m`` or the data length is invalid.
    """
    if m <= 0 or m % 8:
        raise ValueError("Le nombre de matrices doit etre un multiple de 8")
    if len(data) != m // 2:
        raise ValueError("Taille incorrecte pour un vecteur bitsliced")

    step = m // 8
    vector = [0] * m
    for i in range(step):
        for j in range(8):
            vector[i * 8 + j] = sum(
                ((data[plane * step + i] >> j) & 1) << plane
                for plane in range(4)
            )
    return vector


def encode_matrices(
    matrices: list[list[list[int]]],
    rows: int,
    cols: int,
    *,
    triangular: bool = False,
) -> bytes:
    """Encode ``m`` matrices with EncodeBitslicedMatrices (spec, Algorithm 3).

    For each coordinate ``(i, j)`` in row-major order, the ``m`` values
    ``A_k[i, j]`` are encoded as one bitsliced vector. Lower-triangular
    coordinates are skipped when ``triangular`` is true.

    Args:
        matrices: ``m`` matrices, with ``m`` a multiple of 8.
        rows: Number of rows in each matrix.
        cols: Number of columns in each matrix.
        triangular: Whether to encode only upper-triangular coordinates.

    Returns:
        The bitsliced byte representation.

    Raises:
        ValueError: If dimensions, matrix count or elements are invalid.
    """
    coordinates = _matrix_coordinates(rows, cols, triangular)
    if not matrices:
        raise ValueError("La sequence de matrices ne peut pas etre vide")

    for matrix in matrices:
        if len(matrix) != rows or any(len(row) != cols for row in matrix):
            raise ValueError("Dimensions incorrectes pour une matrice")

    encoded = bytearray()
    for row, col in coordinates:
        encoded.extend(
            encode_bitsliced_vector([matrix[row][col] for matrix in matrices])
        )
    return bytes(encoded)


def decode_matrices(
    data: bytes,
    matrix_count: int,
    rows: int,
    cols: int,
    *,
    triangular: bool = False,
) -> list[list[list[int]]]:
    """Decode a bitsliced ``EncodeBitslicedMatrices`` byte string.

    Args:
        data: Bitsliced matrix-sequence bytes.
        matrix_count: Number of matrices ``m``, a multiple of 8.
        rows: Number of rows in each matrix.
        cols: Number of columns in each matrix.
        triangular: Whether only upper-triangular coordinates are encoded.

    Returns:
        The decoded matrices. Omitted lower-triangular entries are zero.

    Raises:
        ValueError: If the count, dimensions or byte length is invalid.
    """
    if matrix_count <= 0 or matrix_count % 8:
        raise ValueError("Le nombre de matrices doit etre un multiple de 8")

    coordinates = _matrix_coordinates(rows, cols, triangular)
    bytes_per_coordinate = matrix_count // 2
    expected_length = len(coordinates) * bytes_per_coordinate
    if len(data) != expected_length:
        raise ValueError(
            f"Taille incorrecte des donnees ({len(data)} != {expected_length})"
        )

    matrices = [
        [[0] * cols for _ in range(rows)]
        for _ in range(matrix_count)
    ]
    position = 0
    for row, col in coordinates:
        values = decode_bitsliced_vector(
            matrix_count,
            data[position:position + bytes_per_coordinate],
        )
        for matrix_index, value in enumerate(values):
            matrices[matrix_index][row][col] = value
        position += bytes_per_coordinate
    return matrices