"""Tests for MAYO vector and nibble-sliced matrix encodings."""

import pytest

from crypto.encoding import (
    decode_matrices,
    decode_vector,
    encode_matrices,
    encode_vector,
)


def test_vector_encoding_keeps_low_nibble_first_and_zero_padding() -> None:
    """Encodevec packs consecutive elements and pads an odd vector with zero."""
    vector = [1, 2, 3]
    encoded = encode_vector(vector)

    assert encoded == bytes.fromhex("21 03")
    assert decode_vector(len(vector), encoded) == vector


def test_matrix_encoding_matches_algorithm_3_byte_for_byte() -> None:
    """Matrix coordinates are row-major, with matrices interleaved per cell."""
    matrices = [
        [[1, 2], [3, 4]],
        [[5, 6], [7, 8]],
    ]

    encoded = encode_matrices(matrices, 2, 2)

    assert encoded == bytes.fromhex("51 62 73 84")
    assert len(encoded) == 2 * 2 * 2 // 2
    assert decode_matrices(encoded, 2, 2, 2) == matrices


def test_matrix_encoding_pads_each_odd_length_coordinate_independently() -> None:
    """An odd matrix count gets one zero high nibble per matrix coordinate."""
    matrices = [
        [[1, 2]],
        [[3, 4]],
        [[5, 6]],
    ]

    encoded = encode_matrices(matrices, 1, 2)

    assert encoded == bytes.fromhex("31 05 42 06")
    assert len(encoded) == 2 * ((len(matrices) + 1) // 2)
    assert decode_matrices(encoded, 3, 1, 2) == matrices


def test_matrix_encoding_covers_all_gf16_values() -> None:
    """All field elements retain their expected nibble in the matrix stream."""
    matrices = [
        [list(range(8))],
        [list(range(8, 16))],
    ]

    encoded = encode_matrices(matrices, 1, 8)

    assert encoded == bytes.fromhex("80 91 A2 B3 C4 D5 E6 F7")
    assert decode_matrices(encoded, 2, 1, 8) == matrices


def test_zero_matrix_sequence_has_exact_size_and_round_trips() -> None:
    """Zero coefficients still occupy every encoded coordinate."""
    matrices = [[[0] * 3 for _ in range(2)] for _ in range(3)]
    encoded = encode_matrices(matrices, 2, 3)

    assert encoded == bytes(2 * 3 * 2)
    assert len(encoded) == 2 * 3 * ((len(matrices) + 1) // 2)
    assert decode_matrices(encoded, 3, 2, 3) == matrices


@pytest.mark.parametrize(
    ("rows", "cols", "matrix_count", "triangular"),
    [
        (1, 4, 2, False),
        (2, 3, 5, False),
        (3, 3, 3, True),
    ],
)
def test_matrix_round_trip_across_dimensions(
    rows: int,
    cols: int,
    matrix_count: int,
    triangular: bool,
) -> None:
    """Different shapes and matrix counts use their exact encoded lengths."""
    matrices = [
        [
            [(matrix_index * 5 + row * 3 + col) % 16 for col in range(cols)]
            for row in range(rows)
        ]
        for matrix_index in range(matrix_count)
    ]
    encoded = encode_matrices(
        matrices,
        rows,
        cols,
        triangular=triangular,
    )
    coordinates = (
        rows * (rows + 1) // 2
        if triangular
        else rows * cols
    )
    expected_length = coordinates * ((matrix_count + 1) // 2)

    decoded = decode_matrices(
        encoded,
        matrix_count,
        rows,
        cols,
        triangular=triangular,
    )

    assert len(encoded) == expected_length
    for matrix_index in range(matrix_count):
        for row in range(rows):
            for col in range(cols):
                expected = (
                    matrices[matrix_index][row][col]
                    if not triangular or row <= col
                    else 0
                )
                assert decoded[matrix_index][row][col] == expected


def test_triangular_matrix_encoding_skips_lower_triangle() -> None:
    """Upper-triangular encoding omits lower cells and decodes them as zero."""
    matrices = [
        [[1, 2], [3, 4]],
        [[5, 6], [7, 8]],
    ]

    encoded = encode_matrices(matrices, 2, 2, triangular=True)
    decoded = decode_matrices(encoded, 2, 2, 2, triangular=True)

    assert encoded == bytes.fromhex("51 62 84")
    assert len(encoded) == 3 * 2 // 2
    assert decoded == [
        [[1, 2], [0, 4]],
        [[5, 6], [0, 8]],
    ]


def test_matrix_decoder_rejects_incorrect_length() -> None:
    """The matrix decoder requires exactly one encoded segment per cell."""
    with pytest.raises(ValueError):
        decode_matrices(b"\x21", 2, 1, 2)


def test_matrix_helpers_reject_invalid_shapes_and_values() -> None:
    """Matrix encoding rejects malformed shapes, values, and triangular forms."""
    with pytest.raises(ValueError):
        encode_matrices([[[1, 2]]], 2, 2)
    with pytest.raises(ValueError):
        encode_matrices([[[16]]], 1, 1)
    with pytest.raises(ValueError):
        encode_matrices([[[1, 2]]], 1, 2, triangular=True)
