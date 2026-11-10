"""Public-key matrix decoding, expansion, and parsing."""

from core.matrix import Matrix
from crypto.aes import aes_ctr_expand
from crypto.encoding import decode_matrices as decode_matrix_sequence
from keys.parameters import M, O_DIM, SEED_PK_BYTES, V


def decode_matrices(
    data: bytes,
    rows: int,
    cols: int,
    triangular: bool = False,
) -> list[Matrix]:
    """Decode the configured matrix sequence with MAYO's matrix encoding.

    Args:
        data: Packed matrix coefficients.
        rows: Number of rows per matrix.
        cols: Number of columns per matrix.
        triangular: If true, decode only upper-triangular coordinates.

    Returns:
        The ``M`` decoded matrices.

    Raises:
        ValueError: If the encoded byte length does not match the dimensions.
    """
    return decode_matrix_sequence(
        data,
        M,
        rows,
        cols,
        triangular=triangular,
    )


def decode_P1(data: bytes) -> list[Matrix]:
    """Decode packed P1 coefficients into the ``M`` upper-triangular matrices.

    Args:
        data: Interleaved packed coefficients for P1.

    Returns:
        The decoded ``M`` matrices, each of size ``V x V``.
    """
    return decode_matrices(data, V, V, triangular=True)


def decode_P2(data: bytes) -> list[Matrix]:
    """Decode packed P2 coefficients into the ``M`` rectangular matrices.

    Args:
        data: Interleaved packed coefficients for P2.

    Returns:
        The decoded ``M`` matrices, each of size ``V x O_DIM``.
    """
    return decode_matrices(data, V, O_DIM, triangular=False)


def generate_P1_P2(seed_pk: bytes) -> tuple[list[Matrix], list[Matrix]]:
    """Expand the public seed and decode its P1 and P2 matrix collections.

    Args:
        seed_pk: The public AES seed.

    Returns:
        The decoded P1 and P2 matrices in their existing ordering.
    """
    p1_elements = M * (V * (V + 1) // 2)
    p2_elements = M * V * O_DIM
    p1_bytes = p1_elements // 2
    p2_bytes = p2_elements // 2

    expanded_data = aes_ctr_expand(seed_pk, p1_bytes + p2_bytes)
    encoded_P1 = expanded_data[:p1_bytes]
    encoded_P2 = expanded_data[p1_bytes:]

    return decode_P1(encoded_P1), decode_P2(encoded_P2)


def expand_public_key(cpk: bytes) -> bytes:
    """Expand a compact public key to the project's expanded byte format.

    Args:
        cpk: Compact key containing the public seed followed by encoded P3.

    Returns:
        Expanded P1 and P2 bytes concatenated with encoded P3.

    Raises:
        ValueError: If ``cpk`` is shorter than its public seed.
    """
    if len(cpk) < SEED_PK_BYTES:
        raise ValueError("Taille invalide de cpk (seed_pk attendue)")

    seed_pk = cpk[:SEED_PK_BYTES]
    encoded_P3 = cpk[SEED_PK_BYTES:]

    p1_bytes = (M * V * (V + 1) // 2) // 2
    p2_bytes = (M * V * O_DIM) // 2
    expanded_P = aes_ctr_expand(seed_pk, p1_bytes + p2_bytes)

    return expanded_P + encoded_P3


def parse_epk(epk: bytes) -> tuple[list[Matrix], list[Matrix], list[Matrix]]:
    """Decode an expanded public key into P1, P2, and P3 matrices.

    Args:
        epk: Expanded public-key bytes.

    Returns:
        The decoded P1, P2, and upper-triangular P3 matrices.

    Raises:
        ValueError: If ``epk`` does not contain enough bytes for P1 and P2.
    """
    p1_bytes = (M * V * (V + 1) // 2) // 2
    p2_bytes = (M * V * O_DIM) // 2
    total_p_bytes = p1_bytes + p2_bytes

    if len(epk) < total_p_bytes:
        raise ValueError("Taille incorrecte de epk")

    encoded_P1 = epk[:p1_bytes]
    encoded_P2 = epk[p1_bytes:total_p_bytes]
    encoded_P3 = epk[total_p_bytes:]

    P1 = decode_P1(encoded_P1)
    P2 = decode_P2(encoded_P2)
    P3 = decode_matrix_sequence(
        encoded_P3,
        M,
        O_DIM,
        O_DIM,
        triangular=True,
    )

    return P1, P2, P3
