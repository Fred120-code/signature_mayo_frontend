"""Secret-key matrix decoding, expansion, and parsing."""

from core.field import add
from core.matrix import Matrix, matrix_add, matrix_multiply, zero_matrix
from crypto.aes import aes_ctr_expand
from crypto.encoding import (
    decode_matrices as decode_matrix_sequence,
    decode_nibbles,
    encode_matrices,
)
from crypto.hashing import derive_key_material
from keys.expand_public import decode_P1, generate_P1_P2
from keys.parameters import (
    M,
    O_DIM,
    SEED_SK_BYTES,
    SEED_PK_BYTES,
    V,
)


def decode_O(encoded_O: bytes) -> Matrix:
    """Decode the encoded secret oil matrix into its ``V x O_DIM`` form.

    Args:
        encoded_O: Packed low-nibble-first oil-matrix elements.

    Returns:
        The decoded secret matrix.

    Raises:
        ValueError: If the encoded byte count is inconsistent with dimensions.
    """
    expected_elements = V * O_DIM
    if len(encoded_O) * 2 != expected_elements:
        raise ValueError("Taille incorrecte de encoded_O")

    elements = decode_nibbles(encoded_O)
    return [
        elements[row_index * O_DIM:(row_index + 1) * O_DIM]
        for row_index in range(V)
    ]


def symmetric_P1(P1_i: Matrix) -> Matrix:
    """Reconstruct the zero-diagonal symmetric matrix ``P1_i + P1_i^T``.

    Args:
        P1_i: Upper-triangular P1 matrix.

    Returns:
        A symmetric matrix with a zero diagonal.
    """
    size = len(P1_i)
    symmetric = zero_matrix(size, size)

    for row in range(size):
        for col in range(size):
            if row != col:
                value_rc = P1_i[row][col] if col >= row else 0
                value_cr = P1_i[col][row] if row >= col else 0
                symmetric[row][col] = add(value_rc, value_cr)
            else:
                symmetric[row][row] = 0

    return symmetric


def compute_L(
    O: Matrix,
    P1: list[Matrix],
    P2: list[Matrix],
) -> list[Matrix]:
    """Compute each secret linking matrix ``L_i``.

    Args:
        O: Secret oil matrix of size ``V x O_DIM``.
        P1: The ``M`` upper-triangular vinegar matrices.
        P2: The ``M`` vinegar-to-oil matrices.

    Returns:
        The ``M`` matrices ``(P1_i + P1_i^T) * O + P2_i``.

    Raises:
        ValueError: If P1 or P2 does not contain exactly ``M`` matrices.
    """
    if len(P1) != M or len(P2) != M:
        raise ValueError("Nombre incorrect de matrices P1 ou P2")

    linking_matrices = []
    for matrix_index in range(M):
        P1_symmetric = symmetric_P1(P1[matrix_index])
        term1 = matrix_multiply(P1_symmetric, O)
        linking_matrices.append(matrix_add(term1, P2[matrix_index]))

    return linking_matrices


def encode_L(L: list[Matrix]) -> bytes:
    """Encode the L matrices in their existing interleaved nibble order.

    Args:
        L: Exactly ``M`` matrices of size ``V x O_DIM``.

    Returns:
        Packed linking-matrix bytes.

    Raises:
        ValueError: If the matrix count or a field-element value is invalid.
    """
    if len(L) != M:
        raise ValueError("Nombre incorrect de matrices L")

    return encode_matrices(L, V, O_DIM)


def decode_L(encoded_L: bytes) -> list[Matrix]:
    """Decode packed linking matrices from their interleaved byte encoding.

    Args:
        encoded_L: Packed linking-matrix bytes.

    Returns:
        The decoded ``M`` matrices of dimensions ``V x O_DIM``.

    Raises:
        ValueError: If the encoded length does not match the parameters.
    """
    return decode_matrix_sequence(encoded_L, M, V, O_DIM)


def expand_secret_key(csk: bytes) -> bytes:
    """Expand a compact secret key into the existing expanded-key format.

    Args:
        csk: Compact secret key containing the secret seed.

    Returns:
        Concatenated secret seed, encoded O, encoded P1, and encoded L.

    Raises:
        ValueError: If ``csk`` is not exactly ``SEED_SK_BYTES`` long.
    """
    if len(csk) != SEED_SK_BYTES:
        raise ValueError("Taille invalide de csk (seed_sk attendue)")

    seed_sk = csk[:SEED_SK_BYTES]
    seed_pk, encoded_O = derive_key_material(
        seed_sk,
        SEED_SK_BYTES,
        SEED_PK_BYTES,
        V,
        O_DIM,
    )
    O = decode_O(encoded_O)
    p1_bytes = (M * V * (V + 1) // 2) // 2
    p2_bytes = (M * V * O_DIM) // 2
    P1, P2 = generate_P1_P2(seed_pk)

    expanded_P = aes_ctr_expand(seed_pk, p1_bytes + p2_bytes)
    encoded_P1 = expanded_P[:p1_bytes]
    encoded_L = encode_L(compute_L(O, P1, P2))

    return seed_sk + encoded_O + encoded_P1 + encoded_L


def parse_esk(
    esk: bytes,
) -> tuple[bytes, Matrix, list[Matrix], list[Matrix]]:
    """Parse an expanded secret key into its structured components.

    Args:
        esk: Expanded secret-key bytes.

    Returns:
        The secret seed, O matrix, P1 matrices, and L matrices.

    Raises:
        ValueError: If ``esk`` does not have the expected encoded length.
    """
    o_bytes = (V * O_DIM) // 2
    p1_bytes = (M * V * (V + 1) // 2) // 2
    l_bytes = (M * V * O_DIM) // 2
    expected_length = SEED_SK_BYTES + o_bytes + p1_bytes + l_bytes

    if len(esk) != expected_length:
        raise ValueError(
            f"Taille incorrecte de esk ({len(esk)} != {expected_length})"
        )

    position = 0
    seed_sk = esk[position:position + SEED_SK_BYTES]
    position += SEED_SK_BYTES
    encoded_O = esk[position:position + o_bytes]
    position += o_bytes
    encoded_P1 = esk[position:position + p1_bytes]
    position += p1_bytes
    encoded_L = esk[position:position + l_bytes]

    return seed_sk, decode_O(encoded_O), decode_P1(encoded_P1), decode_L(encoded_L)
