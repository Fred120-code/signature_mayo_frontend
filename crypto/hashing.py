"""SHAKE256 hashing and MAYO byte-derivation routines."""

import hashlib

from crypto.encoding import decode_vector


def shake256(data: bytes, output_length: int) -> bytes:
    """Return a fixed-length SHAKE256 digest.

    Args:
        data: Input bytes.
        output_length: Number of digest bytes requested.

    Returns:
        The requested SHAKE256 digest bytes.
    """
    return hashlib.shake_256(data).digest(output_length)


def derive_key_material(
    seed_sk: bytes,
    seed_sk_bytes: int,
    seed_pk_bytes: int,
    vinegar_dim: int,
    oil_dim: int,
) -> tuple[bytes, bytes]:
    """Derive the public seed and encoded oil matrix from the secret seed.

    Args:
        seed_sk: Secret seed.
        seed_sk_bytes: Required secret-seed length.
        seed_pk_bytes: Number of derived public-seed bytes.
        vinegar_dim: Number of vinegar rows in the oil matrix.
        oil_dim: Number of oil columns in the matrix.

    Returns:
        The derived public seed and encoded oil matrix bytes.

    Raises:
        ValueError: If ``seed_sk`` has a length different from
            ``seed_sk_bytes``.
    """
    if len(seed_sk) != seed_sk_bytes:
        raise ValueError("Taille incorrecte de seed_sk")

    oil_bytes = (vinegar_dim * oil_dim + 1) // 2
    output = shake256(seed_sk, seed_pk_bytes + oil_bytes)
    return output[:seed_pk_bytes], output[seed_pk_bytes:]


def derive_t(
    m_digest: bytes,
    salt: bytes,
    polynomial_count: int,
) -> list[int]:
    """Derive the target vector ``t`` (spec, Algorithm 8 line 11).

    ``t = Decodevec(m, SHAKE256(M_digest || salt, ceil(m * log(q) / 8)))``,
    which is ``m / 2`` bytes for ``q = 16``.

    Args:
        m_digest: Fixed-length digest of the message.
        salt: Signature salt.
        polynomial_count: Number of target equations ``m``.

    Returns:
        The target vector in GF(16)^m.

    Raises:
        ValueError: If ``polynomial_count`` is not a positive even integer.
    """
    if polynomial_count <= 0 or polynomial_count % 2:
        raise ValueError("Le nombre de polynomes doit etre positif et pair")

    target_bytes = shake256(m_digest + salt, polynomial_count // 2)
    return decode_vector(polynomial_count, target_bytes)