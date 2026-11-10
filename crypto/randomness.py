"""Cryptographically secure random-byte generation helpers."""

import secrets


def random_bytes(length: int) -> bytes:
    """Generate a requested number of cryptographically secure random bytes.

    Args:
        length: Number of bytes to generate.

    Returns:
        A byte string of length ``length``.

    Raises:
        ValueError: If ``length`` is negative.
    """
    if length < 0:
        raise ValueError("La longueur aléatoire ne peut pas être négative")

    return secrets.token_bytes(length)
