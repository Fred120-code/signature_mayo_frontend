"""Arithmetic operations for the finite field GF(16)."""

FIELD_SIZE: int = 16


def add(a: int, b: int) -> int:
    """Add two field elements.

    Args:
        a: First GF(16) element, represented as an integer.
        b: Second GF(16) element, represented as an integer.

    Returns:
        The field sum, represented as an integer.
    """
    return a ^ b


def subtract(a: int, b: int) -> int:
    """Subtract two field elements.

    In characteristic two, subtraction is identical to addition.

    Args:
        a: First GF(16) element, represented as an integer.
        b: Second GF(16) element, represented as an integer.

    Returns:
        The field difference, represented as an integer.
    """
    return a ^ b


def multiply(a: int, b: int) -> int:
    """Multiply two GF(16) elements modulo ``x^4 + x + 1``.

    Args:
        a: First GF(16) element, represented as an integer.
        b: Second GF(16) element, represented as an integer.

    Returns:
        The field product, represented as an integer.
    """
    result = 0

    while b:
        if b & 1:
            result ^= a

        a <<= 1

        if a & 0b10000:
            a ^= 0b10011

        b >>= 1

    return result


def power(a: int, exponent: int) -> int:
    """Raise a GF(16) element to a non-negative integer power.

    Args:
        a: Field element to exponentiate.
        exponent: Exponent. The existing implementation returns ``1`` for
            negative exponents; callers should supply a non-negative value.

    Returns:
        The exponentiated field element.
    """
    result = 1

    while exponent > 0:
        if exponent & 1:
            result = multiply(result, a)

        a = multiply(a, a)
        exponent >>= 1

    return result


def inverse(a: int) -> int:
    """Return the multiplicative inverse of a nonzero GF(16) element.

    Args:
        a: Nonzero field element.

    Returns:
        The multiplicative inverse of ``a``.

    Raises:
        ValueError: If ``a`` is zero.
    """
    if a == 0:
        raise ValueError("Zero n'a pas d'inverse")

    return power(a, 14)


def divide(a: int, b: int) -> int:
    """Divide one GF(16) element by another.

    Args:
        a: Numerator.
        b: Nonzero denominator.

    Returns:
        The field quotient ``a / b``.

    Raises:
        ValueError: If ``b`` is zero.
    """
    if b == 0:
        raise ValueError("Division par zero")

    return multiply(a, inverse(b))
