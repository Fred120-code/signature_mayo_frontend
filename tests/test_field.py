"""Tests for GF(16) arithmetic."""

import pytest

from core.field import add, divide, inverse, multiply, power, subtract


def test_addition_and_subtraction_are_characteristic_two() -> None:
    """Addition and subtraction both use XOR across all field elements."""
    for left in range(16):
        assert add(left, left) == 0
        for right in range(16):
            assert add(left, right) == left ^ right
            assert subtract(left, right) == left ^ right


def test_multiplication_is_closed_over_gf16() -> None:
    """Products of field elements remain in the four-bit field."""
    for left in range(16):
        for right in range(16):
            assert 0 <= multiply(left, right) < 16
            assert multiply(left, 0) == 0
            assert multiply(left, 1) == left


def test_all_nonzero_elements_have_multiplicative_inverses() -> None:
    """Every nonzero GF(16) element multiplied by its inverse equals one."""
    for element in range(1, 16):
        assert multiply(element, inverse(element)) == 1
        assert divide(element, element) == 1


def test_zero_cannot_be_inverted_or_used_as_divisor() -> None:
    """The field API rejects undefined inverse and division operations."""
    with pytest.raises(ValueError):
        inverse(0)
    with pytest.raises(ValueError):
        divide(1, 0)


def test_power_matches_repeated_multiplication() -> None:
    """Exponentiation preserves the existing square-and-multiply result."""
    value = 7
    expected = 1
    for _ in range(5):
        expected = multiply(expected, value)
    assert power(value, 5) == expected
