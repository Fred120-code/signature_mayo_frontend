"""Tests for public-key expansion and parsing."""

import pytest

from crypto.encoding import encode_matrices
from crypto.hashing import derive_key_material
from keys.expand_public import (
    expand_public_key,
    generate_P1_P2,
    parse_epk,
)
from keys.expand_secret import decode_O
from keys.keygen import compute_P3, encode_P3
from keys.parameters import M, O_DIM, SEED_PK_BYTES, SEED_SK_BYTES, V


def _compact_public_key(seed_sk: bytes) -> bytes:
    """Build a compact public key deterministically from a secret seed."""
    seed_pk, encoded_O = derive_key_material(
        seed_sk,
        SEED_SK_BYTES,
        SEED_PK_BYTES,
        V,
        O_DIM,
    )
    O = decode_O(encoded_O)
    P1, P2 = generate_P1_P2(seed_pk)
    return seed_pk + encode_P3(compute_P3(O, P1, P2))


def test_expand_and_parse_public_key() -> None:
    """Expanded public-key encoding parses into all expected matrix groups."""
    cpk = _compact_public_key(bytes(range(SEED_SK_BYTES)))
    epk = expand_public_key(cpk)
    P1, P2, P3 = parse_epk(epk)

    assert len(cpk) == 1168
    assert len(epk) == 70752
    assert len(P1) == len(P2) == len(P3) == M
    assert len(P1[0]) == V and len(P1[0][0]) == V
    assert len(P2[0]) == V and len(P2[0][0]) == O_DIM
    assert len(P3[0]) == O_DIM and len(P3[0][0]) == O_DIM
    assert cpk[SEED_PK_BYTES:] == encode_matrices(
        P3,
        O_DIM,
        O_DIM,
        triangular=True,
    )


def test_public_key_helpers_reject_short_inputs() -> None:
    """Public-key expansion and parsing reject data shorter than required."""
    with pytest.raises(ValueError):
        expand_public_key(b"")
    with pytest.raises(ValueError):
        parse_epk(b"")
