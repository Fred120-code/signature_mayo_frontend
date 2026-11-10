"""Specification-driven tests for MAYO AES and SHAKE derivations."""

import hashlib

import pytest
from Crypto.Cipher import AES

from crypto.aes import aes_ctr_expand, aes_ctr_expand_iv
from crypto.hashing import derive_key_material, derive_t_and_lambda, shake256
from crypto.randomness import random_bytes
from keys.parameters import (
    M,
    N,
    O_DIM,
    SALT_BYTES,
    SEED_PK_BYTES,
    SEED_SK_BYTES,
    V,
)


def _decode_vector_reference(data: bytes, element_count: int) -> list[int]:
    """Decode Encodevec independently from the production helpers."""
    values = []
    for byte in data:
        values.extend((byte & 0x0F, byte >> 4))
    return values[:element_count]


def _aes_ctr_reference(key: bytes, iv: bytes, output_length: int) -> bytes:
    """Apply the specification's IV-XOR-big-endian-counter equation."""
    aes = AES.new(key, AES.MODE_ECB)
    blocks = []
    for index in range((output_length + 15) // 16):
        counter = index.to_bytes(16, byteorder="big")
        input_block = bytes(a ^ b for a, b in zip(iv, counter))
        blocks.append(aes.encrypt(input_block))
    return b"".join(blocks)[:output_length]


def test_aes_ctr_expand_starts_at_zero_and_truncates_final_block() -> None:
    """Zero-IV AES expansion uses big-endian block indices and exact length."""
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    expected = bytes.fromhex(
        "7df76b0c1ab899b33e42f047b91b546f"
        "57127d4034b1bebfaef466b9c7726fc6"
    )

    assert aes_ctr_expand(key, 0) == b""
    assert aes_ctr_expand(key, 32) == expected
    assert aes_ctr_expand(key, 19) == expected[:19]
    with pytest.raises(ValueError):
        aes_ctr_expand(key, -1)


def test_aes_ctr_expand_iv_xors_128_bit_big_endian_counter() -> None:
    """A nonzero IV is XORed with each encoded block index, not incremented."""
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    expected = bytes.fromhex(
        "ec8cdf7398607cb0f2d21675ea9ea1e4"
        "688412675f6fc11e39c4ed0a2aa11d08"
    )

    assert aes_ctr_expand_iv(key, iv, 32) == expected
    assert aes_ctr_expand_iv(key, iv, 19) == expected[:19]
    assert aes_ctr_expand_iv(key, bytes(16), 32) == aes_ctr_expand(key, 32)
    with pytest.raises(ValueError):
        aes_ctr_expand_iv(key, iv, -1)
    with pytest.raises(ValueError):
        aes_ctr_expand_iv(key, iv[:-1], 16)


def test_aes_ctr_expand_iv_matches_spec_equation_for_multiple_blocks() -> None:
    """The AES helper matches a direct XOR-counter construction."""
    key = bytes(range(16))
    iv = bytes.fromhex("102030405060708090a0b0c0d0e0f011")
    expected = _aes_ctr_reference(key, iv, 47)

    assert aes_ctr_expand_iv(key, iv, 47) == expected


def test_shake256_returns_the_requested_output_length() -> None:
    """SHAKE256 is an XOF and returns the exact requested prefix length."""
    message = b"MAYO Round 3 SHAKE test"

    assert shake256(message, 0) == b""
    assert shake256(message, 32) == hashlib.shake_256(message).digest(32)
    assert len(shake256(message, 49)) == 49


def test_key_material_uses_shake256_and_specified_seed_split() -> None:
    """The secret seed expands to public seed followed by EncodeO bytes."""
    seed_sk = bytes(range(SEED_SK_BYTES))
    expected_o_length = (V * O_DIM + 1) // 2
    expanded = hashlib.shake_256(seed_sk).digest(
        SEED_PK_BYTES + expected_o_length
    )

    seed_pk, encoded_o = derive_key_material(
        seed_sk,
        SEED_SK_BYTES,
        SEED_PK_BYTES,
        V,
        O_DIM,
    )

    assert expanded[:SEED_PK_BYTES].hex() == "714951231ff70f18f44ad30645433c0b"
    assert seed_pk == expanded[:SEED_PK_BYTES]
    assert encoded_o == expanded[SEED_PK_BYTES:]
    assert len(seed_pk) == SEED_PK_BYTES
    assert len(encoded_o) == expected_o_length


def test_key_material_uses_ceiling_for_odd_o_element_count() -> None:
    """The generic encoded O length follows ceil(number of nibbles / 2)."""
    seed_sk = bytes(range(SEED_SK_BYTES))
    seed_pk, encoded_o = derive_key_material(
        seed_sk,
        SEED_SK_BYTES,
        2,
        1,
        3,
    )
    expected = hashlib.shake_256(seed_sk).digest(4)

    assert seed_pk == expected[:2]
    assert encoded_o == expected[2:]
    assert len(encoded_o) == 2


def test_key_material_rejects_wrong_secret_seed_length() -> None:
    """Seed expansion rejects a secret seed of the wrong configured size."""
    with pytest.raises(ValueError):
        derive_key_material(b"short", SEED_SK_BYTES, SEED_PK_BYTES, V, O_DIM)


def test_target_and_lambda_match_spec_hash_aes_and_column_order() -> None:
    """t and Lambda follow SHAKE split, AES-CTR, and DecodeLambda columns."""
    m_digest = bytes(range(32))
    salt = bytes(range(24, 48))
    hash_output = hashlib.shake_256(m_digest + salt).digest(M // 2 + 32)
    assert hash_output.hex() == (
        "77a4fa97c67f97df62927242b6f2a59c"
        "4e8dacd2af35812903c51e4bddcbc225"
        "da53049cbcf701906401f2d27d3ba595"
        "53a205a7331e45760c8da02dafb445b5"
    )

    expected_t = _decode_vector_reference(hash_output[:M // 2], M)
    aes_key = hash_output[M // 2:M // 2 + 16]
    aes_iv = hash_output[M // 2 + 16:M // 2 + 32]
    lambda_bytes_length = N * M // 2
    lambda_bytes = _aes_ctr_reference(
        aes_key,
        aes_iv,
        lambda_bytes_length,
    )
    assert lambda_bytes[:32].hex() == (
        "ee42036dec20ca425e96bb53c8bfbecf"
        "7ae74b21d814fd6e4fbdfbd1cb852fe9"
    )

    column_bytes = M // 2
    columns = [
        _decode_vector_reference(
            lambda_bytes[index * column_bytes:(index + 1) * column_bytes],
            M,
        )
        for index in range(N)
    ]
    expected_lambda = [
        [columns[column][row] for column in range(N)]
        for row in range(M)
    ]

    target, lambda_matrix = derive_t_and_lambda(m_digest, salt, M, N)

    assert target == expected_t
    assert lambda_matrix == expected_lambda
    assert len(target) == M
    assert len(lambda_matrix) == M
    assert all(len(row) == N for row in lambda_matrix)
    assert (M * N) // 2 == lambda_bytes_length


def test_target_and_lambda_reject_odd_equation_count() -> None:
    """The MAYO derivation requires even m for its m/2-byte vector encoding."""
    with pytest.raises(ValueError):
        derive_t_and_lambda(b"digest", b"salt", 3, 5)


def test_random_bytes_returns_requested_length_and_rejects_negative() -> None:
    """Random seed material has the requested length and rejects negatives."""
    assert random_bytes(0) == b""
    assert len(random_bytes(SEED_SK_BYTES)) == SEED_SK_BYTES
    with pytest.raises(ValueError):
        random_bytes(-1)
