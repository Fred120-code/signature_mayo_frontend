"""AES-based counter-mode byte expansion used by the MAYO implementation."""

from Crypto.Cipher import AES


def aes_ctr_expand(seed_pk: bytes, output_length: int) -> bytes:
    """Expand bytes using AES-128 with a counter starting at zero.

    The implementation encrypts consecutive 16-byte, big-endian counter
    blocks in ECB mode and concatenates the results, preserving the existing
    MAYO project's counter convention.

    Args:
        seed_pk: The 16-byte AES-128 key.
        output_length: Number of output bytes requested.

    Returns:
        Exactly ``output_length`` bytes.

    Raises:
        ValueError: If the key is not 16 bytes or the requested length is
            negative.
    """
    if len(seed_pk) != 16:
        raise ValueError("seed_pk doit contenir 16 octets")

    if output_length < 0:
        raise ValueError("Longueur de sortie invalide")

    aes = AES.new(seed_pk, AES.MODE_ECB)
    output = bytearray()
    counter = 0

    while len(output) < output_length:
        counter_block = counter.to_bytes(16, byteorder="big")
        output.extend(aes.encrypt(counter_block))
        counter += 1

    return bytes(output[:output_length])


def aes_ctr_expand_iv(key: bytes, iv: bytes, output_length: int) -> bytes:
    """Expand bytes using MAYO's AES-128-CTR counter construction.

    For block index ``i``, encrypt ``iv XOR I2OSP(i, 16)``, where ``I2OSP``
    encodes the index as a 16-byte big-endian integer.

    Args:
        key: The 16-byte AES-128 key.
        iv: The 16-byte initial counter block.
        output_length: Number of output bytes requested.

    Returns:
        The requested prefix of the encrypted counter stream.

    Raises:
        ValueError: If either ``key`` or ``iv`` is not 16 bytes.
        ValueError: If the requested length is negative.
    """
    if len(key) != 16 or len(iv) != 16:
        raise ValueError("key et iv doivent contenir 16 octets")

    if output_length < 0:
        raise ValueError("Longueur de sortie invalide")

    aes = AES.new(key, AES.MODE_ECB)
    output = bytearray()

    for counter in range((output_length + AES.block_size - 1) // AES.block_size):
        counter_bytes = counter.to_bytes(AES.block_size, byteorder="big")
        counter_block = bytes(a ^ b for a, b in zip(iv, counter_bytes))
        output.extend(aes.encrypt(counter_block))

    return bytes(output[:output_length])
