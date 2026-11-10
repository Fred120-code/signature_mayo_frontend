"""Application-layer orchestration for the educational MAYO1 workflow.

This module exposes intermediate key and signature artifacts without coupling
the cryptographic implementation to a user interface framework.
"""

from dataclasses import dataclass

from keys.expand_public import expand_public_key
from keys.expand_secret import expand_secret_key
from keys.keygen import generate_keypair
from scheme.sign import sign
from scheme.verify import verify


@dataclass(frozen=True)
class DemoResult:
    """Artifacts produced by one complete key-generation/sign/verify run."""

    message: bytes | str
    compact_public_key: bytes
    compact_secret_key: bytes
    expanded_public_key: bytes
    expanded_secret_key: bytes
    signature: bytes
    verification_status: int


def run_demo(message: bytes | str) -> DemoResult:
    """Generate keys, sign ``message``, and return every workflow artifact.

    Args:
        message: Message bytes or text to sign and verify.

    Returns:
        The compact and expanded keys, signature, original message, and
        verification status. A status of ``0`` means the signature verified.

    Raises:
        RuntimeError: If signing cannot find a solution within its retry limit.
        ValueError: If key expansion or signing receives invalid data.
    """
    compact_public_key, compact_secret_key = generate_keypair()
    expanded_public_key = expand_public_key(compact_public_key)
    expanded_secret_key = expand_secret_key(compact_secret_key)
    signature = sign(expanded_secret_key, message)
    verification_status = verify(expanded_public_key, message, signature)

    return DemoResult(
        message=message,
        compact_public_key=compact_public_key,
        compact_secret_key=compact_secret_key,
        expanded_public_key=expanded_public_key,
        expanded_secret_key=expanded_secret_key,
        signature=signature,
        verification_status=verification_status,
    )
