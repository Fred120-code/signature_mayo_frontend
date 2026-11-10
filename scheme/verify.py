"""MAYO signature verification, independent of the signing module."""

from typing import Literal, overload

from core.quadratic import evaluate_quadratic_form
from crypto.encoding import decode_vector
from crypto.hashing import derive_t, shake256
from keys.expand_public import parse_epk
from keys.parameters import DIGEST_BYTES, K, M, N, O_DIM, SALT_BYTES, V
from scheme.emulsifier import get_E
from scheme.trace import VerifyTrace


@overload
def verify(
    epk: bytes,
    message: bytes | str,
    sig: bytes,
    *,
    return_trace: Literal[False] = False,
) -> int: ...


@overload
def verify(
    epk: bytes,
    message: bytes | str,
    sig: bytes,
    *,
    return_trace: Literal[True],
) -> tuple[int, VerifyTrace]: ...


def verify(
    epk: bytes,
    message: bytes | str,
    sig: bytes,
    *,
    return_trace: bool = False,
) -> int | tuple[int, VerifyTrace]:
    """Verify a signature using the expanded public key and original message.

    Args:
        epk: Expanded public-key bytes.
        message: Original message as bytes or text.
        sig: Encoded signature bytes.
        return_trace: If true, return a pedagogical trace with the result.

    Returns:
        ``0`` if valid, otherwise ``-1``. When ``return_trace`` is true,
        return ``(result, trace)`` including for handled rejection paths.
    """
    trace = VerifyTrace() if return_trace else None

    def finish(result: int) -> int | tuple[int, VerifyTrace]:
        return result if trace is None else (result, trace)

    if not isinstance(epk, bytes) or not isinstance(sig, bytes):
        if trace is not None:
            trace.add_step(
                "input_rejected",
                "La clé étendue et la signature doivent être des octets.",
                data={
                    "inputs_valid": False,
                    "error_code": "input_type_error",
                },
                status="rejected",
            )
        return finish(-1)
    if not isinstance(message, (bytes, str)):
        if trace is not None:
            trace.add_step(
                "input_rejected",
                "Le message doit être fourni sous forme d'octets ou de texte.",
                data={
                    "inputs_valid": False,
                    "error_code": "input_type_error",
                },
                status="rejected",
            )
        return finish(-1)

    message_type = "text" if isinstance(message, str) else "bytes"
    if isinstance(message, str):
        try:
            message = message.encode("utf-8")
        except UnicodeEncodeError:
            if trace is not None:
                trace.add_step(
                    "message_normalized",
                    "Le texte du message n'a pas pu être encodé en UTF-8.",
                    data={
                        "inputs_valid": False,
                        "error_code": "message_encoding_error",
                    },
                    status="rejected",
                )
            return finish(-1)

    if trace is not None:
        trace.add_step(
            "message_normalized",
            "Le message texte est converti en UTF-8; seul son type et sa "
            "longueur sont tracés.",
            data={
                "message_type": message_type,
                "message_bytes": len(message),
                "inputs_valid": True,
            },
        )

    try:
        P1, P2, P3 = parse_epk(epk)
    except (IndexError, ValueError):
        if trace is not None:
            trace.add_step(
                "public_key_parsed",
                "La clé publique étendue n'a pas le format attendu.",
                data={"error_code": "public_key_format_error"},
                status="rejected",
            )
        return finish(-1)

    if trace is not None:
        trace.add_step(
            "public_key_parsed",
            "La clé publique étendue est décodée en trois familles de "
            "matrices; leurs coefficients ne sont pas tracés.",
            data={
                "expanded_key_bytes": len(epk),
                "polynomial_count": len(P1),
            },
            dimensions={
                "P1": (
                    len(P1),
                    len(P1[0]) if P1 else 0,
                    len(P1[0][0]) if P1 and P1[0] else 0,
                ),
                "P2": (
                    len(P2),
                    len(P2[0]) if P2 else 0,
                    len(P2[0][0]) if P2 and P2[0] else 0,
                ),
                "P3": (
                    len(P3),
                    len(P3[0]) if P3 else 0,
                    len(P3[0][0]) if P3 and P3[0] else 0,
                ),
            },
        )

    expected_s_bytes = (K * N + 1) // 2
    if len(sig) != expected_s_bytes + SALT_BYTES:
        if trace is not None:
            trace.add_step(
                "signature_length_checked",
                "La taille de la signature est comparée à la taille "
                "attendue.",
                data={
                    "signature_bytes": len(sig),
                    "expected_signature_bytes": expected_s_bytes + SALT_BYTES,
                    "error_code": "signature_length_error",
                },
                status="rejected",
            )
        return finish(-1)

    if trace is not None:
        trace.add_step(
            "signature_length_checked",
            "La taille de la signature correspond au format attendu.",
            data={
                "signature_bytes": len(sig),
                "expected_signature_bytes": expected_s_bytes + SALT_BYTES,
            },
        )

    s_bytes = sig[:expected_s_bytes]
    salt = sig[expected_s_bytes:expected_s_bytes + SALT_BYTES]
    if trace is not None:
        trace.add_step(
            "signature_split",
            "La signature est séparée en vecteur encodé et sel; leurs "
            "octets ne sont pas enregistrés.",
            data={
                "encoded_vector_bytes": len(s_bytes),
                "salt_bytes": len(salt),
            },
            dimensions={
                "encoded_vector": (len(s_bytes),),
                "salt": (len(salt),),
            },
        )

    try:
        s_elements = decode_vector(K * N, s_bytes)
    except ValueError:
        if trace is not None:
            trace.add_step(
                "signature_vector_decoded",
                "Le vecteur encodé de la signature n'a pas pu être décodé.",
                data={"error_code": "signature_decode_error"},
                status="rejected",
            )
        return finish(-1)

    if trace is not None:
        trace.add_step(
            "signature_vector_decoded",
            "Le vecteur encodé est décodé en éléments de GF(16); les "
            "éléments ne sont pas enregistrés.",
            data={"vector_elements": len(s_elements)},
            dimensions={"signature_vector": (len(s_elements),)},
        )

    s_blocks = [
        s_elements[index * N:(index + 1) * N]
        for index in range(K)
    ]
    if trace is not None:
        trace.add_step(
            "signature_blocks_partitioned",
            "Le vecteur est réparti en blocs de signature, chacun composé "
            "de variables vinegar puis oil.",
            data={
                "block_count": len(s_blocks),
                "vinegar_elements_per_block": int(V),
                "oil_elements_per_block": int(O_DIM),
            },
            dimensions={
                "signature_blocks": (
                    len(s_blocks),
                    len(s_blocks[0]) if s_blocks else 0,
                ),
                "vinegar_blocks": (len(s_blocks), V),
                "oil_blocks": (len(s_blocks), O_DIM),
            },
        )

    m_digest = shake256(message, DIGEST_BYTES)
    if trace is not None:
        trace.add_step(
            "message_digest_computed",
            "SHAKE256 calcule le digest du message; sa valeur n'est pas "
            "enregistrée.",
            data={"digest_bytes": len(m_digest)},
        )
    try:
        t = derive_t(m_digest, salt, M)
    except ValueError:
        if trace is not None:
            trace.add_step(
                "target_derived",
                "La dérivation de t a échoué.",
                data={"error_code": "derivation_error"},
                status="rejected",
            )
        return finish(-1)

    if trace is not None:
        trace.add_step(
            "target_derived",
            "Le digest et le sel servent à dériver t avec SHAKE256; ses "
            "coefficients ne sont pas enregistrés.",
            data={"target_elements": len(t)},
            dimensions={"t": (len(t),)},
        )

    E = get_E()
    if trace is not None:
        trace.add_step(
            "emulsifier_loaded",
            "La table E est récupérée pour combiner les contributions des "
            "blocs.",
            data={"block_count": len(E)},
            dimensions={
                "E_table": (len(E), len(E[0]) if E else 0),
                "E_entry": (
                    (len(E[0][0]), len(E[0][0][0]))
                    if E and E[0]
                    else ()
                ),
            },
        )

    y = evaluate_quadratic_form(P1, P2, P3, s_blocks, V, O_DIM, K, M, E)
    if trace is not None:
        trace.add_step(
            "quadratic_form_evaluated",
            "La forme quadratique publique est évaluée sur les blocs de "
            "signature; seules les dimensions du résultat sont tracées.",
            data={
                "block_count": len(s_blocks),
                "block_pair_count": K * (K + 1) // 2,
            },
            dimensions={
                "signature_blocks": (
                    len(s_blocks),
                    len(s_blocks[0]) if s_blocks else 0,
                ),
                "P1": (
                    len(P1),
                    len(P1[0]) if P1 else 0,
                    len(P1[0][0]) if P1 and P1[0] else 0,
                ),
                "P2": (
                    len(P2),
                    len(P2[0]) if P2 else 0,
                    len(P2[0][0]) if P2 and P2[0] else 0,
                ),
                "P3": (
                    len(P3),
                    len(P3[0]) if P3 else 0,
                    len(P3[0][0]) if P3 and P3[0] else 0,
                ),
                "result": (len(y),),
            },
        )

    if y == t:
        if trace is not None:
            trace.add_step(
                "verification_compared",
                "Le résultat calculé est égal au vecteur cible t : la "
                "signature est acceptée.",
                data={"valid": True},
                dimensions={"result": (len(y),), "t": (len(t),)},
                status="accepted",
            )
        return finish(0)

    if trace is not None:
        trace.add_step(
            "verification_compared",
            "Le résultat calculé diffère du vecteur cible t : la signature "
            "est rejetée.",
            data={
                "valid": False,
                "error_code": "verification_mismatch",
            },
            dimensions={"result": (len(y),), "t": (len(t),)},
            status="rejected",
        )
    return finish(-1)