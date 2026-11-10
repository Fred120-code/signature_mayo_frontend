"""MAYO signing orchestration, separated from user-interface concerns."""

from typing import Literal, overload

from core.field import add
from core.matrix import (
    Matrix,
    matrix_multiply,
    matrix_transpose,
    matrix_vector_multiply,
    vector_dot,
    vector_subtract,
)
from crypto.encoding import decode_vector, encode_vector
from crypto.hashing import shake256
from crypto.randomness import random_bytes
from keys.expand_secret import parse_esk
from keys.parameters import (
    DIGEST_BYTES,
    K,
    M,
    N,
    O_DIM,
    R_BYTES,
    SALT_BYTES,
    V,
)
from scheme.emulsifier import get_E
from scheme.sample_solution import sample_solution
from scheme.trace import SignTrace, SignTraceError


def add_block(A: Matrix, block_index: int, B: Matrix) -> None:
    """Add an ``M x O_DIM`` matrix into one column block of ``A`` in place.

    Args:
        A: Matrix with ``K`` column blocks.
        block_index: Zero-based block to update.
        B: Matrix to add into the selected block.
    """
    base = block_index * O_DIM
    for row in range(M):
        for col in range(O_DIM):
            A[row][base + col] = add(A[row][base + col], B[row][col])


@overload
def sign(
    esk: bytes,
    message: bytes | str,
    *,
    return_trace: Literal[False] = False,
) -> bytes: ...


@overload
def sign(
    esk: bytes,
    message: bytes | str,
    *,
    return_trace: Literal[True],
) -> tuple[bytes, SignTrace]: ...


def sign(
    esk: bytes,
    message: bytes | str,
    *,
    return_trace: bool = False,
) -> bytes | tuple[bytes, SignTrace]:
    """Generate a MAYO signature using an expanded secret key.

    Args:
        esk: Expanded secret key in the existing encoded format.
        message: Message bytes or text to sign.
        return_trace: If true, return a second value containing a trace with
            metadata and safe previews, omitting secret key material.

    Returns:
        Signature bytes containing the encoded vector followed by its salt,
        or ``(signature, trace)`` when ``return_trace`` is true.

    Raises:
        RuntimeError: If no solution is found within the existing 256 retries.
            When tracing is enabled, the raised ``SignTraceError`` subclass
            also exposes the partial trace through its ``trace`` attribute.
        ValueError: If the expanded secret key or input dimensions are invalid.
    """
    trace = SignTrace() if return_trace else None

    if isinstance(message, str):
        message = message.encode("utf-8")

    seed_sk, O, P1, L = parse_esk(esk)
    if trace is not None:
        trace.add_step(
            "secret_key_prepared",
            "La clé étendue a été analysée en mémoire; ses éléments secrets "
            "ne sont pas copiés dans la trace.",
            data={
                "expanded_key_bytes": len(esk),
                "polynomial_count": len(P1),
                "linking_matrix_count": len(L),
            },
            dimensions={
                "O": (len(O), len(O[0]) if O else 0),
                "P1": (
                    len(P1),
                    len(P1[0]) if P1 else 0,
                    len(P1[0][0]) if P1 and P1[0] else 0,
                ),
                "L": (
                    len(L),
                    len(L[0]) if L else 0,
                    len(L[0][0]) if L and L[0] else 0,
                ),
            },
        )

    m_digest = shake256(message, DIGEST_BYTES)
    if trace is not None:
        trace.add_step(
            "message_digest",
            "SHAKE256 calcule le digest du message.",
            data={
                "digest_bytes": len(m_digest),
                "digest_preview_hex": m_digest[:8].hex(),
            },
        )

    r_val = random_bytes(R_BYTES)
    salt_input = m_digest + r_val + seed_sk
    salt = shake256(salt_input, SALT_BYTES)
    if trace is not None:
        trace.add_step(
            "salt_generated",
            "Le sel est dérivé du digest, d'un aléa éphémère et de la graine "
            "secrète; seuls le sel public et la taille de l'aléa sont tracés.",
            data={
                "salt_bytes": len(salt),
                "salt_hex": salt.hex(),
                "random_input_bytes": len(r_val),
            },
        )

    t = decode_vector(M, shake256(m_digest + salt, (M + 1) // 2))
    if trace is not None:
        trace.add_step(
            "target_derived",
            "Le vecteur cible t est dérivé du digest et du sel avec "
            "SHAKE256.",
            data={"t_preview": t[:8]},
            dimensions={"t": (len(t),)},
        )

    E = get_E()
    if trace is not None:
        trace.add_step(
            "emulsifier_loaded",
            "La table des matrices E est récupérée pour combiner les blocs "
            "du système.",
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

    for ctr in range(256):
        v_bytes_len = K * (V // 2)
        r_bytes_len = (K * O_DIM + 1) // 2
        v_seed_input = m_digest + salt + seed_sk + bytes([ctr])
        v_output = shake256(v_seed_input, v_bytes_len + r_bytes_len)

        v_list = []
        for i in range(K):
            vi_bytes = v_output[i * (V // 2):(i + 1) * (V // 2)]
            v_list.append(decode_vector(V, vi_bytes))

        r = decode_vector(K * O_DIM, v_output[v_bytes_len:])
        if trace is not None:
            trace.add_step(
                "attempt_values_generated",
                "SHAKE256 dérive les blocs vinegar et le vecteur aléatoire "
                "de la tentative; leurs coefficients ne sont pas enregistrés.",
                data={
                    "attempt": ctr + 1,
                    "counter": ctr,
                    "random_output_bytes": len(v_output),
                    "vinegar_block_count": len(v_list),
                    "random_vector_elements": len(r),
                },
                attempt=ctr + 1,
                dimensions={
                    "vinegar_blocks": (
                        len(v_list),
                        len(v_list[0]) if v_list else 0,
                    ),
                    "r": (len(r),),
                },
            )

        M_matrices = []
        for i in range(K):
            Mi = [[0] * O_DIM for _ in range(M)]
            vi = v_list[i]
            for j in range(M):
                Mi[j] = matrix_vector_multiply(matrix_transpose(L[j]), vi)
            M_matrices.append(Mi)

        y = list(t)
        W = [
            [matrix_vector_multiply(P1[a], vj) for a in range(M)]
            for vj in v_list
        ]
        A = [[0] * (K * O_DIM) for _ in range(M)]
        if trace is not None:
            trace.add_step(
                "intermediate_matrices_built",
                "Les matrices intermédiaires liées aux blocs vinegar et les "
                "produits W sont construits; leurs coefficients sensibles "
                "sont omis.",
                data={
                    "M_matrix_count": len(M_matrices),
                    "W_vector_count": sum(len(block) for block in W),
                    "coefficients_recorded": False,
                },
                attempt=ctr + 1,
                dimensions={
                    "M_matrices": (
                        len(M_matrices),
                        len(M_matrices[0]) if M_matrices else 0,
                        len(M_matrices[0][0])
                        if M_matrices and M_matrices[0]
                        else 0,
                    ),
                    "W": (
                        len(W),
                        len(W[0]) if W else 0,
                        len(W[0][0]) if W and W[0] else 0,
                    ),
                },
            )

        for i in range(K):
            vi = v_list[i]
            for j in range(i, K):
                vj = v_list[j]
                u = []
                for a in range(M):
                    term = vector_dot(vi, W[j][a])
                    if i != j:
                        term = add(term, vector_dot(vj, W[i][a]))
                    u.append(term)

                y = vector_subtract(y, matrix_vector_multiply(E[i][j], u))
                add_block(A, i, matrix_multiply(E[i][j], M_matrices[j]))
                if i != j:
                    add_block(A, j, matrix_multiply(E[i][j], M_matrices[i]))

        if trace is not None:
            trace.add_step(
                "linear_system_built",
                "Les contributions des blocs sont accumulées pour former "
                "A x = y; les coefficients ne sont pas exposés.",
                data={
                    "matrix_coefficients": len(A) * (len(A[0]) if A else 0),
                    "target_elements": len(y),
                    "coefficients_recorded": False,
                },
                attempt=ctr + 1,
                dimensions={
                    "A": (len(A), len(A[0]) if A else 0),
                    "y": (len(y),),
                    "r": (len(r),),
                },
            )

        x = sample_solution(A, y, r)
        if trace is not None:
            trace.add_step(
                "sample_solution",
                "SampleSolution cherche une solution en utilisant r pour "
                "les variables libres.",
                data={
                    "attempt": ctr + 1,
                    "solution_found": x is not None,
                    "reason": (
                        "system_inconsistent"
                        if x is None
                        else "solution_found"
                    ),
                },
                attempt=ctr + 1,
                dimensions={"solution": (len(x),) if x is not None else ()},
                status="solved" if x is not None else "inconsistent",
            )

        if x is not None:
            s_list = []
            for i in range(K):
                xi_block = x[i * O_DIM:(i + 1) * O_DIM]
                oxi = matrix_vector_multiply(O, xi_block)
                vi_plus_oxi = [
                    add(v_list[i][index], oxi[index])
                    for index in range(V)
                ]
                s_list.extend(vi_plus_oxi + xi_block)

            signature_vector = encode_vector(s_list)
            signature = signature_vector + salt
            if trace is not None:
                trace.add_step(
                    "signature_encoded",
                    "Les blocs de signature sont assemblés, encodés puis "
                    "concaténés au sel.",
                    data={
                        "vector_elements": len(s_list),
                        "encoded_vector_bytes": len(signature_vector),
                        "salt_bytes": len(salt),
                        "signature_bytes": len(signature),
                    },
                    dimensions={
                        "signature_blocks": (K, N),
                        "signature_vector": (len(s_list),),
                    },
                )
                return signature, trace
            return signature

    if trace is not None:
        trace.add_step(
            "signing_failed",
            "Aucune des 256 tentatives n'a produit de solution.",
            data={"attempts": 256},
            status="failed",
        )
    error_message = (
        "Échec de la signature après 256 tentatives (Retry Limit atteint)."
    )
    if trace is not None:
        raise SignTraceError(error_message, trace)
    raise RuntimeError(error_message)