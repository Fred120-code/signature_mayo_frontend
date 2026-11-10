"""MAYO compact key-pair generation."""

from time import perf_counter

from core.matrix import Matrix, matrix_add, matrix_multiply, matrix_transpose
from core.quadratic import upper_triangle
from crypto.encoding import encode_matrices
from crypto.hashing import derive_key_material
from crypto.randomness import random_bytes
from keys.expand_public import generate_P1_P2
from keys.expand_secret import decode_O
from scheme.trace import KeygenTrace
from keys.parameters import (
    M,
    O_DIM,
    SEED_SK_BYTES,
    SEED_PK_BYTES,
    V,
)

def compute_P3(
    O: Matrix,
    P1: list[Matrix],
    P2: list[Matrix],
) -> list[Matrix]:
    """Compute the upper-triangular P3 matrices for a generated public key.

    Args:
        O: Secret oil matrix of size ``V x O_DIM``.
        P1: The ``M`` upper-triangular matrices of size ``V x V``.
        P2: The ``M`` matrices of size ``V x O_DIM``.

    Returns:
        The ``M`` upper-triangular matrices of size ``O_DIM x O_DIM``.

    Raises:
        ValueError: If P1 or P2 does not contain exactly ``M`` matrices.
    """
    if len(P1) != M or len(P2) != M:
        raise ValueError("Nombre incorrect de matrices P1 ou P2")

    O_T = matrix_transpose(O)
    P3 = []
    for index in range(M):
        temp = matrix_multiply(O_T, P1[index])
        A = matrix_multiply(temp, O)
        B = matrix_multiply(O_T, P2[index])
        P3.append(upper_triangle(matrix_add(A, B)))

    return P3


def encode_P3(P3: list[Matrix]) -> bytes:
    """Encode the upper triangle of P3 in its original interleaved order.

    Args:
        P3: Exactly ``M`` matrices of size ``O_DIM x O_DIM``.

    Returns:
        Packed public-key P3 bytes.

    Raises:
        ValueError: If the matrix count or a field element is invalid.
    """
    if len(P3) != M:
        raise ValueError("Nombre incorrect de matrices P3")

    return encode_matrices(P3, O_DIM, O_DIM, triangular=True)


def generate_keypair(*, return_trace: bool = False):
    """Generate the compact MAYO public and secret keys (spec, Algorithm 5).

    Args:
        return_trace: If true, also return a :class:`KeygenTrace` with the
            ordered steps. Secret values (``seed_sk``, ``O``) are never
            recorded; only sizes, shapes, public values and durations.

    Returns:
        ``(cpk, csk)``, or ``((cpk, csk), trace)`` when ``return_trace``.
    """
    trace = KeygenTrace() if return_trace else None
    clock = perf_counter()

    def step(name, description, *, data=None, dimensions=None):
        nonlocal clock
        if trace is None:
            return
        now = perf_counter()
        values = dict(data or {})
        values["elapsed_ms"] = round((now - clock) * 1000)
        trace.add_step(name, description, data=values, dimensions=dimensions)
        clock = perf_counter()

    p1_bytes = M * V * (V + 1) // 4
    p2_bytes = M * V * O_DIM // 2
    p3_bytes = M * O_DIM * (O_DIM + 1) // 4

    seed_sk = random_bytes(SEED_SK_BYTES)
    step(
        "seed_sk_drawn",
        "seed_sk est tiré au hasard : c'est la clé secrète compacte. Sa "
        "valeur n'est jamais affichée.",
        data={"seed_sk_bytes": SEED_SK_BYTES},
    )

    seed_pk, encoded_O = derive_key_material(
        seed_sk,
        SEED_SK_BYTES,
        SEED_PK_BYTES,
        V,
        O_DIM,
    )
    step(
        "key_material_derived",
        "SHAKE256(seed_sk) produit seed_pk (public) et les octets qui "
        "encodent la matrice secrète O.",
        data={
            "seed_pk_hex": seed_pk.hex(),
            "seed_pk_bytes": len(seed_pk),
            "oil_bytes": len(encoded_O),
        },
    )

    O = decode_O(encoded_O)
    step(
        "oil_matrix_decoded",
        "Les octets d'huile sont décodés en la matrice secrète O. Ses "
        "coefficients ne sont pas enregistrés.",
        dimensions={"O": (V, O_DIM)},
    )

    P1, P2 = generate_P1_P2(seed_pk)
    step(
        "p1_p2_expanded",
        "AES-128-CTR(seed_pk) produit les octets de P1 et P2, décodés "
        "depuis leur encodage bitsliced.",
        data={
            "aes_output_bytes": p1_bytes + p2_bytes,
            "p1_bytes": p1_bytes,
            "p2_bytes": p2_bytes,
        },
        dimensions={"P1": (M, V, V), "P2": (M, V, O_DIM)},
    )

    P3 = compute_P3(O, P1, P2)
    step(
        "p3_computed",
        "Pour chaque i : P3_i = Upper(−Oᵀ·P1_i·O − Oᵀ·P2_i). C'est la "
        "seule partie de la clé publique qui dépend de la clé secrète.",
        dimensions={"P3": (M, O_DIM, O_DIM)},
    )

    encoded_P3 = encode_P3(P3)
    step(
        "p3_encoded",
        "Le triangle supérieur de P3 est encodé en bitsliced.",
        data={"p3_bytes": len(encoded_P3), "expected_p3_bytes": p3_bytes},
    )

    cpk = seed_pk + encoded_P3
    step(
        "keys_assembled",
        "Clé publique compacte : seed_pk ∥ P3. Clé secrète compacte : "
        "seed_sk.",
        data={
            "compact_public_key_bytes": len(cpk),
            "compact_secret_key_bytes": len(seed_sk),
        },
    )

    if trace is not None:
        return (cpk, seed_sk), trace
    return cpk, seed_sk