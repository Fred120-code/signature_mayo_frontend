"""
============================================================
                    MAYO1 - SIGNATURE MODULE
============================================================

Ce module implémente l'algorithme de signature (MAYO.Sign)
du schéma post-quantique MAYO1, conformément à l'Algorithme 7
de la spécification officielle.

Etapes :
    1. Découpage de la clé secrète élargie (esk) via parse_esk.
    2. Hachage du message et génération du sel (salt).
    3. Dérivation du vecteur cible t et des blocs d'extension.
    4. Boucle de tirage (Retry Loop) pour trouver une préimage.
    5. Construction et résolution complète du système linéaire Ax = y.
    6. Assemblage et encodage de la signature finale.

Auteurs : Groupe de projet Cryptographie ENSPY (2026-2027)
"""

# ============================================================
# 1. IMPORTATION DES BIBLIOTHEQUES ET MODULES LOCAUX
# ============================================================

import secrets
import hashlib

from Crypto.Cipher import AES

from mayo_operation import add, multiply, subtract
from mayo_matrice import (
    matrix_add,
    matrix_transpose,
    matrix_multiply,
    matrix_vector_multiply,
    solve_linear_system,
    vector_add,
    vector_subtract,
    vector_dot
)
from mayo_keygen import (
    Q, N, M, O_DIM, V, K, SEED_SK_BYTES,
    aes_ctr_expand,
    encode_nibbles,
    decode_nibbles,
    zero_matrix
)
from mayo_expand_sk import parse_esk
from mayo_emulsifier import build_E


# ============================================================
# 2. PARAMETRES DE SIGNATURE MAYO1
# ============================================================

DIGEST_BYTES = 32   # Taille du hachage du message
SALT_BYTES = 24     # Taille du sel (spécification round 3, MAYO1)
R_BYTES = 24        # Taille de l'aléa optionnel R (= salt_bytes)

_E_CACHE = None     # Table des matrices E_ij, construite une seule fois


# ============================================================
# 3. FONCTIONS UTILITAIRES DE VECTEURS
# ============================================================

def decode_vector(dim, data):
    """
    TITRE : Décodage d'un vecteur sur F16.
    """
    elements = decode_nibbles(data)
    if len(elements) < dim:
        raise ValueError("Données insuffisantes pour décoder le vecteur")
    return elements[:dim]


def encode_vector(vector):
    """
    TITRE : Encodage d'un vecteur sur F16.
    """
    for val in vector:
        if not 0 <= val < Q:
            raise ValueError("Élément invalide dans F16 pour l'encodage du vecteur")
    return encode_nibbles(vector)


# ============================================================
# 4. FONCTIONS AUXILIAIRES DE SIGNATURE
# ============================================================

def get_E():
    """
    TITRE : Table des matrices E_ij de MAYO1.

    DESCRIPTION :
    Construit la table E[i][j] (voir mayo_emulsifier) à la première
    utilisation, puis la réutilise aux appels suivants.

    RETOUR :
        Une table K x K de matrices M x M.
    """

    global _E_CACHE

    if _E_CACHE is None:
        _E_CACHE = build_E(M, K)

    return _E_CACHE


def aes_ctr_expand_iv(key, iv, output_length):
    """
    TITRE : Expansion AES-128-CTR avec clé et IV explicites.

    DESCRIPTION :
    Les blocs compteur sont iv, iv + 1, iv + 2, ... (entier de
    128 bits en big-endian), chiffrés avec AES-128.

    REMARQUE :
    La convention exacte du compteur doit être vérifiée avec la
    spécification et les vecteurs officiels MAYO.

    PARAMETRES :
        key : clé AES de 16 octets.
        iv : bloc compteur initial de 16 octets.
        output_length : nombre d'octets à produire.

    RETOUR :
        Une suite d'octets de longueur output_length.
    """

    if len(key) != 16 or len(iv) != 16:
        raise ValueError("key et iv doivent contenir 16 octets")

    aes = AES.new(key, AES.MODE_ECB)

    counter = int.from_bytes(iv, byteorder="big")
    output = bytearray()

    while len(output) < output_length:

        counter_block = (counter % (1 << 128)).to_bytes(
            16,
            byteorder="big"
        )

        output.extend(aes.encrypt(counter_block))

        counter += 1

    return bytes(output[:output_length])


def derive_t_and_lambda(m_digest, salt):
    """
    TITRE : Dérivation du vecteur cible t et de la matrice Lambda.

    DESCRIPTION :
    Lignes 11 à 14 de l'Algorithme 7 :
        hash = SHAKE256(M_digest || salt, M/2 + 32)
        t = les M/2 premiers octets décodés
        Lambda = AES-128-CTR(clé = hash[M/2 : M/2+16],
                             iv  = hash[M/2+16 : M/2+32]),
                 matrice M x N lue ligne par ligne.
    Lambda_v correspond aux V premières colonnes et Lambda_o aux
    O_DIM dernières.

    Cette fonction est partagée par Sign et Verify.

    PARAMETRES :
        m_digest : hachage du message.
        salt : sel de la signature.

    RETOUR :
        t : vecteur cible de F16^M.
        Lambda : matrice M x N.
    """

    hash_input = m_digest + salt
    target_bytes_len = M // 2 + 32
    hash_output = hashlib.shake_256(hash_input).digest(target_bytes_len)

    t_bytes = hash_output[: M // 2]
    t = decode_vector(M, t_bytes)

    aes_key = hash_output[M // 2 : M // 2 + 16]
    aes_iv = hash_output[M // 2 + 16 : M // 2 + 32]

    lambda_bytes = aes_ctr_expand_iv(aes_key, aes_iv, (M * N) // 2)
    lambda_flat = decode_nibbles(lambda_bytes)

    Lambda = [
        lambda_flat[i * N : (i + 1) * N]
        for i in range(M)
    ]

    return t, Lambda


def add_block(A, block_index, B):
    """
    TITRE : Ajout d'un bloc de colonnes dans la matrice A.

    DESCRIPTION :
    Effectue A[:, block_index * O_DIM : (block_index + 1) * O_DIM] += B
    avec l'addition de F16.

    PARAMETRES :
        A : matrice M x (K * O_DIM), modifiée sur place.
        block_index : indice du bloc de colonnes.
        B : matrice M x O_DIM à ajouter.

    RETOUR :
        Aucun. La matrice A est modifiée.
    """

    base = block_index * O_DIM

    for r in range(M):
        for c in range(O_DIM):
            A[r][base + c] = add(A[r][base + c], B[r][c])


def sample_solution(A, y, r):
    """
    TITRE : Résolution de A x = y avec variables libres tirées de r.

    DESCRIPTION :
    Équivalent de SampleSolution(A, y, r) : les variables libres
    prennent les valeurs de r. On résout A x0 = y - A r (variables
    libres à zéro), puis x = x0 + r.

    PARAMETRES :
        A : matrice M x (K * O_DIM).
        y : vecteur de F16^M.
        r : vecteur de F16^(K * O_DIM).

    RETOUR :
        Une solution x, ou None si le système est incompatible.
    """

    Ar = matrix_vector_multiply(A, r)

    x0 = solve_linear_system(A, vector_subtract(y, Ar))

    if x0 is None:
        return None

    return vector_add(x0, r)


# ============================================================
# 5. ALGORITHME DE SIGNATURE (MAYO.Sign)
# ============================================================

def sign(esk, message):
    """
    TITRE : Génération d'une signature MAYO (MAYO.Sign - Algorithme 7).

    PARAMETRES :
        esk     : clé secrète élargie (bytes).
        message : message à signer (bytes ou str).

    RETOUR :
        sig : signature encodée binaire (bytes).
    """
    if isinstance(message, str):
        message = message.encode('utf-8')

    # 1. Décodage de la clé secrète élargie
    seed_sk, O, P1, L = parse_esk(esk)

    # 2. Hachage du message
    m_digest = hashlib.shake_256(message).digest(DIGEST_BYTES)

    # 3. Génération de l'aléa R et du sel (salt)
    r_val = secrets.token_bytes(R_BYTES)
    salt_input = m_digest + r_val + seed_sk
    salt = hashlib.shake_256(salt_input).digest(SALT_BYTES)

    # 4. Dérivation du vecteur cible t et des coefficients Lambda
    t, Lambda = derive_t_and_lambda(m_digest, salt)

    Lambda_v = [row[:V] for row in Lambda]
    Lambda_o = [row[V:] for row in Lambda]

    # Matrices E_ij (multiplication par z^l modulo f(z))
    E = get_E()

    # 5. Boucle de tirage (Retry Loop)
    for ctr in range(256):
        v_bytes_len = K * (V // 2)
        r_bytes_len = (K * O_DIM + 1) // 2
        v_seed_input = m_digest + salt + seed_sk + bytes([ctr])
        v_output = hashlib.shake_256(v_seed_input).digest(v_bytes_len + r_bytes_len)

        v_list = []
        for i in range(K):
            vi_bytes = v_output[i * (V // 2) : (i + 1) * (V // 2)]
            vi = decode_vector(V, vi_bytes)
            v_list.append(vi)

        r_bytes = v_output[v_bytes_len:]
        r = decode_vector(K * O_DIM, r_bytes)

        # 1. Calcul des matrices M_i (M x O_DIM)
        M_matrices = []
        for i in range(K):
            Mi = zero_matrix(M, O_DIM)
            vi = v_list[i]
            for j in range(M):
                Mi[j] = matrix_vector_multiply(matrix_transpose(L[j]), vi)
            M_matrices.append(Mi)

        # Ligne 31 : M_0 <- M_0 + Lambda_v * O + Lambda_o
        M_matrices[0] = matrix_add(
            matrix_add(M_matrices[0], matrix_multiply(Lambda_v, O)),
            Lambda_o
        )

        # 2. Initialisation du vecteur y à partir de t
        y = list(t)

        # W[j][a] = P1_a * v_j
        # (P1_a est triangulaire supérieure : on ne la symétrise pas)
        W = [
            [matrix_vector_multiply(P1[a], vj) for a in range(M)]
            for vj in v_list
        ]

        # 3. Construction de la matrice A et soustraction des termes (Lignes 32-39 de l'Algo 7)
        A = zero_matrix(M, K * O_DIM)

        for i in range(K):
            vi = v_list[i]

            # Ligne 33 : y <- y - E_i0 * Lambda_v * v_i
            lam_v_vi = matrix_vector_multiply(Lambda_v, vi)
            y = vector_subtract(y, matrix_vector_multiply(E[i][0], lam_v_vi))

            for j in range(i, K):
                vj = v_list[j]

                # Ligne 35 : u_a = vi^T * P1_a * vj (+ vj^T * P1_a * vi si i != j)
                u = [0] * M
                for a in range(M):
                    term = vector_dot(vi, W[j][a])

                    # Terme croisé si i != j (symétrie)
                    if i != j:
                        term = add(term, vector_dot(vj, W[i][a]))

                    u[a] = term

                # Ligne 36 : y <- y - E_ij * u
                y = vector_subtract(y, matrix_vector_multiply(E[i][j], u))

                # Lignes 37-39 : accumulation dans A par blocs E_ij * M_j et E_ij * M_i
                add_block(A, i, matrix_multiply(E[i][j], M_matrices[j]))

                if i != j:
                    add_block(A, j, matrix_multiply(E[i][j], M_matrices[i]))

        # Résolution du système linéaire Ax = y (variables libres tirées de r)
        x = sample_solution(A, y, r)

        if x is not None:
            # Succès : Construction de la signature s
            s_list = []
            for i in range(K):
                xi_block = x[i * O_DIM : (i + 1) * O_DIM]
                oxi = matrix_vector_multiply(O, xi_block)
                vi_plus_oxi = [add(v_list[i][idx], oxi[idx]) for idx in range(V)]
                s_list.extend(vi_plus_oxi + xi_block)

            sig = encode_vector(s_list) + salt
            return sig

    raise RuntimeError("Échec de la signature après 256 tentatives (Retry Limit atteint).")


# ============================================================
# 6. FONCTIONS DE TEST UNITAIRES
# ============================================================

def test_sample_solution():
    """
    TITRE : Test de la fonction sample_solution.

    DESCRIPTION :
    Construit un système A x0 = y résoluble, puis vérifie que la
    solution retournée satisfait A x = y. Vérifie aussi qu'un
    système incompatible renvoie None.
    """
    print("\n===== TEST SAMPLE_SOLUTION =====")

    taille = 6

    A = [[secrets.randbelow(Q) for _ in range(taille)] for _ in range(taille)]
    x0 = [secrets.randbelow(Q) for _ in range(taille)]
    r = [secrets.randbelow(Q) for _ in range(taille)]

    y = matrix_vector_multiply(A, x0)

    x = sample_solution(A, y, r)

    print("Solution trouvée :", x)

    assert x is not None
    assert matrix_vector_multiply(A, x) == y

    assert sample_solution([[1, 1], [1, 1]], [1, 2], [0, 0]) is None

    print("A x = y verifie, systeme incompatible detecte !")


def test_sign_module():
    """
    TITRE : Test de base du module de signature.
    """
    print("\n===== TEST MODULE DE SIGNATURE (MAYO.Sign) =====")

    from mayo_keygen import generate_secret_seed
    from mayo_expand_sk import expand_secret_key

    seed_sk = generate_secret_seed()
    esk = expand_secret_key(seed_sk)

    message = "Bonjour l'ENSPY - Test de signature MAYO1"
    print("Message à signer :", message)

    sig = sign(esk, message)
    print("Signature générée avec succès !")
    print(f"Taille totale de la signature : {len(sig)} octets")

    # Affichage de la signature en format hexadécimal (tronqué ou complet)
    print(f"Signature (Hex) : {sig.hex()}")

    # On peut séparer visuellement le sel (les 24 derniers octets) de la partie vecteur s
    salt_part = sig[-SALT_BYTES:]
    vector_part = sig[:-SALT_BYTES]
    print(f" -> Partie vecteur s : {len(vector_part)} octets")
    print(f" -> Partie sel (salt) : {salt_part.hex()}")

    assert len(sig) > SALT_BYTES
    assert len(sig) == 464
    print("Test de signature validé !")


# ============================================================
# 7. POINT D'ENTREE DU PROGRAMME
# ============================================================

if __name__ == "__main__":
    test_sample_solution()
    test_sign_module()
