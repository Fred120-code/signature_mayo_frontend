"""
============================================================
                    MAYO1 - SECRET KEY EXPANSION
============================================================

Ce module implémente l'expansion de la clé secrète compacte (csk)
en une clé secrète élargie (esk) pour le schéma MAYO1, conformément
à l'Algorithme 5 (MAYO.ExpandSK) de la spécification officielle.

Etapes :
    1. Extraction de seed_sk depuis csk.
    2. Dérivation de seed_pk et O (SHAKE256).
    3. Décodage de la matrice O.
    4. Génération et décodage de P1 et P2 (AES-128-CTR).
    5. Calcul des M matrices de liaison Li = (P1_i + P1_i^T) * O + P2_i.
    6. Encodage des matrices Li.
    7. Construction et retour de la clé secrète élargie (esk).

"""

# ============================================================
# 1. IMPORTATION DES BIBLIOTHEQUES ET MODULES LOCAUX
# ============================================================

from mayo_operation import add
from mayo_matrice import (
    matrix_add,
    matrix_transpose,
    matrix_multiply
)
from mayo_keygen import (
    Q, N, M, O_DIM, V, SEED_SK_BYTES, SEED_PK_BYTES,
    derive_key_material,
    decode_O,
    generate_P1_P2,
    encode_nibbles,
    decode_nibbles,
    zero_matrix
)


# ============================================================
# 2. CALCUL DE LA PARTIE SYMETRIQUE (P1_i + P1_i^T)
# ============================================================

def symmetric_P1(P1_i):
    """
    TITRE : Reconstitution de la matrice symétrique complète.

    DESCRIPTION :
    À partir d'une matrice P1_i triangulaire supérieure de dimensions
    V x V sur F16, calcule la matrice symétrique P1_i + P1_i^T.

    Dans F16 (caractéristique 2), l'addition est le XOR (^).
    Pour tout r != c, le coefficient vaut P1_i[r][c] ^ P1_i[c][r].
    Sur la diagonale (r == c), x ^ x = 0.

    PARAMETRE :
        P1_i : matrice triangulaire supérieure V x V.

    RETOUR :
        Une matrice carrée V x V symétrique à diagonale nulle.
    """

    size = len(P1_i)
    sym = zero_matrix(size, size)

    for r in range(size):
        for c in range(size):
            if r != c:
                val_rc = P1_i[r][c] if c >= r else 0
                val_cr = P1_i[c][r] if r >= c else 0
                sym[r][c] = add(val_rc, val_cr)
            else:
                sym[r][r] = 0

    return sym


# ============================================================
# 3. CALCUL DES MATRICES DE LIAISON L_i
# ============================================================

def compute_L(O, P1, P2):
    """
    TITRE : Calcul des matrices de liaison L_i.

    DESCRIPTION :
    Pour chaque polynôme i de 0 à M - 1, calcule la matrice :

        L_i = (P1_i + P1_i^T) * O + P2_i

    PARAMETRES :
        O  : matrice secrète d'huile de dimensions V x O_DIM (80 x 8).
        P1 : liste des M matrices triangulaires supérieures V x V (80 x 80).
        P2 : liste des M matrices V x O_DIM (80 x 8).

    RETOUR :
        Liste de M matrices L_i de dimensions V x O_DIM (80 x 8).
    """

    if len(P1) != M or len(P2) != M:
        raise ValueError("Nombre incorrect de matrices P1 ou P2")

    L = []

    for i in range(M):
        # 1. Calcul de (P1_i + P1_i^T)
        P1_sym = symmetric_P1(P1[i])

        # 2. Multiplication par O : dimensions (V x V) * (V x O_DIM) = (V x O_DIM)
        term1 = matrix_multiply(P1_sym, O)

        # 3. Addition dans F16 avec P2_i
        L_i = matrix_add(term1, P2[i])

        L.append(L_i)

    return L


# ============================================================
# 4. ENCODAGE ET DECODAGE DES MATRICES L_i
# ============================================================

def encode_L(L):
    """
    TITRE : Encodage compact des matrices L.

    DESCRIPTION :
    Récupère l'ensemble des coefficients des M matrices L_i selon l'ordre
    entrelacé (pour chaque ligne r, pour chaque colonne c, pour chaque k dans [0, M-1]),
    puis les empacte par couples de nibbles dans des octets.

    PARAMETRE :
        L : liste des M matrices de dimensions V x O_DIM.

    RETOUR :
        Suite d'octets encodée représentant les matrices L.
    """

    if len(L) != M:
        raise ValueError("Nombre incorrect de matrices L")

    elements = []

    for r in range(V):
        for c in range(O_DIM):
            for k in range(M):
                val = L[k][r][c]
                if not 0 <= val < Q:
                    raise ValueError("Elément invalide dans F16")
                elements.append(val)

    return encode_nibbles(elements)


def decode_L(encoded_L):
    """
    TITRE : Décodage des matrices L.

    DESCRIPTION :
    Reconstitue les M matrices L_i de dimensions V x O_DIM à partir
    de leur représentation binaire encodée.

    PARAMETRE :
        encoded_L : octets encodés de L.

    RETOUR :
        Liste des M matrices L_i de dimensions V x O_DIM.
    """

    expected_elements = M * V * O_DIM
    if len(encoded_L) * 2 != expected_elements:
        raise ValueError("Taille incorrecte de encoded_L")

    elements = decode_nibbles(encoded_L)
    L = [zero_matrix(V, O_DIM) for _ in range(M)]

    pos = 0
    for r in range(V):
        for c in range(O_DIM):
            for k in range(M):
                L[k][r][c] = elements[pos]
                pos += 1

    return L


# ============================================================
# 5. EXPANSION COMPLETE DE LA CLE SECRETE (ALGORITHME 5)
# ============================================================

def expand_secret_key(csk):
    """
    TITRE : Expansion de la clé secrète compacte (MAYO.ExpandSK).

    DESCRIPTION :
    Exécute l'Algorithme 5 de MAYO :
        1. Extrait seed_sk depuis csk.
        2. Dérive seed_pk et encoded_O via SHAKE256.
        3. Décode O.
        4. Génère et décode P1 et P2 via AES-128-CTR.
        5. Calcule les M matrices L_i.
        6. Concatène tous les composants pour former esk.

    PARAMETRE :
        csk : clé secrète compacte (seed_sk de 24 octets).

    RETOUR :
        esk : clé secrète élargie binaire.
    """

    if len(csk) != SEED_SK_BYTES:
        raise ValueError("Taille invalide de csk (seed_sk attendue)")

    seed_sk = csk[:SEED_SK_BYTES]

    # Dérivation SHAKE256
    seed_pk, encoded_O = derive_key_material(seed_sk)

    # Décodage de O
    O = decode_O(encoded_O)

    # Génération et décodage de P1 et P2
    p1_bytes = (M * V * (V + 1) // 2) // 2
    P1, P2 = generate_P1_P2(seed_pk)

    # Reconstitution des octets bruts encodés de P1
    from mayo_keygen import aes_ctr_expand
    p2_bytes = (M * V * O_DIM) // 2
    expanded_P = aes_ctr_expand(seed_pk, p1_bytes + p2_bytes)
    encoded_P1 = expanded_P[:p1_bytes]

    # Calcul des matrices L
    L = compute_L(O, P1, P2)

    # Encodage de L
    encoded_L = encode_L(L)

    # Assemblage de esk = seedsk || encoded_O || encoded_P1 || encoded_L
    esk = seed_sk + encoded_O + encoded_P1 + encoded_L

    return esk


def parse_esk(esk):
    """
    TITRE : Découpage et décodage de la clé secrète élargie (esk).

    DESCRIPTION :
    Utilisé par MAYO.Sign pour extraire directement les structures d'objets Python
    (seed_sk, O, P1, L) à partir de la suite d'octets esk.

    PARAMETRE :
        esk : clé secrète élargie sous forme d'octets.

    RETOUR :
        seed_sk : graine secrète (24 octets).
        O       : matrice secrète d'huile (80 x 8).
        P1      : liste des M matrices V x V.
        L       : liste des M matrices de liaison V x O_DIM.
    """

    o_bytes = (V * O_DIM) // 2
    p1_bytes = (M * V * (V + 1) // 2) // 2
    l_bytes = (M * V * O_DIM) // 2

    expected_length = SEED_SK_BYTES + o_bytes + p1_bytes + l_bytes

    if len(esk) != expected_length:
        raise ValueError(f"Taille incorrecte de esk ({len(esk)} != {expected_length})")

    idx = 0

    seed_sk = esk[idx : idx + SEED_SK_BYTES]
    idx += SEED_SK_BYTES

    encoded_O = esk[idx : idx + o_bytes]
    idx += o_bytes

    encoded_P1 = esk[idx : idx + p1_bytes]
    idx += p1_bytes

    encoded_L = esk[idx : idx + l_bytes]

    O = decode_O(encoded_O)
    from mayo_keygen import decode_P1
    P1 = decode_P1(encoded_P1)
    L = decode_L(encoded_L)

    return seed_sk, O, P1, L


# ============================================================
# 6. FONCTIONS DE TEST UNITAIRES
# ============================================================

def test_symmetric_P1():
    """
    TITRE : Test de la fonction symmetric_P1.

    DESCRIPTION :
    Vérifie la reconstruction symétrique de P1_i + P1_i^T.
    """

    print("\n===== TEST SYMMETRIC_P1 =====")

    # Matrice triangulaire supérieure 2x2 dans F16
    P1_test = [
        [3, 5],
        [0, 9]
    ]

    sym = symmetric_P1(P1_test)

    # Attendu :
    # (0,0) = 0
    # (0,1) = 5 ^ 0 = 5
    # (1,0) = 0 ^ 5 = 5
    # (1,1) = 0
    assert sym[0][0] == 0
    assert sym[0][1] == 5
    assert sym[1][0] == 5
    assert sym[1][1] == 0

    print("Test symétrisation réussi !")


def test_compute_L():
    """
    TITRE : Test du calcul des matrices de liaison L_i.

    DESCRIPTION :
    Génère des paramètres et vérifie le nombre et les dimensions des M matrices L_i.
    """

    print("\n===== TEST COMPUTE_L =====")

    from mayo_keygen import generate_secret_seed

    seed_sk = generate_secret_seed()
    seed_pk, encoded_O = derive_key_material(seed_sk)

    O = decode_O(encoded_O)
    P1, P2 = generate_P1_P2(seed_pk)

    L = compute_L(O, P1, P2)

    print("Nombre de matrices L :", len(L))
    print("Dimensions de L[0]   :", len(L[0]), "x", len(L[0][0]))

    assert len(L) == M
    assert all(len(matrix) == V for matrix in L)
    assert all(len(row) == O_DIM for matrix in L for row in matrix)
    assert all(0 <= val < Q for matrix in L for row in matrix for val in row)

    print("Calcul des matrices L réussi !")


def test_encode_decode_L():
    """
    TITRE : Test d'encodage / décodage des matrices L.

    DESCRIPTION :
    Vérifie que encode_L puis decode_L restitue exactement les matrices initiales.
    """

    print("\n===== TEST ENCODE / DECODE L =====")

    from mayo_keygen import generate_secret_seed

    seed_sk = generate_secret_seed()
    seed_pk, encoded_O = derive_key_material(seed_sk)

    O = decode_O(encoded_O)
    P1, P2 = generate_P1_P2(seed_pk)

    L_orig = compute_L(O, P1, P2)
    encoded_L = encode_L(L_orig)
    L_rec = decode_L(encoded_L)

    assert L_orig == L_rec, "Échec du test aller-retour pour L !"

    print("Test encodage/décodage de L réussi !")


def test_expand_secret_key():
    """
    TITRE : Test d'expansion globale de la clé secrète (MAYO.ExpandSK).

    DESCRIPTION :
    Génère une csk, exécute ExpandSK et contrôle la taille totale de esk
    ainsi que le bon découpage via parse_esk.
    """

    print("\n===== TEST EXPAND_SECRET_KEY (ALGORITHME 5) =====")

    from mayo_keygen import generate_secret_seed

    csk = generate_secret_seed()
    esk = expand_secret_key(csk)

    print("Taille de csk (clé compacte) :", len(csk), "octets")
    print("Taille de esk (clé élargie)  :", len(esk), "octets")

    # Vérification des tailles des composants dans esk pour MAYO1 :
    # seed_sk : 24 octets
    # O : 80 * 8 / 2 = 320 octets
    # P1 : 80 * (80 * 81 / 2) / 2 = 129 600 octets
    # L : 80 * (80 * 8) / 2 = 25 600 octets
    # Total attendu : 24 + 320 + 129 600 + 25 600 = 155 544 octets
    assert len(csk) == 24
    assert len(esk) == 155544

    seed_sk_parsed, O_parsed, P1_parsed, L_parsed = parse_esk(esk)

    assert seed_sk_parsed == csk
    assert len(O_parsed) == V and len(O_parsed[0]) == O_DIM
    assert len(P1_parsed) == M
    assert len(L_parsed) == M

    print("Expansion de la clé secrète entièrement validée !")


# ============================================================
# 7. POINT D'ENTREE DU PROGRAMME
# ============================================================

if __name__ == "__main__":

    test_symmetric_P1()
    test_compute_L()
    test_encode_decode_L()
    test_expand_secret_key()