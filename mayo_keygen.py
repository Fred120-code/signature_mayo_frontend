"""
============================================================
                    MAYO1 - KEY GENERATION
============================================================

Ce module implémente les principales étapes de la génération
des clés du schéma de signature post-quantique MAYO1.

Etapes :
    1. Vérification des paramètres.
    2. Génération de la graine secrète.
    3. Dérivation des données avec SHAKE256.
    4. Décodage de la matrice O.
    5. Expansion AES et génération de P1 et P2.
    6. Calcul des matrices P3.
    7. Encodage de P3.
    8. Construction de la clé publique et de la clé secrète.

Attention :
Ce code est une implémentation pédagogique. La conformité
complète doit être vérifiée avec la spécification MAYO
Round 3 et ses vecteurs de test officiels.
"""

# ============================================================
# 1. IMPORTATION DES BIBLIOTHEQUES
# ============================================================

import secrets
import hashlib

from Crypto.Cipher import AES

from mayo_matrice import (
    matrix_add,
    matrix_transpose,
    matrix_multiply
)


# ============================================================
# 2. PARAMETRES DE MAYO1
# ============================================================

Q = 16          # Taille du corps fini F16
N = 88          # Nombre de variables
M = 80          # Nombre de polynomes quadratiques
O_DIM = 8       # Nombre de variables Oil
K = 10          # Parametre k

SEED_SK_BYTES = 24   # Taille de la graine secrete
SEED_PK_BYTES = 16  # Taille de la graine publique

V = N - O_DIM       # Nombre de variables Vinegar : 80


# ============================================================
# 3. FONCTIONS UTILITAIRES SUR LES MATRICES
# ============================================================

def zero_matrix(rows, cols):
    """
    TITRE : Création d'une matrice nulle.

    DESCRIPTION :
    Construit une matrice de dimensions rows x cols
    dont tous les éléments sont initialisés à zéro.

    PARAMETRES :
        rows : nombre de lignes.
        cols : nombre de colonnes.

    RETOUR :
        Une matrice remplie de zéros.
    """

    return [
        [0 for _ in range(cols)]
        for _ in range(rows)
    ]


def upper_triangle(A):
    """
    TITRE : Calcul de Upper(A) selon la spécification MAYO.

    DESCRIPTION :
    Construit la matrice triangulaire supérieure suivante :
        Upper(A)[i][j] = A[i][j] + A[j][i]   si i < j
        Upper(A)[i][i] = A[i][i]
        Upper(A)[i][j] = 0                   si i > j

    L'addition dans F16 est le XOR (^).

    PARAMETRE :
        A : matrice carrée.

    RETOUR :
        Une nouvelle matrice triangulaire supérieure.
    """

    if not A or not A[0]:
        raise ValueError("Matrice vide")

    if any(len(row) != len(A) for row in A):
        raise ValueError("La matrice doit etre carree")

    size = len(A)

    return [
        [
            (A[i][j] ^ A[j][i]) if j > i
            else (A[i][j] if j == i else 0)
            for j in range(size)
        ]
        for i in range(size)
    ]

# ============================================================
# 4. VERIFICATION DES PARAMETRES
# ============================================================

def check_parameters():
    """
    TITRE : Vérification des paramètres MAYO1.

    DESCRIPTION :
    Vérifie certaines conditions de cohérence des paramètres
    utilisés dans notre implémentation de MAYO1.

    RETOUR :
        Aucun. Déclenche une assertion si une condition échoue.
    """

    assert Q == 16
    assert V == 80
    assert V >= M
    assert K * O_DIM >= M

    print("Parametres MAYO1 valides !")


# ============================================================
# 5. GENERATION ET DERIVATION DES GRAINES
# ============================================================

def generate_secret_seed():
    """
    TITRE : Génération de la graine secrète.

    DESCRIPTION :
    Génère une graine secrète aléatoire cryptographiquement
    sûre de 24 octets à l'aide du module secrets.

    RETOUR :
        Une graine secrète de SEED_SK_BYTES octets.
    """

    return secrets.token_bytes(SEED_SK_BYTES)


def derive_key_material(seed_sk):
    """
    TITRE : Dérivation des données de clé avec SHAKE256.

    DESCRIPTION :
    Utilise SHAKE256 pour dériver, à partir de la graine
    secrète, la graine publique seed_pk et la représentation
    encodée de la matrice O.

    PARAMETRE :
        seed_sk : graine secrète de 24 octets.

    RETOUR :
        seed_pk  : graine publique de 16 octets.
        encoded_O : représentation encodée de la matrice O.
    """

    if len(seed_sk) != SEED_SK_BYTES:
        raise ValueError("Taille incorrecte de seed_sk")

    o_bytes = (V * O_DIM) // 2

    output_length = SEED_PK_BYTES + o_bytes

    output = hashlib.shake_256(seed_sk).digest(output_length)

    seed_pk = output[:SEED_PK_BYTES]

    encoded_O = output[SEED_PK_BYTES:]

    return seed_pk, encoded_O


# ============================================================
# 6. DECODAGE DE LA MATRICE O
# ============================================================

def decode_O(encoded_O):
    """
    TITRE : Décodage de la matrice secrète O.

    DESCRIPTION :
    Transforme les octets encodés en éléments de F16.
    Chaque octet contient deux éléments :
        - le nibble de poids faible ;
        - le nibble de poids fort.

    Les éléments sont ensuite organisés dans une matrice
    de dimensions V x O_DIM, soit 80 x 8 pour MAYO1.

    PARAMETRE :
        encoded_O : représentation binaire de la matrice O.

    RETOUR :
        La matrice O de dimensions 80 x 8.
    """

    expected_elements = V * O_DIM

    if len(encoded_O) * 2 != expected_elements:
        raise ValueError("Taille incorrecte de encoded_O")

    elements = []

    for byte in encoded_O:

        low = byte & 0x0F
        high = (byte >> 4) & 0x0F

        elements.append(low)
        elements.append(high)

    O = [
        elements[i * O_DIM:(i + 1) * O_DIM]
        for i in range(V)
    ]

    return O


# ============================================================
# 7. EXPANSION AES-128-CTR
# ============================================================

def aes_ctr_expand(seed_pk, output_length):
    """
    TITRE : Expansion des données avec AES-128.

    DESCRIPTION :
    Utilise seed_pk comme clé AES de 128 bits pour produire
    une suite d'octets à partir de blocs compteur successifs.

    Chaque compteur est représenté sur 16 octets en big-endian,
    puis chiffré avec AES.

    PARAMETRES :
        seed_pk : clé AES de 16 octets.
        output_length : nombre d'octets à produire.

    RETOUR :
        Une suite d'octets de longueur output_length.

    REMARQUE :
    La convention exacte du compteur doit être vérifiée
    avec la spécification et les vecteurs officiels MAYO.
    """

    if len(seed_pk) != SEED_PK_BYTES:
        raise ValueError("seed_pk doit contenir 16 octets")

    if output_length < 0:
        raise ValueError("Longueur de sortie invalide")

    aes = AES.new(seed_pk, AES.MODE_ECB)

    output = bytearray()
    counter = 0

    while len(output) < output_length:

        counter_block = counter.to_bytes(
            16,
            byteorder="big"
        )

        encrypted_block = aes.encrypt(counter_block)

        output.extend(encrypted_block)

        counter += 1

    return bytes(output[:output_length])


# ============================================================
# 8. DECODAGE DES MATRICES P1 ET P2
# ============================================================

def decode_nibbles(data):
    """
    TITRE : Extraction des éléments de F16.

    DESCRIPTION :
    Transforme une suite d'octets en une liste d'éléments
    de F16 en séparant les deux nibbles de chaque octet.

    PARAMETRE :
        data : suite d'octets à décoder.

    RETOUR :
        Liste des éléments de F16.
    """

    elements = []

    for byte in data:

        low = byte & 0x0F
        high = (byte >> 4) & 0x0F

        elements.append(low)
        elements.append(high)

    return elements


def decode_matrices(data, rows, cols, triangular=False):
    """
    TITRE : Décodage d'un ensemble de matrices.

    DESCRIPTION :
    Décode les éléments de F16 et les répartit dans M matrices.

    Le décodage est entrelacé : pour chaque position (i, j),
    on récupère successivement les coefficients des M matrices.

    Si triangular vaut True, seuls les éléments du triangle
    supérieur sont décodés.

    PARAMETRES :
        data : données binaires à décoder.
        rows : nombre de lignes de chaque matrice.
        cols : nombre de colonnes de chaque matrice.
        triangular : indique si les matrices sont triangulaires.

    RETOUR :
        Une liste de M matrices.
    """

    elements = decode_nibbles(data)

    if triangular:
        elements_per_matrix = rows * (rows + 1) // 2
    else:
        elements_per_matrix = rows * cols

    expected = M * elements_per_matrix

    if len(data) != (expected + 1) // 2:
        raise ValueError("Taille incorrecte des donnees")

    matrices = [
        zero_matrix(rows, cols)
        for _ in range(M)
    ]

    position = 0

    for i in range(rows):
        for j in range(cols):

            if triangular and j < i:
                continue

            for k in range(M):
                matrices[k][i][j] = elements[position]
                position += 1

    return matrices


def decode_P1(data):
    """
    TITRE : Décodage des matrices P1.

    DESCRIPTION :
    Décode les M matrices P1 de dimensions V x V.
    Chaque matrice est triangulaire supérieure.

    PARAMETRE :
        data : représentation binaire des matrices P1.

    RETOUR :
        Liste de M matrices triangulaires supérieures.
    """

    return decode_matrices(
        data,
        V,
        V,
        triangular=True
    )


def decode_P2(data):
    """
    TITRE : Décodage des matrices P2.

    DESCRIPTION :
    Décode les M matrices P2 de dimensions V x O_DIM.

    PARAMETRE :
        data : représentation binaire des matrices P2.

    RETOUR :
        Liste de M matrices de dimensions 80 x 8.
    """

    return decode_matrices(
        data,
        V,
        O_DIM,
        triangular=False
    )


# ============================================================
# 9. GENERATION DES MATRICES P1 ET P2
# ============================================================

def generate_P1_P2(seed_pk):
    """
    TITRE : Génération des matrices P1 et P2.

    DESCRIPTION :
    Détermine la quantité d'octets nécessaire, effectue
    l'expansion AES, sépare les données de P1 et P2,
    puis décode les deux ensembles de matrices.

    PARAMETRE :
        seed_pk : graine publique utilisée par AES.

    RETOUR :
        P1 : liste des M matrices triangulaires V x V.
        P2 : liste des M matrices V x O_DIM.
    """

    p1_elements = M * (V * (V + 1) // 2)
    p2_elements = M * V * O_DIM

    p1_bytes = p1_elements // 2
    p2_bytes = p2_elements // 2

    total_bytes = p1_bytes + p2_bytes

    expanded_data = aes_ctr_expand(
        seed_pk,
        total_bytes
    )

    encoded_P1 = expanded_data[:p1_bytes]
    encoded_P2 = expanded_data[p1_bytes:]

    P1 = decode_P1(encoded_P1)
    P2 = decode_P2(encoded_P2)

    return P1, P2


# ============================================================
# 10. CALCUL DES MATRICES P3
# ============================================================

def compute_P3(O, P1, P2):
    """
    TITRE : Calcul des matrices P3.

    DESCRIPTION :
    Calcule les M matrices P3 à partir de O, P1 et P2.

    Pour chaque indice i, effectue :

        P3[i] = Upper(O^T * P1[i] * O + O^T * P2[i])

    L'addition remplace la soustraction car le corps F16
    est de caractéristique 2.

    PARAMETRES :
        O  : matrice secrète de dimensions V x O_DIM.
        P1 : liste des matrices de dimensions V x V.
        P2 : liste des matrices de dimensions V x O_DIM.

    RETOUR :
        Liste des M matrices P3 de dimensions O_DIM x O_DIM.
    """

    if len(P1) != M or len(P2) != M:
        raise ValueError("Nombre incorrect de matrices P1 ou P2")

    P3 = []

    O_T = matrix_transpose(O)

    for i in range(M):

        # Calcul de O^T * P1[i] * O
        temp = matrix_multiply(O_T, P1[i])
        A = matrix_multiply(temp, O)

        # Calcul de O^T * P2[i]
        B = matrix_multiply(O_T, P2[i])

        # Addition dans F16
        C = matrix_add(A, B)

        # Extraction du triangle supérieur
        P3_i = upper_triangle(C)

        P3.append(P3_i)

    return P3


# ============================================================
# 11. ENCODAGE DES MATRICES P3
# ============================================================

def encode_nibbles(elements):
    """
    TITRE : Encodage des éléments de F16 en octets.

    DESCRIPTION :
    Regroupe deux éléments de F16 dans un octet :
        - le premier dans le nibble de poids faible ;
        - le second dans le nibble de poids fort.

    PARAMETRE :
        elements : liste d'éléments de F16.

    RETOUR :
        Suite d'octets encodée.
    """

    encoded = bytearray()

    for i in range(0, len(elements), 2):

        low = elements[i]

        if not 0 <= low < Q:
            raise ValueError("Element invalide dans F16")

        if i + 1 < len(elements):
            high = elements[i + 1]

            if not 0 <= high < Q:
                raise ValueError("Element invalide dans F16")
        else:
            high = 0

        byte = low | (high << 4)

        encoded.append(byte)

    return bytes(encoded)


def encode_P3(P3):
    """
    TITRE : Encodage des matrices P3.

    DESCRIPTION :
    Récupère les coefficients du triangle supérieur des M
    matrices P3 selon l'ordre entrelacé, puis les transforme
    en octets.

    PARAMETRE :
        P3 : liste des M matrices de dimensions O_DIM x O_DIM.

    RETOUR :
        Représentation binaire compacte de P3.
    """

    if len(P3) != M:
        raise ValueError("Nombre incorrect de matrices P3")

    elements = []

    for i in range(O_DIM):
        for j in range(i, O_DIM):

            for k in range(M):

                value = P3[k][i][j]

                if not 0 <= value < Q:
                    raise ValueError("Element invalide dans P3")

                elements.append(value)

    return encode_nibbles(elements)


# ============================================================
# 12. GENERATION COMPLETE DES CLES
# ============================================================

def generate_keypair():
    """
    TITRE : Génération de la paire de clés MAYO1.

    DESCRIPTION :
    Exécute les principales étapes de KeyGen :
        1. Génération de seed_sk.
        2. Dérivation de seed_pk et encoded_O.
        3. Décodage de O.
        4. Génération de P1 et P2.
        5. Calcul de P3.
        6. Encodage de P3.
        7. Construction des clés compactes.

    RETOUR :
        cpk : clé publique compacte.
        csk : clé secrète compacte.
    """

    # Génération de la graine secrète
    seed_sk = generate_secret_seed()

    # Dérivation de la graine publique et de O
    seed_pk, encoded_O = derive_key_material(seed_sk)

    # Décodage de O
    O = decode_O(encoded_O)
    # Génération de P1 et P2
    P1, P2 = generate_P1_P2(seed_pk)

    # Calcul de P3
    P3 = compute_P3(O, P1, P2)

    # Encodage de P3
    encoded_P3 = encode_P3(P3)

    # Construction des clés compactes
    cpk = seed_pk + encoded_P3
    csk = seed_sk

    return cpk, csk


# ============================================================
# 13. FONCTIONS DE TEST
# ============================================================

def test_keygen():
    """
    TITRE : Test de la génération des graines.

    DESCRIPTION :
    Vérifie les paramètres MAYO1, génère une graine secrète,
    puis contrôle les tailles des données dérivées.
    """

    print("\n===== TEST GENERATION DES GRAINES =====")

    check_parameters()

    seed_sk = generate_secret_seed()

    seed_pk, encoded_O = derive_key_material(seed_sk)

    print("Taille seed_sk :", len(seed_sk), "octets")
    print("Taille seed_pk :", len(seed_pk), "octets")
    print("Taille O encodee :", len(encoded_O), "octets")

    assert len(seed_sk) == SEED_SK_BYTES
    assert len(seed_pk) == SEED_PK_BYTES

    print("Generation des graines reussie !")


def test_decode_O():
    """
    TITRE : Test du décodage de O.

    DESCRIPTION :
    Vérifie que la matrice O décodée possède les dimensions
    attendues et que ses éléments appartiennent à F16.
    """

    print("\n===== TEST DECODAGE DE O =====")

    seed_sk = generate_secret_seed()
    seed_pk, encoded_O = derive_key_material(seed_sk)

    O = decode_O(encoded_O)

    print("Nombre de lignes :", len(O))
    print("Nombre de colonnes :", len(O[0]))
    print("Premiere ligne :", O[0])

    assert len(O) == V
    assert all(len(row) == O_DIM for row in O)

    assert all(
        0 <= element < Q
        for row in O
        for element in row
    )

    print("Tous les elements appartiennent a F16 !")
    print("Decodage de O reussi !")


def test_generate_P1_P2():
    """
    TITRE : Test de la génération de P1 et P2.

    DESCRIPTION :
    Vérifie le nombre, les dimensions et la structure
    triangulaire supérieure des matrices P1.
    Vérifie également les dimensions de P2.
    """

    print("\n===== TEST GENERATION P1 ET P2 =====")

    seed_sk = generate_secret_seed()
    seed_pk, encoded_O = derive_key_material(seed_sk)

    P1, P2 = generate_P1_P2(seed_pk)

    print("Nombre de matrices P1 :", len(P1))
    print("Dimensions de P1[0] :", len(P1[0]), "x", len(P1[0][0]))

    print("Nombre de matrices P2 :", len(P2))
    print("Dimensions de P2[0] :", len(P2[0]), "x", len(P2[0][0]))

    assert len(P1) == M
    assert all(len(matrix) == V for matrix in P1)
    assert all(len(row) == V for matrix in P1 for row in matrix)

    assert len(P2) == M
    assert all(len(matrix) == V for matrix in P2)
    assert all(
        len(row) == O_DIM
        for matrix in P2
        for row in matrix
    )

    assert all(
        P1[k][r][c] == 0
        for k in range(M)
        for r in range(V)
        for c in range(r)
    )

    print("Les dimensions sont correctes !")
    print("Les matrices P1 sont triangulaires superieures !")


def test_compute_P3():
    """
    TITRE : Test du calcul des matrices P3.

    DESCRIPTION :
    Génère les données nécessaires, calcule P3, puis vérifie
    le nombre de matrices, leurs dimensions, leur structure
    triangulaire supérieure et les valeurs dans F16.
    """

    print("\n===== TEST CALCUL P3 =====")

    seed_sk = generate_secret_seed()
    seed_pk, encoded_O = derive_key_material(seed_sk)

    O = decode_O(encoded_O)

    P1, P2 = generate_P1_P2(seed_pk)

    P3 = compute_P3(O, P1, P2)

    print("Nombre de matrices P3 :", len(P3))
    print(
        "Dimensions de P3[0] :",
        len(P3[0]), "x", len(P3[0][0])
    )

    assert len(P3) == M

    assert all(
        len(matrix) == O_DIM
        for matrix in P3
    )

    assert all(
        len(row) == O_DIM
        for matrix in P3
        for row in matrix
    )

    assert all(
        P3[k][r][c] == 0
        for k in range(M)
        for r in range(O_DIM)
        for c in range(r)
    )

    assert all(
        0 <= element < Q
        for matrix in P3
        for row in matrix
        for element in row
    )

    print("Les 80 matrices P3 ont ete calculees !")
    print("Dimensions correctes : 8 x 8")
    print("Triangles superieurs verifies !")
    print("Tous les elements appartiennent a F16 !")


def test_generate_keypair():
    """
    TITRE : Test de la génération complète des clés.

    DESCRIPTION :
    Exécute KeyGen et vérifie les tailles de la clé publique
    et de la clé secrète pour les paramètres MAYO1.
    """

    print("\n===== TEST GENERATION DES CLES MAYO1 =====")

    cpk, csk = generate_keypair()

    print("Taille de la cle publique :", len(cpk), "octets")
    print("Taille de la cle secrete :", len(csk), "octets")

    assert len(cpk) == 1456
    assert len(csk) == 24

    print("Generation des cles reussie !")

def test_upper_triangle():
    """
    TITRE : Test de la fonction upper_triangle.

    DESCRIPTION :
    Vérifie que upper_triangle respecte la définition de Upper
    de la spécification MAYO :

        Upper(M)[i][j] = M[i][j] + M[j][i]   si i < j
        Upper(M)[i][i] = M[i][i]
        Upper(M)[i][j] = 0                   si i > j

    L'addition dans F16 est le XOR.
    """

    print("\n===== TEST UPPER_TRIANGLE =====")

    # Exemple a la main : 2 XOR 3 = 1
    A = [[1, 2], [3, 4]]
    attendu = [[1, 1], [0, 4]]
    resultat = upper_triangle(A)

    print("Entree   :", A)
    print("Resultat :", resultat)
    print("Attendu  :", attendu)

    assert resultat == attendu, "upper_triangle doit ajouter M[j][i] a M[i][j]"

    # Matrice aleatoire O_DIM x O_DIM
    B = [
        [secrets.randbelow(Q) for _ in range(O_DIM)]
        for _ in range(O_DIM)
    ]

    U = upper_triangle(B)

    for i in range(O_DIM):
        for j in range(O_DIM):

            if j > i:
                attendu_ij = B[i][j] ^ B[j][i]
            elif j == i:
                attendu_ij = B[i][i]
            else:
                attendu_ij = 0

            assert U[i][j] == attendu_ij, (
                f"Erreur a la position ({i}, {j})"
            )

    print("Upper conforme a la specification MAYO !")


def test_trapdoor_P3():
    """
    TITRE : Test de la propriété de trappe de P3.

    DESCRIPTION :
    Pour tout vecteur t de F16^O_DIM, le vecteur x = (O*t, t)
    appartient à l'espace Oil. La forme quadratique de chaque
    P_i doit s'annuler sur x :

        v^T P1[i] v + v^T P2[i] t + t^T P3[i] t = 0    avec v = O*t

    Ce test est indépendant de la fonction Upper : il vérifie
    directement que P3 est cohérent avec O, P1 et P2.
    """

    print("\n===== TEST PROPRIETE DE TRAPPE (P3) =====")

    seed_sk = generate_secret_seed()
    seed_pk, encoded_O = derive_key_material(seed_sk)

    O = decode_O(encoded_O)
    P1, P2 = generate_P1_P2(seed_pk)
    P3 = compute_P3(O, P1, P2)

    nombre_vecteurs = 3

    for n_test in range(nombre_vecteurs):

        # Vecteur colonne t aleatoire de dimension O_DIM
        t = [[secrets.randbelow(Q)] for _ in range(O_DIM)]

        v = matrix_multiply(O, t)

        v_T = matrix_transpose(v)
        t_T = matrix_transpose(t)

        for i in range(M):

            a = matrix_multiply(v_T, matrix_multiply(P1[i], v))[0][0]
            b = matrix_multiply(v_T, matrix_multiply(P2[i], t))[0][0]
            c = matrix_multiply(t_T, matrix_multiply(P3[i], t))[0][0]

            assert a ^ b ^ c == 0, (
                f"La forme quadratique ne s'annule pas "
                f"(vecteur {n_test}, matrice {i})"
            )

    print("La forme quadratique s'annule sur l'espace Oil !")
    print(f"{nombre_vecteurs} vecteurs x {M} matrices verifies.")

# ============================================================
# 14. POINT D'ENTREE DU PROGRAMME
# ============================================================

if __name__ == "__main__":

    test_keygen()

    test_decode_O()

    test_generate_P1_P2()

    test_compute_P3()

    test_generate_keypair()

    test_upper_triangle()

    test_trapdoor_P3()