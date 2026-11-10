"""
============================================================
              MAYO1 - MATRICES E_ij (EMULSIFIANT)
============================================================

E_ij est la matrice m x m de la multiplication par z^l dans
F16[z] / (f(z)), où f(z) = z^m + F_TAIL[3] z^3 + F_TAIL[2] z^2
                              + F_TAIL[1] z + F_TAIL[0].

Ces matrices "mélangent" les contributions des k vecteurs de la
signature. Sans elles, tous les blocs de la matrice A du système
linéaire de Sign sont identiques (rang <= o) et le système est
presque jamais résoluble.

Etapes :
    1. Définition de l'indice l associé à chaque paire (i, j).
    2. Calcul des matrices de multiplication par z^l modulo f(z).
    3. Construction de la table E[i][j].

ATTENTION : F_TAIL ci-dessous est une VALEUR DE TEST (queue du
polynôme f78 du round 2, m = 78). Il faut la remplacer par la queue
du polynôme f80 de la spécification round 3 (m = 80) pour obtenir
des signatures conformes. Sign et Verify restent cohérents entre
eux quelle que soit la valeur choisie.

Auteurs : Groupe de projet Cryptographie ENSPY (2026-2027)
"""

# ============================================================
# 1. IMPORTATION DES BIBLIOTHEQUES ET MODULES LOCAUX
# ============================================================

from mayo_operation import add, multiply
from mayo_matrice import matrix_multiply


# ============================================================
# 2. PARAMETRES DU POLYNOME f(z)
# ============================================================

# f(z) = z^m + F_TAIL[3] z^3 + F_TAIL[2] z^2 + F_TAIL[1] z + F_TAIL[0]
F_TAIL = [8, 0, 2, 8]   # f64(z) de la spec MAYO1 (Table 2.1, section 2.1.7.1)

# ============================================================
# 3. INDICE l D'UNE PAIRE (i, j)
# ============================================================

def ell_index(i, j, k):
    """
    TITRE : Indice l de la paire (i, j) avec i <= j.

    DESCRIPTION :
    Reprend l'ordre de parcours de l'algorithme de vérification :
    i croissant et, pour chaque i, j de k - 1 jusqu'à i. Le compteur l
    augmente à chaque paire.

    PARAMETRES :
        i : premier indice.
        j : second indice (j >= i).
        k : paramètre k du schéma.

    RETOUR :
        L'entier l associé à la paire (i, j).
    """

    return sum(k - ii for ii in range(i)) + (k - 1 - j)


# ============================================================
# 4. MATRICES DE MULTIPLICATION PAR z^l
# ============================================================

def z_power_matrices(m, count, tail=F_TAIL):
    """
    TITRE : Matrices de multiplication par z^l modulo f(z).

    DESCRIPTION :
    Construit E_0 (identité), puis E_{l+1} à partir de E_l en
    multipliant par z : décalage des lignes vers le bas, puis
    réduction du coefficient de z^m avec la queue de f. En
    caractéristique 2, z^m est égal à la queue de f.

    PARAMETRES :
        m     : degré de f(z), donc taille des matrices.
        count : nombre de matrices à construire.
        tail  : coefficients [f0, f1, f2, f3] de la queue de f.

    RETOUR :
        La liste [E_0, E_1, ..., E_{count-1}] de matrices m x m.
    """

    identity = [
        [1 if r == c else 0 for c in range(m)]
        for r in range(m)
    ]

    result = [identity]

    for _ in range(count - 1):

        last = result[-1]

        # Ligne du débordement (coefficient de z^m)
        overflow = last[m - 1]

        # Multiplication par z : décalage des lignes vers le bas
        new = [[0] * m] + [row[:] for row in last[:m - 1]]

        # Réduction modulo f(z)
        for r, coeff in enumerate(tail):
            if coeff:
                new[r] = [
                    add(a, multiply(coeff, b))
                    for a, b in zip(new[r], overflow)
                ]

        result.append(new)

    return result


# ============================================================
# 5. TABLE DES MATRICES E_ij
# ============================================================

def build_E(m, k, tail=F_TAIL):
    """
    TITRE : Table E[i][j] des k x k matrices E_ij.

    DESCRIPTION :
    E[i][j] est la multiplication par z^l(i, j) pour i <= j, et
    E[j][i] = E[i][j] (hypothèse de symétrie pour E_i0 avec i > 0).

    PARAMETRES :
        m    : degré de f(z).
        k    : paramètre k du schéma.
        tail : coefficients [f0, f1, f2, f3] de la queue de f.

    RETOUR :
        Une table k x k dont chaque case est une matrice m x m.
    """

    powers = z_power_matrices(m, k * (k + 1) // 2, tail)

    # Initialize with a valid matrix so the table never contains None.
    E = [[powers[0] for _ in range(k)] for _ in range(k)]

    for i in range(k):
        for j in range(i, k):
            E[i][j] = powers[ell_index(i, j, k)]
            E[j][i] = E[i][j]

    return E


# ============================================================
# 6. FONCTIONS DE TEST UNITAIRES
# ============================================================

def test_ell_index():
    """
    TITRE : Test de la fonction ell_index.

    DESCRIPTION :
    Vérifie que les indices l associés aux paires (i, j) avec
    i <= j couvrent exactement 0 .. k(k+1)/2 - 1 sans doublon.
    """

    print("\n===== TEST ELL_INDEX =====")

    k = 10

    indices = [
        ell_index(i, j, k)
        for i in range(k)
        for j in range(i, k)
    ]

    print("Nombre de paires :", len(indices))

    assert sorted(indices) == list(range(k * (k + 1) // 2))
    assert ell_index(0, k - 1, k) == 0

    print("Les indices l couvrent 0 .. 54 sans doublon !")


def test_z_power_matrices():
    """
    TITRE : Test des matrices de multiplication par z^l.

    DESCRIPTION :
    Vérifie que E_0 est l'identité, que E_(l+1) = E_1 * E_l, et que
    z^m modulo f(z) est bien la queue de f (colonne 0 de E_m).
    """

    print("\n===== TEST Z_POWER_MATRICES =====")

    m = 8

    powers = z_power_matrices(m, 12)

    identity = [
        [1 if r == c else 0 for c in range(m)]
        for r in range(m)
    ]

    assert powers[0] == identity

    for l in range(11):
        assert powers[l + 1] == matrix_multiply(powers[1], powers[l])

    colonne_0 = [row[0] for row in powers[m]]

    print("Colonne 0 de E_m :", colonne_0)

    assert colonne_0 == F_TAIL + [0] * (m - len(F_TAIL))

    print("E_(l+1) = E_1 * E_l verifie !")
    print("z^m modulo f(z) = queue de f verifie !")


def test_build_E():
    """
    TITRE : Test de la table E[i][j].

    DESCRIPTION :
    Vérifie les dimensions, la symétrie E[i][j] = E[j][i] et que
    E[0][k-1] (l = 0) est l'identité, d'abord sur un petit exemple
    puis avec les dimensions de MAYO1 (m = 80, k = 10).
    """

    print("\n===== TEST BUILD_E =====")

    m, k = 8, 4

    E = build_E(m, k)

    identity = [
        [1 if r == c else 0 for c in range(m)]
        for r in range(m)
    ]

    assert E[0][k - 1] == identity
    assert all(E[i][j] == E[j][i] for i in range(k) for j in range(k))

    E_mayo = build_E(80, 10)

    print("Dimensions de E[3][7] :", len(E_mayo[3][7]), "x", len(E_mayo[3][7][0]))

    assert len(E_mayo) == 10 and len(E_mayo[0]) == 10
    assert all(
        len(E_mayo[i][j]) == 80 and len(E_mayo[i][j][0]) == 80
        for i in range(10)
        for j in range(10)
    )

    print("Table E correcte !")


# ============================================================
# 7. POINT D'ENTREE DU PROGRAMME
# ============================================================

if __name__ == "__main__":

    test_ell_index()

    test_z_power_matrices()

    test_build_E()
