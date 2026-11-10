from mayo_operation import add, subtract, multiply, inverse

# addition de matrices
def matrix_add(A, B):
    if len(A) != len(B):
        raise ValueError("Les matrices doivent avoir le meme nombre de lignes")

    if any(len(row_a) != len(row_b)
           for row_a, row_b in zip(A, B)):
        raise ValueError("Les matrices doivent avoir les memes dimensions")

    return [
        [add(a, b) for a, b in zip(row_a, row_b)]
        for row_a, row_b in zip(A, B)
    ]


# transposée des matrices
def matrix_transpose(A):
    if not A or not A[0]:
        raise ValueError("La matrice ne doit pas etre vide")

    if any(len(row) != len(A[0]) for row in A):
        raise ValueError("Matrice invalide : lignes de tailles differentes")

    return [
        [A[i][j] for i in range(len(A))]
        for j in range(len(A[0]))
    ]
    

#multiplication de deux matrices
    
def matrix_multiply(A, B):
    if not A or not B or not A[0] or not B[0]:
        raise ValueError("Les matrices ne doivent pas etre vides")

    if any(len(row) != len(A[0]) for row in A):
        raise ValueError("La matrice A est invalide")

    if any(len(row) != len(B[0]) for row in B):
        raise ValueError("La matrice B est invalide")

    rows_A = len(A)
    cols_A = len(A[0])
    rows_B = len(B)
    cols_B = len(B[0])

    if cols_A != rows_B:
        raise ValueError("Dimensions incompatibles")

    C = [[0 for _ in range(cols_B)] for _ in range(rows_A)]

    for i in range(rows_A):
        for j in range(cols_B):
            total = 0

            for k in range(cols_A):
                total = add(
                    total,
                    multiply(A[i][k], B[k][j])
                )

            C[i][j] = total

    return C


# multiplication d'une matrice par un vecteur

def matrix_vector_multiply(A, x):
    if not A or not A[0]:
        raise ValueError("La matrice ne doit pas etre vide")

    if any(len(row) != len(A[0]) for row in A):
        raise ValueError("Matrice invalide")

    if len(A[0]) != len(x):
        raise ValueError("Dimensions incompatibles")

    result = []

    for row in A:
        total = 0

        for a, b in zip(row, x):
            total = add(total, multiply(a, b))

        result.append(total)

    return result


#resoudre un système linéaire Ax=b

def solve_linear_system(A, b):
    """
    Resout A*x = b dans F16.

    Si plusieurs solutions existent, les variables libres
    sont fixees a zero.

    Retourne une solution ou None si le systeme
    est incompatible.
    """

    if not A or not A[0]:
        raise ValueError("La matrice A ne doit pas etre vide")

    rows = len(A)
    cols = len(A[0])

    if any(len(row) != cols for row in A):
        raise ValueError("Matrice A invalide")

    if len(b) != rows:
        raise ValueError("Dimensions incompatibles")

    # Construction de la matrice augmentee [A | b]
    M = [
        list(A[i]) + [b[i]]
        for i in range(rows)
    ]

    pivot_columns = []
    pivot_row = 0

    for col in range(cols):

        # Recherche d'un pivot non nul
        selected = None

        for r in range(pivot_row, rows):
            if M[r][col] != 0:
                selected = r
                break

        if selected is None:
            continue

        # Echange des lignes
        M[pivot_row], M[selected] = M[selected], M[pivot_row]

        # Normalisation du pivot
        pivot = M[pivot_row][col]
        inv_pivot = inverse(pivot)

        M[pivot_row] = [
            multiply(value, inv_pivot)
            for value in M[pivot_row]
        ]

        # Elimination dans toutes les autres lignes
        for r in range(rows):
            if r != pivot_row:
                factor = M[r][col]

                if factor != 0:
                    for j in range(cols + 1):
                        M[r][j] = subtract(
                            M[r][j],
                            multiply(factor, M[pivot_row][j])
                        )

        pivot_columns.append(col)
        pivot_row += 1

        if pivot_row == rows:
            break

    # Verification de la compatibilite
    for r in range(rows):
        if all(M[r][c] == 0 for c in range(cols)):
            if M[r][cols] != 0:
                return None

    # Les variables libres sont fixees a zero
    solution = [0] * cols

    for r, col in enumerate(pivot_columns):
        solution[col] = M[r][cols]

    return solution


# ============================================================
# OPERATIONS SUR LES VECTEURS
# ============================================================

def vector_add(a, b):
    """
    TITRE : Addition de deux vecteurs de F16.

    DESCRIPTION :
    Additionne les deux vecteurs composante par composante
    avec l'addition de F16 (fonction add de mayo_operation).

    PARAMETRES :
        a : premier vecteur.
        b : second vecteur, de même longueur que a.

    RETOUR :
        Le vecteur a + b.
    """

    if len(a) != len(b):
        raise ValueError("Les vecteurs doivent avoir la meme longueur")

    return [add(x, y) for x, y in zip(a, b)]


def vector_subtract(a, b):
    """
    TITRE : Soustraction de deux vecteurs de F16.

    DESCRIPTION :
    Soustrait les deux vecteurs composante par composante
    avec la soustraction de F16 (fonction subtract de mayo_operation).

    PARAMETRES :
        a : premier vecteur.
        b : second vecteur, de même longueur que a.

    RETOUR :
        Le vecteur a - b.
    """

    if len(a) != len(b):
        raise ValueError("Les vecteurs doivent avoir la meme longueur")

    return [subtract(x, y) for x, y in zip(a, b)]


def vector_dot(a, b):
    """
    TITRE : Produit scalaire de deux vecteurs de F16.

    DESCRIPTION :
    Calcule la somme des produits composante par composante,
    avec les opérations add et multiply de F16.

    PARAMETRES :
        a : premier vecteur.
        b : second vecteur, de même longueur que a.

    RETOUR :
        Un élément de F16 : a . b.
    """

    if len(a) != len(b):
        raise ValueError("Les vecteurs doivent avoir la meme longueur")

    total = 0

    for x, y in zip(a, b):
        total = add(total, multiply(x, y))

    return total


# ============================================================
# EVALUATION DE LA FORME QUADRATIQUE (OPTIMISÉE)
# ============================================================

def evaluate_quadratic_form(P1, P2, P3, s_blocks, V, O_DIM, K, M_poly, E):
    """
    TITRE : Évaluation de la clé publique P*(s) = somme_{i<=j} E_ij * u_ij.

    DESCRIPTION :
    Chaque P_a est la matrice triangulaire supérieure par blocs
        P_a = [[P1_a, P2_a], [0, P3_a]]    (taille n x n)
    et, pour s_i = (v_i, x_i) de taille n :
        u_ij[a] = s_i^T P_a s_j                      si i = j
        u_ij[a] = s_i^T P_a s_j + s_j^T P_a s_i      si i != j

    Les matrices P1_a et P3_a sont utilisées TELLES QUE STOCKEES
    (triangulaires supérieures, zéros sous la diagonale) : elles
    ne sont pas symétrisées.

    PARAMETRES :
        P1, P2, P3 : listes des M_poly matrices de la clé publique.
        s_blocks   : liste des K vecteurs s_i de taille V + O_DIM.
        V, O_DIM, K, M_poly : paramètres du schéma.
        E          : table E[i][j] des matrices M_poly x M_poly
                     (voir mayo_emulsifier).

    RETOUR :
        Le vecteur P*(s) de F16^M_poly.
    """

    # W[j][a] = P_a * s_j  (vecteur de taille n)
    W = []

    for sj in s_blocks:
        vj = sj[:V]
        xj = sj[V:]

        Wj = []

        for a in range(M_poly):
            top = vector_add(
                matrix_vector_multiply(P1[a], vj),
                matrix_vector_multiply(P2[a], xj)
            )
            bottom = matrix_vector_multiply(P3[a], xj)

            Wj.append(top + bottom)

        W.append(Wj)

    y = [0] * M_poly

    for i in range(K):
        for j in range(i, K):

            u = []

            for a in range(M_poly):
                val = vector_dot(s_blocks[i], W[j][a])

                if i != j:
                    val = add(val, vector_dot(s_blocks[j], W[i][a]))

                u.append(val)

            y = vector_add(y, matrix_vector_multiply(E[i][j], u))

    return y
