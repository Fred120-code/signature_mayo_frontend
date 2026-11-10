"""
============================================================
                    MAYO1 - VERIFICATION MODULE
============================================================

Ce module implémente l'algorithme de vérification de signature
(MAYO.Verify) pour le schéma post-quantique MAYO1, conformément
à l'Algorithme 8 de la spécification officielle.

Auteurs : Groupe de projet Cryptographie ENSPY (2026-2027)
"""

# ============================================================
# 1. IMPORTATION DES BIBLIOTHEQUES ET MODULES LOCAUX
# ============================================================

import hashlib

from mayo_operation import add, multiply
from mayo_matrice import (
    evaluate_quadratic_form,
    matrix_vector_multiply,
    vector_add
)
from mayo_keygen import (
    Q, N, M, O_DIM, V, K,
    aes_ctr_expand,
    decode_nibbles
)
from mayo_expand_pk import parse_epk
from mayo_sign import (
    decode_vector,
    derive_t_and_lambda,
    get_E,
    DIGEST_BYTES,
    SALT_BYTES
)


# ============================================================
# 2. ALGORITHME DE VERIFICATION (MAYO.Verify)
# ============================================================

def verify(epk, message, sig):
    """
    TITRE : Vérification d'une signature MAYO (MAYO.Verify - Algorithme 8).

    PARAMETRES :
        epk     : clé publique élargie (bytes).
        message : message original signé (bytes ou str).
        sig     : signature encodée binaire (bytes).

    RETOUR :
        0  si la signature est valide.
        -1 si la signature est invalide.
    """
    if isinstance(message, str):
        message = message.encode('utf-8')

    # 1. Décodage de la clé publique élargie (Lignes 1-7)
    try:
        P1, P2, P3 = parse_epk(epk)
    except Exception:
        return -1

    # 2. Décodage de la signature (Lignes 9-13)
    expected_s_bytes = (K * N + 1) // 2
    if len(sig) != expected_s_bytes + SALT_BYTES:
        return -1

    s_bytes = sig[:expected_s_bytes]
    salt = sig[expected_s_bytes : expected_s_bytes + SALT_BYTES]

    try:
        s_elements = decode_vector(K * N, s_bytes)
    except Exception:
        return -1

    s_blocks = [
        s_elements[i * N : (i + 1) * N]
        for i in range(K)
    ]

    # 3. Hachage du message et dérivation de t et Lambda (Lignes 15-20)
    m_digest = hashlib.shake_256(message).digest(DIGEST_BYTES)

    try:
        t, Lambda = derive_t_and_lambda(m_digest, salt)
    except Exception:
        return -1

    # Matrices E_ij (multiplication par z^l modulo f(z))
    E = get_E()

    # 4. Calcul de P*(s) + L(Lambda, s) (Lignes 22-28)

    # A. Évaluation de la forme quadratique P*(s) via le module mayo_matrice
    y = evaluate_quadratic_form(P1, P2, P3, s_blocks, V, O_DIM, K, M, E)

    # B. Ajout de la contribution linéaire L(Lambda, s) = somme_i E_0i * Lambda * s_i
    for i in range(K):
        linear_val = matrix_vector_multiply(Lambda, s_blocks[i])
        y = vector_add(y, matrix_vector_multiply(E[0][i], linear_val))

    # 5. Comparaison finale y == t (Lignes 30-33)
    print(f"DEBUG -> y calculé : {y[:5]}...")
    print(f"DEBUG -> t attendu : {t[:5]}...")

    if y == t:
        return 0

    return -1

    # return -1


# ============================================================
# 3. FONCTIONS DE TEST UNITAIRES
# ============================================================

def test_verify_module():
    """
    TITRE : Test d'intégration complet du module de vérification.

    DESCRIPTION :
    Vérifie qu'une signature valide est acceptée, puis qu'elle est
    rejetée si le message est modifié, si la signature est modifiée
    ou si la clé publique est celle d'une autre paire de clés.
    """
    print("\n===== TEST MODULE DE VERIFICATION (MAYO.Verify) =====")

    from mayo_keygen import generate_keypair
    from mayo_expand_sk import expand_secret_key
    from mayo_expand_pk import expand_public_key
    from mayo_sign import sign

    print("1. Génération des clés...")
    cpk, csk = generate_keypair()
    esk = expand_secret_key(csk)
    epk = expand_public_key(cpk)

    print("2. Signature d'un message test...")
    message = "Test de vérification de signature MAYO1 - ENSPY 2026"
    sig = sign(esk, message)

    print("3. Vérification de la signature...")
    result = verify(epk, message, sig)
    print(f"Résultat de la vérification : {result}")

    assert result == 0, "La signature valide aurait dû être acceptée !"

    print("4. Message modifié...")
    assert verify(epk, message + "!", sig) == -1, "Message modifié accepté !"

    print("5. Signature modifiée...")
    bad_sig = bytearray(sig)
    bad_sig[10] = (bad_sig[10] + 1) % 256
    assert verify(epk, message, bytes(bad_sig)) == -1, "Signature modifiée acceptée !"

    print("6. Mauvaise clé publique...")
    cpk_autre, csk_autre = generate_keypair()
    epk_autre = expand_public_key(cpk_autre)
    assert verify(epk_autre, message, sig) == -1, "Mauvaise clé acceptée !"

    print("Test de vérification validé avec succès !")


# ============================================================
# 4. POINT D'ENTREE DU PROGRAMME
# ============================================================

if __name__ == "__main__":
    test_verify_module()
