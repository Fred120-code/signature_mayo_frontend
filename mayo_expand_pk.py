"""
============================================================
                    MAYO1 - PUBLIC KEY EXPANSION
============================================================

Ce module implémente l'expansion de la clé publique compacte (cpk)
en une clé publique élargie (epk) pour le schéma MAYO1, conformément
à l'Algorithme 6 (MAYO.ExpandPK) de la spécification officielle.

Etapes :
    1. Extraction de seed_pk depuis cpk.
    2. Expansion de seed_pk via AES-128-CTR pour générer les octets de P1 et P2.
    3. Récupération de la partie encodée de P3 depuis cpk.
    4. Construction et retour de la clé publique élargie (epk).

Auteurs : Groupe de projet Cryptographie ENSPY (2026-2027)
"""

# ============================================================
# 1. IMPORTATION DES BIBLIOTHEQUES ET MODULES LOCAUX
# ============================================================

from mayo_keygen import (
    Q, N, M, O_DIM, V, SEED_PK_BYTES,
    aes_ctr_expand,
    decode_P1,
    decode_P2,
    decode_nibbles,
    zero_matrix
)


# ============================================================
# 2. EXPANSION COMPLETE DE LA CLE PUBLIQUE (ALGORITHME 6)
# ============================================================

def expand_public_key(cpk):
    """
    TITRE : Expansion de la clé publique compacte (MAYO.ExpandPK).

    DESCRIPTION :
    Exécute l'Algorithme 6 de MAYO :
        1. Extrait seed_pk depuis cpk.
        2. Exécute AES-128-CTR sur seed_pk pour obtenir les octets de P1 et P2.
        3. Concatène le résultat avec la portion encoded_P3 extraite de cpk.

    PARAMETRE :
        cpk : clé publique compacte (seed_pk + encoded_P3).

    RETOUR :
        epk : clé publique élargie binaire.
    """
    if len(cpk) < SEED_PK_BYTES:
        raise ValueError("Taille invalide de cpk (seed_pk attendue)")

    seed_pk = cpk[:SEED_PK_BYTES]
    encoded_P3 = cpk[SEED_PK_BYTES:]

    # Calcul des tailles d'octets pour P1 et P2
    p1_bytes = (M * V * (V + 1) // 2) // 2
    p2_bytes = (M * V * O_DIM) // 2
    total_p_bytes = p1_bytes + p2_bytes

    # Expansion AES-128-CTR (Algorithme 6, ligne 5)
    expanded_P = aes_ctr_expand(seed_pk, total_p_bytes)

    # Assemblage : epk = AES_CTR(seed_pk) || encoded_P3
    epk = expanded_P + encoded_P3

    return epk


def parse_epk(epk):
    """
    TITRE : Découpage et décodage de la clé publique élargie (epk).

    DESCRIPTION :
    Utilisé par le module de vérification pour extraire directement
    les listes de matrices (P1, P2, P3) à partir de la clé élargie epk.

    PARAMETRE :
        epk : clé publique élargie sous forme d'octets.

    RETOUR :
        P1 : liste des M matrices V x V triangulaires supérieures.
        P2 : liste des M matrices V x O_DIM.
        P3 : liste des M matrices O_DIM x O_DIM triangulaires supérieures.
    """
    p1_bytes = (M * V * (V + 1) // 2) // 2
    p2_bytes = (M * V * O_DIM) // 2
    total_p_bytes = p1_bytes + p2_bytes

    if len(epk) < total_p_bytes:
        raise ValueError("Taille incorrecte de epk")

    encoded_P1 = epk[:p1_bytes]
    encoded_P2 = epk[p1_bytes : total_p_bytes]
    encoded_P3 = epk[total_p_bytes:]

    P1 = decode_P1(encoded_P1)
    P2 = decode_P2(encoded_P2)

    # Décodage de P3
    elements_P3 = decode_nibbles(encoded_P3)
    P3 = [zero_matrix(O_DIM, O_DIM) for _ in range(M)]
    
    pos = 0
    for i in range(O_DIM):
        for j in range(i, O_DIM):
            for k in range(M):
                P3[k][i][j] = elements_P3[pos]
                pos += 1

    return P1, P2, P3


# ============================================================
# 3. FONCTIONS DE TEST UNITAIRES
# ============================================================

# ============================================================
# 3. FONCTIONS DE TEST UNITAIRES
# ============================================================

def test_expand_public_key():
    """
    TITRE : Test d'expansion globale de la clé publique (MAYO.ExpandPK).

    DESCRIPTION :
    Génère une paire de clés, extrait cpk, exécute ExpandPK,
    affiche la clé élargie epk, puis vérifie le bon découpage et décodage via parse_epk.
    """
    print("\n===== TEST EXPAND_PUBLIC_KEY (ALGORITHME 6) =====")

    from mayo_keygen import generate_keypair

    cpk, csk = generate_keypair()
    epk = expand_public_key(cpk)

    print("Taille de cpk (clé compacte) :", len(cpk), "octets")
    print("Taille de epk (clé élargie)  :", len(epk), "octets")
    
    # Affichage de la clé publique élargie (epk) en format hexadécimal (tronqué ou complet)
    # print(f"Clé publique élargie epk (Hex) : {epk.hex()}")

    P1, P2, P3 = parse_epk(epk)

    assert len(P1) == M
    assert len(P2) == M
    assert len(P3) == M

    print("Expansion de la clé publique entièrement validée !")

# ============================================================
# 4. POINT D'ENTREE DU PROGRAMME
# ============================================================

if __name__ == "__main__":
    test_expand_public_key()