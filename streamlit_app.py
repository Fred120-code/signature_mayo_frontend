"""Streamlit dashboard for the local educational MAYO-like project."""

import hashlib
from time import perf_counter

import streamlit as st

from keys.expand_public import expand_public_key
from keys.expand_secret import expand_secret_key
from keys.keygen import generate_keypair
from keys.parameters import (
    DIGEST_BYTES,
    K,
    M,
    N,
    O_DIM,
    SALT_BYTES,
    SEED_PK_BYTES,
    SEED_SK_BYTES,
    V,
)
from scheme.sign import sign
from scheme.trace import SignTrace, SignTraceError

PAGES = (
    "Accueil",
    "Génération des clés",
    "Signature",
    "Vérification",
    "Analyse et performances",
)
KEYPAIR_STATE_KEY = "generated_keypair"
SIGNATURE_STATE_KEY = "generated_signature"


def profile_sizes() -> dict[str, int]:
    """Return encoded artifact sizes derived from the active local parameters."""
    p1_bytes = M * (V * (V + 1) // 2) // 2
    p2_bytes = M * V * O_DIM // 2
    p3_bytes = M * (O_DIM * (O_DIM + 1) // 2) // 2
    oil_bytes = V * O_DIM // 2
    linking_matrices_bytes = M * V * O_DIM // 2
    signature_vector_bytes = (K * N + 1) // 2

    return {
        "compact_public_key": SEED_PK_BYTES + p3_bytes,
        "compact_secret_key": SEED_SK_BYTES,
        "expanded_public_key": p1_bytes + p2_bytes + p3_bytes,
        "expanded_secret_key": (
            SEED_SK_BYTES
            + oil_bytes
            + p1_bytes
            + linking_matrices_bytes
        ),
        "signature": signature_vector_bytes + SALT_BYTES,
    }


def render_home() -> None:
    """Render the project overview."""
    st.markdown(
        """
        <div class="hero">
            <div class="eyebrow">LABORATOIRE CRYPTOGRAPHIQUE · DÉMONSTRATION</div>
            <h1>Comprendre la signature<br>par les données et les étapes.</h1>
            <p>
                Un espace pédagogique pour explorer le profil MAYO-like local,
                ses paramètres et le parcours de vérification — sans masquer
                la distinction entre démonstration et conformité officielle.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.warning(
        "Projet éducatif non certifié. La conformité aux spécifications "
        "officielles et aux vecteurs de test n’est pas attestée."
    )

    st.subheader("Le parcours cryptographique")
    columns = st.columns(4)
    for column, number, title, caption in zip(
        columns,
        ("01", "02", "03", "04"),
        ("Clés", "Message", "Signature", "Vérification"),
        (
            "Générer et étendre les clés",
            "Choisir les données à signer",
            "Résoudre le système du schéma",
            "Comparer le résultat à la cible",
        ),
    ):
        with column:
            st.markdown(
                f"""
                <div class="step-card">
                    <span class="step-number">{number}</span>
                    <h3>{title}</h3>
                    <p>{caption}</p>
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.markdown(
        """
        <div class="note-card">
            <strong>Une interface en construction</strong>
            <p>
                La génération des clés et la signature utilisent le moteur
                réel. La vue détaillée de Verify reste en développement;
                aucun résultat cryptographique n’est simulé.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_key_generation() -> None:
    """Generate and retain a real key pair only after explicit user action."""
    st.title("Génération des clés")
    st.caption(
        "Création et expansion d’une paire avec les fonctions cryptographiques "
        "du profil local."
    )
    st.info(
        "Les clés secrètes sont conservées uniquement dans l’état de cette "
        "session Streamlit. Elles ne sont jamais affichées."
    )

    st.subheader("Parcours de génération")
    st.markdown(
        """
        1. **Génération des graines et construction compacte** — réalisées
           ensemble par `generate_keypair()`.
        2. **Expansion de la clé publique** — `expand_public_key(cpk)`.
        3. **Expansion de la clé secrète** — `expand_secret_key(csk)`.
        4. **Paire disponible** — les clés étendues restent en session pour
           les prochaines étapes pédagogiques.
        """
    )

    if st.button("Générer une paire de clés", type="primary"):
        compact_public_key, compact_secret_key = generate_keypair()
        expanded_public_key = expand_public_key(compact_public_key)
        expanded_secret_key = expand_secret_key(compact_secret_key)
        public_fingerprint = hashlib.sha256(compact_public_key).hexdigest()[:16]

        st.session_state[KEYPAIR_STATE_KEY] = {
            "compact_public_key": compact_public_key,
            "compact_secret_key": compact_secret_key,
            "expanded_public_key": expanded_public_key,
            "expanded_secret_key": expanded_secret_key,
            "public_fingerprint": public_fingerprint,
        }

    keypair = st.session_state.get(KEYPAIR_STATE_KEY)
    if keypair is None:
        st.caption(
            "Aucune paire n’a encore été générée dans cette session. "
            "Utilisez le bouton ci-dessus pour commencer."
        )
        return

    st.success("Paire générée et clés étendues avec succès.")
    st.markdown(
        f"**Empreinte publique (SHA-256, préfixe)**  \n"
        f"`{keypair['public_fingerprint']}`"
    )

    metrics = st.columns(2)
    metrics[0].metric(
        "Clé publique compacte",
        f"{len(keypair['compact_public_key']):,} octets".replace(",", " "),
    )
    metrics[1].metric(
        "Clé secrète compacte",
        f"{len(keypair['compact_secret_key']):,} octets".replace(",", " "),
    )
    metrics = st.columns(2)
    metrics[0].metric(
        "Clé publique étendue",
        f"{len(keypair['expanded_public_key']):,} octets".replace(",", " "),
    )
    metrics[1].metric(
        "Clé secrète étendue",
        f"{len(keypair['expanded_secret_key']):,} octets".replace(",", " "),
    )

    with st.expander("Paramètres utilisés"):
        st.dataframe(
            [
                {"Paramètre": "Q", "Valeur": "16"},
                {"Paramètre": "N", "Valeur": str(N)},
                {"Paramètre": "M", "Valeur": str(M)},
                {"Paramètre": "K", "Valeur": str(K)},
                {"Paramètre": "V", "Valeur": str(V)},
                {"Paramètre": "O_DIM", "Valeur": str(O_DIM)},
                {
                    "Paramètre": "Graine secrète",
                    "Valeur": f"{SEED_SK_BYTES} octets (non affichée)",
                },
                {
                    "Paramètre": "Graine publique",
                    "Valeur": f"{SEED_PK_BYTES} octets",
                },
            ],
            hide_index=True,
            width="stretch",
        )


def render_signature_trace(trace: SignTrace) -> None:
    """Render actual Sign events in order without revealing value previews."""
    st.subheader("Étapes réellement exécutées")
    labels = {
        "secret_key_prepared": "Préparation de la clé secrète étendue",
        "message_digest": "Calcul du condensat du message",
        "salt_generated": "Génération du sel",
        "target_and_lambda_derived": "Dérivation de t et Lambda",
        "emulsifier_loaded": "Chargement de la table E",
        "attempt_values_generated": "Génération des valeurs de tentative",
        "intermediate_matrices_built": "Construction de M_matrices et W",
        "linear_system_built": "Construction du système linéaire",
        "sample_solution": "Résolution du système",
        "signature_encoded": "Encodage de la signature finale",
        "signing_failed": "Limite de tentatives atteinte",
    }

    for step in trace.steps:
        title = labels.get(step.name, "Étape de signature")
        if step.attempt is not None:
            title = f"Tentative {step.attempt} — {title}"
        with st.expander(f"{step.number}. {title}", expanded=False):
            st.write(step.description)
            st.caption(f"Résultat : {step.status}")

            safe_data = {
                key: value
                for key, value in step.data.items()
                if key not in {
                    "digest_preview_hex",
                    "salt_hex",
                    "t_preview",
                    "lambda_preview",
                }
            }
            if safe_data:
                st.json(safe_data)
            if step.dimensions:
                st.write("Dimensions")
                st.json(
                    {
                        name: list(shape)
                        for name, shape in step.dimensions.items()
                    }
                )


def render_signature() -> None:
    """Sign the submitted message with the current session's real secret key."""
    st.title("Signature")
    st.caption(
        "Le message est signé par le moteur local avec la clé secrète étendue "
        "de la paire conservée dans cette session."
    )

    keypair = st.session_state.get(KEYPAIR_STATE_KEY)
    if keypair is None:
        st.warning(
            "Aucune paire de clés n’est disponible. Générez d’abord une paire "
            "dans la section « Génération des clés »."
        )
        return

    st.text_area(
        "Message à signer",
        key="signature_message_input",
        help="Le moteur accepte aussi un message vide.",
    )
    if st.button("Signer le message", type="primary"):
        message = st.session_state["signature_message_input"]
        started = perf_counter()
        try:
            signature, trace = sign(
                keypair["expanded_secret_key"],
                message,
                return_trace=True,
            )
        except SignTraceError as error:
            elapsed = perf_counter() - started
            st.session_state[SIGNATURE_STATE_KEY] = {
                "message": message,
                "signature": None,
                "trace": error.trace,
                "elapsed_seconds": elapsed,
                "error_kind": "retry_limit",
            }
        except ValueError:
            elapsed = perf_counter() - started
            st.session_state[SIGNATURE_STATE_KEY] = {
                "message": message,
                "signature": None,
                "trace": None,
                "elapsed_seconds": elapsed,
                "error_kind": "invalid_key_or_input",
            }
        except Exception:
            elapsed = perf_counter() - started
            st.session_state[SIGNATURE_STATE_KEY] = {
                "message": message,
                "signature": None,
                "trace": None,
                "elapsed_seconds": elapsed,
                "error_kind": "internal_error",
            }
        else:
            elapsed = perf_counter() - started
            st.session_state[SIGNATURE_STATE_KEY] = {
                "message": message,
                "signature": signature,
                "trace": trace,
                "elapsed_seconds": elapsed,
                "error_kind": None,
            }

    result = st.session_state.get(SIGNATURE_STATE_KEY)
    if result is None:
        st.caption(
            "Saisissez un message puis lancez la signature. Aucun calcul "
            "n’est effectué avant votre action."
        )
        return

    st.markdown("#### Message soumis")
    st.code(result["message"] if result["message"] else "(message vide)")
    st.metric("Temps réel de signature", f"{result['elapsed_seconds']:.3f} s")

    if result["error_kind"] == "retry_limit":
        st.error(
            "La signature a échoué : aucune solution n’a été trouvée dans la "
            "limite de tentatives du moteur."
        )
        if result["trace"] is not None:
            render_signature_trace(result["trace"])
        return
    if result["error_kind"] == "invalid_key_or_input":
        st.error(
            "La signature n’a pas pu être calculée : la clé de session ou "
            "l’entrée n’est pas exploitable."
        )
        return
    if result["error_kind"] == "internal_error":
        st.error(
            "Une erreur interne a interrompu la signature. Aucun détail "
            "technique ni secret n’est affiché."
        )
        return

    signature = result["signature"]
    if signature is None:
        st.error("Aucune signature n’a été produite.")
        return

    st.success("Signature produite avec succès.")
    st.metric("Taille de la signature", f"{len(signature)} octets")
    show_hex = st.checkbox(
        "Afficher la signature en hexadécimal",
        value=False,
        key="show_signature_hex",
    )
    if show_hex:
        st.code(signature.hex(), language="text")
    if result["trace"] is not None:
        render_signature_trace(result["trace"])


def render_development_page(title: str, subtitle: str) -> None:
    """Show a clearly marked placeholder for an unconnected workflow."""
    st.title(title)
    st.caption(subtitle)
    st.info("En cours de développement")
    st.markdown(
        """
        Cette vue est réservée à une future visualisation des étapes réelles du
        moteur. Elle n’exécute pas encore cette opération et n’affiche aucun
        résultat cryptographique fictif.
        """
    )


def render_analysis() -> None:
    """Render parameter-derived sizes and optionally measured runtime."""
    st.title("Analyse et performances")
    st.caption(
        "Tailles calculées depuis les paramètres et formats du profil local."
    )

    sizes = profile_sizes()
    first_row = st.columns(3)
    metrics = (
        ("Clé publique compacte", "compact_public_key"),
        ("Clé secrète compacte", "compact_secret_key"),
        ("Signature", "signature"),
    )
    for column, (label, key) in zip(first_row, metrics):
        column.metric(label, f"{sizes[key]:,} octets".replace(",", " "))

    second_row = st.columns(2)
    for column, label, key in zip(
        second_row,
        ("Clé publique étendue", "Clé secrète étendue"),
        ("expanded_public_key", "expanded_secret_key"),
    ):
        column.metric(label, f"{sizes[key]:,} octets".replace(",", " "))

    with st.expander("Paramètres actifs du profil"):
        st.dataframe(
            [
                {"Paramètre": "Q", "Valeur": "16"},
                {"Paramètre": "N", "Valeur": str(N)},
                {"Paramètre": "M", "Valeur": str(M)},
                {"Paramètre": "K", "Valeur": str(K)},
                {"Paramètre": "V", "Valeur": str(V)},
                {"Paramètre": "O_DIM", "Valeur": str(O_DIM)},
                {"Paramètre": "Digest", "Valeur": f"{DIGEST_BYTES} octets"},
                {"Paramètre": "Sel", "Valeur": f"{SALT_BYTES} octets"},
            ],
            hide_index=True,
            width="stretch",
        )

    st.subheader("Mesure d’une exécution réelle")
    st.markdown(
        "Le chronométrage inclut génération et expansion des clés, signature "
        "et vérification. Il n’est déclenché qu’à la demande et les clés ne "
        "sont jamais affichées."
    )
    if st.button("Lancer une démonstration mesurée", type="primary"):
        from app import run_demo

        started = perf_counter()
        result = run_demo("Mesure pédagogique locale")
        elapsed = perf_counter() - started

        st.metric("Durée totale observée", f"{elapsed:.3f} s")
        st.metric("Taille de la signature", f"{len(result.signature)} octets")
        if result.verification_status == 0:
            st.success("La signature générée a été vérifiée avec succès.")
        else:
            st.error("La vérification de la signature générée a échoué.")
        st.caption(
            "Mesure d’une exécution locale unique; ce résultat n’est pas un "
            "benchmark comparatif."
        )


def main() -> None:
    """Run the interactive academic dashboard."""
    st.set_page_config(
        page_title="MAYO1 Lab · Démonstration",
        page_icon="◈",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    st.markdown(
        """
        <style>
        .stApp {
            background:
                radial-gradient(ellipse at 70% -15%, #dfeaf9 0, transparent 38%),
                #f5f7fb;
        }
        [data-testid="stSidebar"] {
            background: #101b2c;
        }
        [data-testid="stSidebar"] * {
            color: #e7edf7;
        }
        .hero {
            padding: 2.4rem 2.6rem;
            border-radius: 24px;
            color: white;
            background: linear-gradient(120deg, #13233b, #245a78);
            margin: 0.6rem 0 1.4rem;
        }
        .hero h1 {
            color: white;
            font-size: clamp(2.2rem, 5vw, 4rem);
            line-height: 1.08;
            letter-spacing: -0.04em;
            margin: 0.8rem 0;
        }
        .hero p {
            color: #d3e2ef;
            max-width: 720px;
            font-size: 1.05rem;
        }
        .eyebrow, .step-number {
            color: #70d6c3;
            font-size: 0.78rem;
            font-weight: 700;
            letter-spacing: 0.12em;
        }
        .step-card, .note-card {
            background: white;
            border: 1px solid #e3e9f1;
            border-radius: 16px;
            padding: 1.2rem;
            min-height: 150px;
            box-shadow: 0 8px 26px rgba(24, 45, 70, 0.05);
        }
        .step-card h3 {
            margin: 0.8rem 0 0.3rem;
            color: #172a43;
        }
        .step-card p, .note-card p {
            color: #607087;
            margin-bottom: 0;
        }
        .note-card {
            margin-top: 1.3rem;
            min-height: 0;
            border-left: 4px solid #42b9a7;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    with st.sidebar:
        st.markdown("## ◈ MAYO1 Lab")
        st.caption("LABORATOIRE PÉDAGOGIQUE")
        selected_page = st.radio(
            "Navigation",
            PAGES,
            label_visibility="collapsed",
        )
        st.divider()
        st.caption("PROFIL LOCAL")
        st.caption(f"GF(16) · N={N} · M={M} · K={K}")

    if selected_page == "Accueil":
        render_home()
    elif selected_page == "Génération des clés":
        render_key_generation()
    elif selected_page == "Signature":
        render_signature()
    elif selected_page == "Vérification":
        render_development_page(
            "Vérification",
            "Suivre l’évaluation de la signature et son résultat.",
        )
    else:
        render_analysis()


if __name__ == "__main__":
    main()
