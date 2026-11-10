"""Tests for the Streamlit dashboard structure and navigation."""

import hashlib
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from keys.parameters import K, M, N, O_DIM, V
from scheme.trace import SignTrace, SignTraceError
from streamlit_app import KEYPAIR_STATE_KEY, profile_sizes

APP_PATH = Path(__file__).resolve().parents[1] / "streamlit_app.py"


def test_dashboard_loads_home_without_running_crypto() -> None:
    """The home view loads with no cryptographic run or runtime measurement."""
    app = AppTest.from_file(str(APP_PATH)).run()

    assert not app.exception
    assert app.title == []
    assert any("Comprendre la signature" in item.value for item in app.markdown)
    assert not any("Durée totale observée" in item.label for item in app.metric)
    assert not app.button


def test_navigation_opens_development_placeholders() -> None:
    """The unconnected workflow pages are reachable and clearly marked."""
    app = AppTest.from_file(str(APP_PATH)).run()

    for page in ("Vérification",):
        app.sidebar.radio[0].set_value(page)
        app.run()
        assert not app.exception
        assert any(item.value == page for item in app.title)
        assert any(
            "En cours de développement" in item.value for item in app.info
        )
        assert any(
            "n’affiche aucun résultat cryptographique fictif"
            in " ".join(item.value.split())
            for item in app.markdown
        )


def test_signature_page_requires_keypair() -> None:
    """The signature view explains when no session key pair is available."""
    app = AppTest.from_file(str(APP_PATH)).run()
    app.sidebar.radio[0].set_value("Signature")
    app.run()

    assert not app.exception
    assert any(item.value == "Signature" for item in app.title)
    assert any("Aucune paire de clés" in item.value for item in app.warning)
    assert not app.text_area
    assert not app.button


def test_key_generation_creates_and_retains_real_pair_without_exposure() -> None:
    """KeyGen runs on button click, persists in session, and keeps secrets hidden."""
    app = AppTest.from_file(str(APP_PATH)).run()
    app.sidebar.radio[0].set_value("Génération des clés")
    app.run()

    assert not app.exception
    assert not app.metric
    assert len(app.button) == 1
    assert app.button[0].label == "Générer une paire de clés"
    assert not app.session_state.get(KEYPAIR_STATE_KEY)

    app.button[0].click()
    app.run(timeout=120)

    assert not app.exception
    assert any("Paire générée" in item.value for item in app.success)
    keypair = app.session_state[KEYPAIR_STATE_KEY]
    sizes = profile_sizes()
    assert len(keypair["compact_public_key"]) == sizes["compact_public_key"]
    assert len(keypair["compact_secret_key"]) == sizes["compact_secret_key"]
    assert len(keypair["expanded_public_key"]) == sizes["expanded_public_key"]
    assert len(keypair["expanded_secret_key"]) == sizes["expanded_secret_key"]
    assert keypair["public_fingerprint"] == hashlib.sha256(
        keypair["compact_public_key"]
    ).hexdigest()[:16]

    displayed_values = [
        item.value
        for item in (
        list(app.markdown)
        + list(app.caption)
        + list(app.success)
        + list(app.info)
        )
    ]
    displayed_values.extend(
        f"{metric.label} {metric.value}" for metric in app.metric
    )
    rendered = "\n".join(displayed_values)
    for key in (
        "compact_secret_key",
        "expanded_secret_key",
    ):
        secret = keypair[key]
        assert secret.hex() not in rendered
        assert repr(secret) not in rendered

    original_public = keypair["compact_public_key"]
    original_secret = keypair["expanded_secret_key"]
    original_fingerprint = keypair["public_fingerprint"]
    app.run()
    retained_pair = app.session_state[KEYPAIR_STATE_KEY]
    assert retained_pair["compact_public_key"] == original_public
    assert retained_pair["expanded_secret_key"] == original_secret
    assert retained_pair["public_fingerprint"] == original_fingerprint


def test_signature_uses_session_key_and_retains_real_result() -> None:
    """The UI produces a verifiable signature and keeps it across reruns."""
    from scheme.verify import verify

    app = AppTest.from_file(str(APP_PATH)).run()
    app.sidebar.radio[0].set_value("Génération des clés")
    app.run()
    app.button[0].click()
    app.run(timeout=120)
    keypair = app.session_state[KEYPAIR_STATE_KEY]

    app.sidebar.radio[0].set_value("Signature")
    app.run()
    message = "MAYO Lab signature test"
    app.text_area[0].set_value(message)
    app.run()
    assert app.button[0].label == "Signer le message"

    app.button[0].click()
    app.run(timeout=120)

    assert not app.exception
    assert any("Signature produite avec succès" in item.value for item in app.success)
    signature_result = app.session_state["generated_signature"]
    signature = signature_result["signature"]
    assert signature_result["message"] == message
    assert signature_result["error_kind"] is None
    assert len(signature) == 321
    assert verify(keypair["expanded_public_key"], message, signature) == 0
    assert any(
        metric.label == "Taille de la signature"
        and metric.value == "321 octets"
        for metric in app.metric
    )
    assert any(
        metric.label == "Temps réel de signature"
        for metric in app.metric
    )
    assert not app.checkbox[0].value
    assert not any(signature.hex() in item.value for item in app.code)

    trace_names = [step.name for step in signature_result["trace"].steps]
    assert trace_names[:5] == [
        "secret_key_prepared",
        "message_digest",
        "salt_generated",
        "target_and_lambda_derived",
        "emulsifier_loaded",
    ]
    assert trace_names[-1] == "signature_encoded"
    rendered = "\n".join(
        item.value
        for item in list(app.markdown)
        + list(app.caption)
        + list(app.code)
        + list(app.success)
        + list(app.info)
    )
    assert signature.hex() not in rendered
    assert keypair["expanded_secret_key"].hex() not in rendered
    for secret in (
        keypair["compact_secret_key"],
        keypair["expanded_secret_key"],
    ):
        assert secret.hex() not in rendered
        assert repr(secret) not in rendered

    original_signature = signature
    app.run(timeout=120)
    retained_result = app.session_state["generated_signature"]
    assert retained_result["signature"] == original_signature
    assert retained_result["message"] == message
    assert verify(
        keypair["expanded_public_key"],
        message,
        retained_result["signature"],
    ) == 0

    app.checkbox[0].set_value(True)
    app.run(timeout=120)
    assert any(signature.hex() in item.value for item in app.code)


def test_empty_message_is_signed_by_real_engine() -> None:
    """An empty message follows the signing implementation's valid path."""
    from scheme.verify import verify

    app = AppTest.from_file(str(APP_PATH)).run()
    app.sidebar.radio[0].set_value("Génération des clés")
    app.run()
    app.button[0].click()
    app.run(timeout=120)
    keypair = app.session_state[KEYPAIR_STATE_KEY]

    app.sidebar.radio[0].set_value("Signature")
    app.run()
    app.text_area[0].set_value("")
    app.run()
    app.button[0].click()
    app.run(timeout=120)

    result = app.session_state["generated_signature"]
    assert result["message"] == ""
    assert result["error_kind"] is None
    assert len(result["signature"]) == 321
    assert verify(keypair["expanded_public_key"], "", result["signature"]) == 0
    assert any("Signature produite avec succès" in item.value for item in app.success)


def test_signing_failure_is_reported_without_raw_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The retry limit keeps its trace and reports a clear UI failure."""
    import scheme.sign as sign_module

    def fail_sign(*_: object, **kwargs: object) -> tuple[bytes, SignTrace]:
        assert kwargs == {"return_trace": True}
        trace = SignTrace()
        trace.add_step(
            "signing_failed",
            "Aucune tentative n'a abouti.",
            data={"attempts": 256},
            status="failed",
        )
        raise SignTraceError("internal detail", trace)

    monkeypatch.setattr(sign_module, "sign", fail_sign)
    app = AppTest.from_file(str(APP_PATH)).run()
    app.session_state[KEYPAIR_STATE_KEY] = {
        "expanded_secret_key": b"test-only-secret",
    }
    app.sidebar.radio[0].set_value("Signature")
    app.run()
    app.text_area[0].set_value("failure case")
    app.run()
    app.button[0].click()
    app.run(timeout=120)

    assert app.session_state["generated_signature"]["error_kind"] == "retry_limit"
    assert any("aucune solution" in item.value for item in app.error)
    assert "internal detail" not in "\n".join(item.value for item in app.error)
    assert app.session_state["generated_signature"]["signature"] is None


@pytest.mark.parametrize(
    ("exception", "expected_kind", "message_fragment"),
    [
        (ValueError("invalid key"), "invalid_key_or_input", "clé de session"),
        (RuntimeError("private internal details"), "internal_error", "erreur interne"),
    ],
)
def test_unexpected_signing_errors_are_reported_safely(
    monkeypatch: pytest.MonkeyPatch,
    exception: Exception,
    expected_kind: str,
    message_fragment: str,
) -> None:
    """Key/input and internal failures are shown without exception contents."""
    import scheme.sign as sign_module

    def fail_sign(*_: object, **kwargs: object) -> None:
        assert kwargs == {"return_trace": True}
        raise exception

    monkeypatch.setattr(sign_module, "sign", fail_sign)
    app = AppTest.from_file(str(APP_PATH)).run()
    app.session_state[KEYPAIR_STATE_KEY] = {
        "expanded_secret_key": b"test-only-secret",
    }
    app.sidebar.radio[0].set_value("Signature")
    app.run()
    app.text_area[0].set_value("failure case")
    app.run()
    app.button[0].click()
    app.run(timeout=120)

    result = app.session_state["generated_signature"]
    assert result["error_kind"] == expected_kind
    assert result["signature"] is None
    displayed_errors = "\n".join(item.value for item in app.error)
    assert message_fragment in displayed_errors
    assert str(exception) not in displayed_errors


def test_analysis_shows_sizes_from_current_local_profile() -> None:
    """Analysis metrics are derived from the active cryptographic constants."""
    app = AppTest.from_file(str(APP_PATH)).run()
    app.sidebar.radio[0].set_value("Analyse et performances")
    app.run()

    assert not app.exception
    sizes = profile_sizes()
    assert sizes == {
        "compact_public_key": 1168,
        "compact_secret_key": 24,
        "expanded_public_key": 70752,
        "expanded_secret_key": 69856,
        "signature": 321,
    }
    displayed_metrics = {metric.label: metric.value for metric in app.metric}
    assert displayed_metrics["Signature"] == "321 octets"
    assert displayed_metrics["Clé publique compacte"] == "1 168 octets"
    assert displayed_metrics["Clé secrète compacte"] == "24 octets"
    assert f"GF(16) · N={N} · M={M} · K={K}" in {
        item.value for item in app.sidebar.caption
    }
    assert (V, O_DIM) == (58, 8)
    assert not any(
        metric.label == "Durée totale observée" for metric in app.metric
    )
