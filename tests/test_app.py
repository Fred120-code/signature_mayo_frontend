"""Tests for the UI-independent application workflow."""

import app


def test_run_demo_returns_workflow_artifacts(monkeypatch) -> None:
    """The application layer passes artifacts through each stage."""
    events: list[tuple[str, object]] = []
    message = "demo message"

    def generate_keypair() -> tuple[bytes, bytes]:
        events.append(("keygen", None))
        return b"compact public", b"compact secret"

    def expand_public_key(key: bytes) -> bytes:
        events.append(("expand public", key))
        return b"expanded public"

    def expand_secret_key(key: bytes) -> bytes:
        events.append(("expand secret", key))
        return b"expanded secret"

    def sign(key: bytes, input_message: bytes | str) -> bytes:
        events.append(("sign", (key, input_message)))
        return b"signature"

    def verify(
        key: bytes,
        input_message: bytes | str,
        signature: bytes,
    ) -> int:
        events.append(("verify", (key, input_message, signature)))
        return 0

    monkeypatch.setattr(app, "generate_keypair", generate_keypair)
    monkeypatch.setattr(app, "expand_public_key", expand_public_key)
    monkeypatch.setattr(app, "expand_secret_key", expand_secret_key)
    monkeypatch.setattr(app, "sign", sign)
    monkeypatch.setattr(app, "verify", verify)

    result = app.run_demo(message)

    assert result.message == message
    assert result.compact_public_key == b"compact public"
    assert result.compact_secret_key == b"compact secret"
    assert result.expanded_public_key == b"expanded public"
    assert result.expanded_secret_key == b"expanded secret"
    assert result.signature == b"signature"
    assert result.verification_status == 0
    assert events == [
        ("keygen", None),
        ("expand public", b"compact public"),
        ("expand secret", b"compact secret"),
        ("sign", (b"expanded secret", message)),
        ("verify", (b"expanded public", message, b"signature")),
    ]
