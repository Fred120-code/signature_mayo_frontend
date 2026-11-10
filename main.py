"""Command-line entry point for the educational MAYO1 demonstration."""

import argparse

from app import run_demo


def main() -> int:
    """Run one demonstration and print its artifact sizes and outcome."""
    parser = argparse.ArgumentParser(description="Run the MAYO1 demo workflow.")
    parser.add_argument(
        "message",
        nargs="?",
        default="MAYO1 educational demonstration",
        help="message to sign and verify",
    )
    arguments = parser.parse_args()

    result = run_demo(arguments.message)
    print("MAYO1 — demonstration éducative")
    print(f"Clé publique compacte : {len(result.compact_public_key)} octets")
    print(f"Clé secrète compacte : {len(result.compact_secret_key)} octets")
    print(f"Clé publique étendue : {len(result.expanded_public_key)} octets")
    print(f"Clé secrète étendue : {len(result.expanded_secret_key)} octets")
    print(f"Signature : {len(result.signature)} octets")
    if result.verification_status == 0:
        print("Vérification : valide")
        return 0

    print("Vérification : invalide")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
