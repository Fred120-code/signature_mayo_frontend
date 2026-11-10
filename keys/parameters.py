"""Parameter constants and consistency checks for the MAYO1 project."""

from typing import Final

from core.field import FIELD_SIZE

Q: Final[int] = FIELD_SIZE
N: Final[int] = 66
M: Final[int] = 64
O_DIM: Final[int] = 8
K: Final[int] =9
SEED_SK_BYTES: Final[int] = 24
SEED_PK_BYTES: Final[int] = 16
V: Final[int] = N - O_DIM
DIGEST_BYTES: Final[int] = 32
SALT_BYTES: Final[int] = 24
R_BYTES: Final[int] = 24


def check_parameters() -> None:
    """Assert the project's expected MAYO1 parameter relationships.

    This preserves the checks and console message of the original helper.

    Raises:
        AssertionError: If any configured parameter relationship is invalid.
    """
    assert Q == 16
    assert V == N - O_DIM
    assert K * O_DIM >= M

    print("Parametres MAYO1 valides !")
