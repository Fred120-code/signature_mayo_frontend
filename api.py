"""API HTTP du laboratoire MAYO1 : expose le moteur existant et ses traces.

Lancer depuis la racine du dépôt :  uvicorn api:app --reload
Puis ouvrir http://127.0.0.1:8000

Les clés restent en mémoire côté serveur (démo mono-utilisateur) et ne sont
jamais renvoyées au navigateur. Seuls les tailles, durées, traces expurgées
et la signature (publique) sont transmises.
"""

from pathlib import Path
from time import perf_counter
from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from keys.expand_public import expand_public_key
from keys.expand_secret import expand_secret_key
from keys.keygen import generate_keypair
from keys.parameters import K, M, N, O_DIM
from scheme.sign import sign
from scheme.trace import SignTraceError
from scheme.verify import verify

WEB_DIR = Path(__file__).parent / "web"
app = FastAPI(title="MAYO1 Lab API")
STORE: dict[str, bytes] = {}


class SignRequest(BaseModel):
    message: str


class VerifyRequest(BaseModel):
    message: str
    tamper: Literal["none", "message", "signature"] = "none"


def _need(*names: str) -> None:
    if any(name not in STORE for name in names):
        raise HTTPException(409, "Génère d'abord les clés (et signe avant de vérifier).")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


@app.post("/api/keygen")
def keygen() -> dict:
    start = perf_counter()
    cpk, csk = generate_keypair()
    generate_ms = (perf_counter() - start) * 1000
    start = perf_counter()
    STORE.clear()
    STORE.update(epk=expand_public_key(cpk), esk=expand_secret_key(csk))
    expand_ms = (perf_counter() - start) * 1000
    return {
        "params": {"n": N, "m": M, "o": O_DIM, "k": K},
        "sizes": {
            "compact_public_key": len(cpk),
            "compact_secret_key": len(csk),
            "expanded_public_key": len(STORE["epk"]),
            "expanded_secret_key": len(STORE["esk"]),
        },
        "timings_ms": {"keygen": round(generate_ms), "expansion": round(expand_ms)},
    }


@app.post("/api/sign")
def sign_endpoint(req: SignRequest) -> dict:
    _need("esk")
    start = perf_counter()
    try:
        signature, trace = sign(STORE["esk"], req.message, return_trace=True)
    except SignTraceError as error:
        raise HTTPException(
            500, {"error": str(error), "trace": error.trace.to_dict()["steps"]}
        ) from error
    STORE["signature"] = signature
    return {
        "signature_hex": signature.hex(),
        "signature_bytes": len(signature),
        "elapsed_ms": round((perf_counter() - start) * 1000),
        "trace": trace.to_dict()["steps"],
    }


@app.post("/api/verify")
def verify_endpoint(req: VerifyRequest) -> dict:
    _need("epk", "signature")
    message, signature = req.message, STORE["signature"]
    if req.tamper == "message":
        message += "x"
    elif req.tamper == "signature":
        altered = bytearray(signature)
        altered[5] ^= 0x01  # inverse un seul bit
        signature = bytes(altered)
    start = perf_counter()
    result, trace = verify(STORE["epk"], message, signature, return_trace=True)
    return {
        "valid": result == 0,
        "result_code": result,
        "tamper": req.tamper,
        "elapsed_ms": round((perf_counter() - start) * 1000),
        "trace": trace.to_dict()["steps"],
    }
