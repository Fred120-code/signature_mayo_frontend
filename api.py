import os
import secrets
import threading
import time
from pathlib import Path
from time import perf_counter
from typing import Literal

from fastapi import Cookie, FastAPI, HTTPException, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from keys.expand_public import expand_public_key
from keys.expand_secret import expand_secret_key
from keys.keygen import generate_keypair
from keys.parameters import K, M, N, O_DIM
from scheme.sign import sign
from scheme.trace import SignTraceError
from scheme.verify import verify

WEB_DIR = Path(__file__).parent / "web"
COOKIE = "mayo_sid"
SESSION_TTL = int(os.getenv("SESSION_TTL_SECONDS", "1800"))
MAX_SESSIONS = int(os.getenv("MAX_SESSIONS", "200"))

app = FastAPI(title="MAYO1 Lab API")
STORE: dict[str, dict] = {}
LOCK = threading.Lock()


class SignRequest(BaseModel):
    message: str = Field(max_length=2000)


class VerifyRequest(BaseModel):
    message: str = Field(max_length=2000)
    tamper: Literal["none", "message", "signature"] = "none"


def _purge() -> None:
    """Drop expired sessions, then the oldest ones above the limit."""
    now = time.time()
    for sid in [s for s, d in STORE.items() if now - d["ts"] > SESSION_TTL]:
        del STORE[sid]
    while len(STORE) >= MAX_SESSIONS:
        del STORE[min(STORE, key=lambda s: STORE[s]["ts"])]


def _session(sid: str | None, *names: str) -> dict:
    with LOCK:
        data = STORE.get(sid or "")
        if data is None or any(name not in data for name in names):
            raise HTTPException(
                409, "Génère d'abord les clés (et signe avant de vérifier)."
            )
        data["ts"] = time.time()
        return data


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/")
def index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


@app.post("/api/keygen")
def keygen(
    response: Response, mayo_sid: str | None = Cookie(None)
) -> dict:
    start = perf_counter()
    cpk, csk = generate_keypair()
    generate_ms = (perf_counter() - start) * 1000
    start = perf_counter()
    epk, esk = expand_public_key(cpk), expand_secret_key(csk)
    expand_ms = (perf_counter() - start) * 1000
    sid = secrets.token_urlsafe(24)
    with LOCK:
        STORE.pop(mayo_sid or "", None)
        _purge()
        STORE[sid] = {"epk": epk, "esk": esk, "ts": time.time()}
    response.set_cookie(
        COOKIE, sid, max_age=SESSION_TTL, httponly=True, samesite="lax"
    )
    return {
        "params": {"n": N, "m": M, "o": O_DIM, "k": K},
        "sizes": {
            "compact_public_key": len(cpk),
            "compact_secret_key": len(csk),
            "expanded_public_key": len(epk),
            "expanded_secret_key": len(esk),
        },
        "timings_ms": {"keygen": round(generate_ms), "expansion": round(expand_ms)},
    }


@app.post("/api/sign")
def sign_endpoint(
    req: SignRequest, mayo_sid: str | None = Cookie(None)
) -> dict:
    data = _session(mayo_sid, "esk")
    start = perf_counter()
    try:
        signature, trace = sign(data["esk"], req.message, return_trace=True)
    except SignTraceError as error:
        raise HTTPException(
            500, {"error": str(error), "trace": error.trace.to_dict()["steps"]}
        ) from error
    data["signature"] = signature
    return {
        "signature_hex": signature.hex(),
        "signature_bytes": len(signature),
        "elapsed_ms": round((perf_counter() - start) * 1000),
        "trace": trace.to_dict()["steps"],
    }


@app.post("/api/verify")
def verify_endpoint(
    req: VerifyRequest, mayo_sid: str | None = Cookie(None)
) -> dict:
    data = _session(mayo_sid, "epk", "signature")
    message, signature = req.message, data["signature"]
    if req.tamper == "message":
        message += "x"
    elif req.tamper == "signature":
        altered = bytearray(signature)
        altered[5] ^= 0x01  # inverse un seul bit
        signature = bytes(altered)
    start = perf_counter()
    result, trace = verify(data["epk"], message, signature, return_trace=True)
    return {
        "valid": result == 0,
        "result_code": result,
        "tamper": req.tamper,
        "elapsed_ms": round((perf_counter() - start) * 1000),
        "trace": trace.to_dict()["steps"],
    }