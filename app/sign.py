"""Ed25519 signing for tamper-evident evidence records.

Every evidence record Heron emits is signed so a counterparty can confirm the
record came from this Heron instance and was not altered. Mirrors the AARM R5
"tamper-evident receipt" shape in the agent-to-agent setting.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_KEY_PATH = Path(__file__).resolve().parent.parent / "data" / "heron_ed25519.key"


def _load_or_create_key() -> Ed25519PrivateKey:
    # Deploy: a stable identity across restarts. Prefer HERON_SIGNING_KEY (base64 of
    # the 32-byte raw ed25519 seed) so ephemeral containers keep one signing key;
    # else a persisted file; else generate (dev).
    env_key = os.environ.get("HERON_SIGNING_KEY")
    if env_key:
        return Ed25519PrivateKey.from_private_bytes(base64.b64decode(env_key))
    if _KEY_PATH.exists():
        return serialization.load_pem_private_key(_KEY_PATH.read_bytes(), password=None)  # type: ignore[return-value]
    key = Ed25519PrivateKey.generate()
    _KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    _KEY_PATH.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return key


def private_seed_b64() -> str:
    """The raw seed, base64 — set this as HERON_SIGNING_KEY in the deploy env."""
    raw = _PRIVATE.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return base64.b64encode(raw).decode("ascii")


_PRIVATE = _load_or_create_key()


def _canonical(payload: dict) -> bytes:
    # Deterministic serialization so the same record always signs/verifies identically.
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def public_key_b64() -> str:
    raw = _PRIVATE.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def sign(payload: dict) -> dict:
    """Return the ed25519 signature block for a record body (the body itself is not mutated)."""
    sig = _PRIVATE.sign(_canonical(payload))
    return {
        "alg": "ed25519",
        "value": base64.b64encode(sig).decode("ascii"),
        "public_key": public_key_b64(),
    }


def verify(payload: dict, signature_b64: str, public_key_b64_str: str) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64_str))
        pub.verify(base64.b64decode(signature_b64), _canonical(payload))
        return True
    except Exception:
        return False
