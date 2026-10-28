"""Load the shared mandate vectors and verify one with the library (used by several tests)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from joserfc.jwk import ECKey

from countersign.mandates import VerifiedChain, verify_chain

VECTOR_FILE = Path(__file__).parent / "vectors" / "mandates" / "chain_vectors.json"


def load_vectors() -> list[dict[str, Any]]:
    data = json.loads(VECTOR_FILE.read_text())
    assert data["version"] == 1
    vectors: list[dict[str, Any]] = data["vectors"]
    return vectors


def verify_vector(vector: dict[str, Any], token: str | None = None) -> VerifiedChain:
    now = vector["now"]
    return verify_chain(
        vector["token"] if token is None else token,
        issuer_key=ECKey.import_key(vector["issuer_jwk"]),
        expected_vcts=vector["expected_vcts"],
        audience=vector["audience"],
        nonce=vector["nonce"],
        clock=lambda: now,
    )
