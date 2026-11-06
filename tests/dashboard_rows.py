"""Put a committed evidence vector into a database as a dashboard order, labelled as simulated.

The vectors are synthetic (a test scans them), so an order made from one is never a sandbox capture:
its source label is `simulator`. The checkout row is the checkout the vector's merchant-signed JWT
carries, the attempt row says captured, and the bundle row is the vector text unchanged (or the text the
caller passes, for the tests that need a bundle with a hostile or forged member).
"""

from __future__ import annotations

import base64
import json
import time
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, insert

from countersign.canonical import canonicalize
from countersign.checkout.store import checkout_sessions
from countersign.tables import (
    attempt_mandates,
    checkout_customers,
    checkout_sources,
    evidence_bundles,
    payment_attempts,
)

VECTORS = Path(__file__).resolve().parent / "vectors" / "evidence"


def vector_text(name: str = "valid.json") -> str:
    return (VECTORS / name).read_text(encoding="utf-8")


def insert_bundle_order(
    engine: Engine, text: str, *, source: str = "simulator", created_us: int | None = None
) -> dict[str, str]:
    bundle: dict[str, Any] = json.loads(text)
    segment = bundle["checkout_jwt"].split(".")[1]
    checkout = json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
    cid, capture = bundle["checkout_id"], bundle["capture_id"]
    now = created_us if created_us is not None else time.time_ns() // 1000
    with engine.begin() as conn:
        conn.execute(
            insert(checkout_sessions).values(
                id=cid, status="completed", version=1, checkout=canonicalize(checkout),
                next_line_seq=2, catalog_hash=b"\0" * 32, created_us=now, updated_us=now,
                expires_us=now + 86_400_000_000,
            )
        )  # fmt: skip
        conn.execute(
            insert(checkout_sources).values(checkout_id=cid, source=source, created_us=now)
        )
        conn.execute(
            insert(checkout_customers).values(
                checkout_id=cid, customer_id=bundle["consent"]["customer_id"],
                agent_thumbprint=None, source="delegation", created_us=now,
            )
        )  # fmt: skip
        conn.execute(
            insert(attempt_mandates).values(
                checkout_id=cid, payment_token=bundle["mandates"]["payment_closed"],
                checkout_mandate=bundle["mandates"]["checkout_closed"], created_us=now,
            )
        )  # fmt: skip
        conn.execute(
            insert(payment_attempts).values(
                checkout_id=cid, reservation_handle="rsv_vector", spend_id="spd_vector",
                mandate_digest="vector", state="captured", mode="redirect",
                custom_id=bundle["gate"]["custom_id"], principal=None, order_id=bundle["order_id"],
                authorization_id=bundle["authorization_id"], capture_id=capture, created_us=now,
                updated_us=now, gate_code=None, gate_reason=None,
            )
        )  # fmt: skip
        conn.execute(
            insert(evidence_bundles).values(
                capture_id=capture, checkout_id=cid, bundle=text, created_us=now
            )
        )  # fmt: skip
    return {"checkout_id": cid, "capture_id": capture}
