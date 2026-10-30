"""An ACP cart and the equivalent UCP cart are the same canonical checkout (INV-5, INV-8).

The two adapters read different request shapes and keep different members around the checkout, but the
canonical model is one: same items and quantities give byte-identical canonical bytes and the same
terms hash. ACP specific members (protocol version, capabilities, links, timestamps) are not in them.
"""

from __future__ import annotations

import itertools
import json

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from sqlalchemy import Engine, select

from countersign.canonical import canonicalize
from countersign.catalog.catalog import load_catalog
from countersign.checkout.store import checkout_sessions
from countersign.lock import PrincipalLock
from countersign.merchant.policy import policy_hash
from countersign.protocols.acp.requests import CartLine, CreateRequest
from countersign.protocols.acp.service import AcpContext, AcpService
from countersign.protocols.ucp.requests import CheckoutRequest, LineRequest
from countersign.protocols.ucp.service import UcpService

CATALOG = load_catalog()
COUNTER = itertools.count()
carts = st.lists(
    st.tuples(st.integers(0, len(CATALOG.items) - 1), st.integers(1, 99)), min_size=1, max_size=20
)


def services(engine: Engine) -> tuple[UcpService, AcpService]:
    ucp = UcpService(engine, CATALOG, policy_hash=policy_hash())
    acp = AcpService(engine, CATALOG, policy_hash=policy_hash(), lock=PrincipalLock(engine))
    return ucp, acp


def test_equivalent_carts_have_identical_canonical_bytes_and_terms_hash(
    app_engine: Engine, clean_payments: None
) -> None:
    ucp, acp = services(app_engine)

    @settings(
        max_examples=500,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
    )
    @given(cart=carts)
    def check(cart: list[tuple[int, int]]) -> None:
        ucp_lines, _, errors = ucp._resolve(
            CheckoutRequest(
                tuple(LineRequest(CATALOG.items[i].id, q, None, None) for i, q in cart)
            ),
            set(),
            1,
            update=False,
        )
        assert not errors
        acp_lines = [
            (f"li_{n}", CartLine(CATALOG.items[i].id, q, None)) for n, (i, q) in enumerate(cart, 1)
        ]
        same_id = f"chk_equiv_{next(COUNTER):010d}"
        from_ucp = ucp._build(same_id, ucp_lines)
        from_acp = acp._build(same_id, acp_lines)
        assert from_ucp.canonical_bytes() == from_acp.canonical_bytes()
        assert from_ucp.terms_bytes() == from_acp.terms_bytes()
        assert from_ucp.terms_hash() == from_acp.terms_hash()

    check()


def test_a_cart_made_over_http_by_each_protocol_is_stored_as_the_same_bytes(
    app_engine: Engine, clean_payments: None
) -> None:
    ucp, acp = services(app_engine)
    cart = [(0, 2), (1, 3)]
    made_ucp = ucp.create(
        CheckoutRequest(tuple(LineRequest(CATALOG.items[i].id, q, None, None) for i, q in cart))
    )
    made_acp = acp.create(
        CreateRequest(tuple(CartLine(CATALOG.items[i].id, q, None) for i, q in cart), "USD"),
        AcpContext(),
    )
    assert made_ucp.record is not None
    with app_engine.connect() as conn:
        rows = {r.id: bytes(r.checkout) for r in conn.execute(select(checkout_sessions)).all()}

    def without_id(raw: bytes) -> bytes:
        return canonicalize({**json.loads(raw), "id": "X"})

    stored_ucp, stored_acp = rows[made_ucp.record.id], rows[made_acp.record.id]
    assert without_id(stored_ucp) == without_id(stored_acp)
    assert made_acp.record.checkout.canonical_bytes() == stored_acp


def test_acp_only_members_are_outside_the_canonical_bytes(
    app_engine: Engine, clean_payments: None
) -> None:
    _, acp = services(app_engine)
    session = acp.create(
        CreateRequest((CartLine(CATALOG.items[0].id, 1, None),), "USD"), AcpContext()
    )
    body = session.body()
    canonical = json.loads(session.record.checkout.canonical_bytes())
    for member in ("protocol", "capabilities", "links", "fulfillment_options", "created_at",
                   "messages", "expires_at", "updated_at"):  # fmt: skip
        assert member in body and member not in canonical
    assert set(canonical) == {"id", "currency", "line_items", "totals"}
