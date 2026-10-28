"""The Merchant role writes its decisions to the real hash-chained log before it returns."""

from __future__ import annotations

import hashlib

from sqlalchemy import Engine

from countersign.ledger.store import entries_for_checkout, verify_log
from countersign.merchant.decision_log import LedgerDecisionLog
from countersign.merchant.verify import Accepted, CheckoutMandateVerifier, Rejected
from tests.mandate_issuer import NOW
from tests.merchant_support import AllowAllConstraintsForTests, make_setup

POLICY = hashlib.sha256(b"policy v1").digest()


def test_accept_and_reject_are_in_the_verified_chain(app_engine: Engine, clean_log: None) -> None:
    s = make_setup()
    log = LedgerDecisionLog(app_engine, POLICY, lambda: NOW * 1_000_000)
    verifier = CheckoutMandateVerifier(
        s.verifier._config, s.store, log, lambda: float(NOW), AllowAllConstraintsForTests()
    )
    token = s.mandate().token
    ok = verifier.verify(mandate=token, issued_checkout=s.issued, current=s.checkout)
    bad = verifier.verify(mandate=token, issued_checkout=s.issued, current=s.checkout)
    assert isinstance(ok, Accepted) and isinstance(bad, Rejected)
    with app_engine.connect() as conn:
        entries = entries_for_checkout(conn, s.checkout.id)
        assert [e.kind for e in entries] == [
            "merchant.checkout_mandate.accepted",
            "merchant.checkout_mandate.rejected",
        ]
        assert verify_log(conn).ok


def test_a_log_that_cannot_be_written_fails_the_operation(
    app_engine: Engine, clean_log: None
) -> None:
    import pytest
    from sqlalchemy import create_engine

    from countersign.merchant.decision_log import DecisionLogError

    s = make_setup()
    broken = create_engine("postgresql+psycopg://nobody:x@127.0.0.1:1/none")
    log = LedgerDecisionLog(broken, POLICY, lambda: NOW * 1_000_000)
    verifier = CheckoutMandateVerifier(
        s.verifier._config, s.store, log, lambda: float(NOW), AllowAllConstraintsForTests()
    )
    token = s.mandate().token
    with pytest.raises(DecisionLogError):
        verifier.verify(mandate=token, issued_checkout=s.issued, current=s.checkout)
    assert s.store._open == {}
