"""Merchant role verification: every step, every UCP error code, single use and atomicity."""

from __future__ import annotations

import base64
import json
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from countersign.canonical import checkout_hash, sd_hash
from countersign.canonical.models import Checkout
from countersign.mandates import split_chain
from countersign.mandates.errors import MandateError
from countersign.merchant import receipts
from countersign.merchant.authorization import checkout_jwt, sign_checkout
from countersign.merchant.constraints import ConstraintResult, DenyAllConstraints
from countersign.merchant.decision_log import DecisionLogError
from countersign.merchant.keys import generate_jwk, validate_jwk
from countersign.merchant.rejection import UCP_CODES, Rejection
from countersign.merchant.reservations import (
    AlreadyReservedError,
    InMemoryReservationStore,
    ReservationError,
    ReservationRequest,
)
from countersign.merchant.verify import (
    MODE_AUTONOMOUS,
    MODE_HUMAN_PRESENT,
    Accepted,
    Rejected,
    _map_mandate_error,
    terms_difference,
)
from tests.mandate_issuer import NOW, Keys, issue_human_present
from tests.merchant_support import (
    AllowAllConstraintsForTests,
    RaisingConstraintsForTests,
    Setup,
    make_checkout,
    make_setup,
    signed_response,
)


def rejected(result: object, step: str, reason: str, code: str, detail: str | None = None) -> None:
    assert isinstance(result, Rejected), result
    assert (result.step, result.reason, result.ucp_code) == (step, reason, code), result
    if detail is not None:
        assert result.detail == detail or result.detail.startswith(detail)
    message = result.messages[0]
    assert message["type"] == "error" and message["code"] == code and message["content"]
    assert message["severity"] in {"recoverable", "unrecoverable"}


def accepted(result: object) -> Accepted:
    assert isinstance(result, Accepted), result
    return result


# ----- the happy paths -----


def test_autonomous_mandate_is_accepted_with_a_verifiable_receipt() -> None:
    s = make_setup()
    issued = s.mandate()
    result = accepted(s.verify(issued.token))
    assert result.mode == MODE_AUTONOMOUS
    claims = receipts.verify_receipt(result.receipt, [s.merchant_key.public_jwk])
    assert claims == {
        "status": "Success",
        "iss": "https://merchant.example",
        "iat": NOW,
        "reference": sd_hash(split_chain(issued.token)[-1].serialization),
        "order_id": s.checkout.id,
    }
    assert claims["reference"] == result.chain.final.digest == result.reference
    assert result.checkout_hash == checkout_hash(s.jwt)
    assert [e["kind"] for e in s.log.entries] == ["merchant.checkout_mandate.accepted"]


def test_human_present_mandate_signed_by_the_platform_is_accepted() -> None:
    s = make_setup()
    token = issue_human_present(s.keys, checkout_jwt_value=s.jwt)
    assert accepted(s.verify(token)).mode == MODE_HUMAN_PRESENT


def test_a_rejection_receipt_is_signed_and_names_the_ucp_code() -> None:
    s = make_setup()
    token = s.mandate(kb_aud="elsewhere").token
    result = s.verify(token)
    rejected(result, "M2", "chain:kb_audience_mismatch", "mandate_invalid_signature")
    claims = receipts.verify_receipt(result.receipt, [s.merchant_key.public_jwk])
    assert claims["status"] == "Error" and claims["error"] == "mandate_invalid_signature"
    assert claims["error_description"] == "chain:kb_audience_mismatch"
    assert claims["reference"] == sd_hash(split_chain(token)[-1].serialization)
    assert [e["kind"] for e in s.log.entries] == ["merchant.checkout_mandate.rejected"]
    assert s.log.entries[0]["step"] == "M2"


def test_receipts_do_not_verify_as_merchant_authorization_or_when_tampered() -> None:
    s = make_setup()
    result = accepted(s.verify(s.mandate().token))
    head, payload, signature = result.receipt.split(".")
    with pytest.raises(receipts.ReceiptError):
        receipts.verify_receipt(f"{head}.{payload}x.{signature}", [s.merchant_key.public_jwk])
    with pytest.raises(receipts.ReceiptError):
        receipts.verify_receipt(result.receipt, [validate_jwk(generate_jwk()).public_jwk])
    header = json.loads(base64.urlsafe_b64decode(head + "=="))
    assert header["typ"] == receipts.RECEIPT_TYP and set(header) == {"alg", "kid", "typ"}


# ----- M1 mandate_required -----


@pytest.mark.parametrize("mandate", [None, ""])
def test_m1_missing_mandate(mandate: object) -> None:
    s = make_setup()
    rejected(s.verify(mandate), "M1", "mandate_missing", "mandate_required")


# ----- M2 chain: mandate_invalid_signature, mandate_expired, agent_missing_key -----


@pytest.mark.parametrize("mandate", ["garbage", "a.b.c~", 5, b"x~", "A" * 20000])
def test_m2_unparseable_mandates(mandate: object) -> None:
    s = make_setup()
    result = s.verify(mandate)
    assert isinstance(result, Rejected) and result.step == "M2"
    assert result.ucp_code == "mandate_invalid_signature"


def test_m2_open_mandate_signed_by_an_untrusted_platform_key() -> None:
    s = make_setup()
    token = s.mandate(issuer_signer=Keys().stranger).token
    rejected(s.verify(token), "M2", "chain:signature_invalid", "mandate_invalid_signature")


def test_m2_closed_mandate_signed_by_a_key_other_than_cnf() -> None:
    s = make_setup()
    token = s.mandate(kb_signer=Keys().stranger).token
    rejected(s.verify(token), "M2", "chain:signature_invalid", "mandate_invalid_signature")


def test_m2_human_present_mandate_signed_by_another_key() -> None:
    s = make_setup()
    token = issue_human_present(s.keys, checkout_jwt_value=s.jwt, signer=Keys().stranger)
    rejected(s.verify(token), "M2", "chain:signature_invalid", "mandate_invalid_signature")


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"issuer_alg_header": "none", "issuer_sign_alg": "none"}, "chain:alg_not_allowed"),
        ({"kb_alg_header": "HS256", "kb_sign_alg": "HS256"}, "chain:alg_not_allowed"),
        ({"sd_hash_value": "x" * 43}, "chain:sd_hash_mismatch"),
        ({"edit_kb_payload": lambda p: p.update(nonce="")}, "chain:kb_claim_missing"),
        ({"kb_iat": NOW + 3600}, "chain:issued_in_future"),
        ({"open_nbf": NOW + 3600}, "chain:not_yet_valid"),
        ({"open_exp": None}, "chain:exp_missing"),
    ],
)
def test_m2_other_chain_failures_are_invalid_signature(kwargs: dict, reason: str) -> None:
    s = make_setup()
    rejected(s.verify(s.mandate(**kwargs).token), "M2", reason, "mandate_invalid_signature")


def test_m2_expired_open_mandate() -> None:
    s = make_setup()
    rejected(
        s.verify(s.mandate(open_exp=NOW - 61).token), "M2", "mandate_expired", "mandate_expired"
    )


def test_m2_expired_closed_mandate() -> None:
    s = make_setup()
    rejected(
        s.verify(s.mandate(closed_exp=NOW - 61).token), "M2", "mandate_expired", "mandate_expired"
    )


def test_m2_expired_human_present_mandate_and_the_clock_is_injected() -> None:
    s = make_setup()
    token = issue_human_present(s.keys, checkout_jwt_value=s.jwt, exp=NOW + 100)
    s.clock_value[0] = NOW + 161
    rejected(s.verify(token), "M2", "mandate_expired", "mandate_expired")
    s.clock_value[0] = NOW + 160  # exactly the skew past exp still passes
    accepted(s.verify(token))


def test_m2_platform_without_a_usable_key() -> None:
    s = make_setup(platform_trusted=False)
    rejected(s.verify(s.mandate().token), "M2", "platform_key_missing", "agent_missing_key")


@pytest.mark.parametrize(
    "cnf",
    [None, "abc", {"kid": "agent"}, {"jwk": {"kty": "RSA", "n": "AQAB", "e": "AQAB"}}],
)
def test_m2_open_mandate_without_a_usable_agent_key(cnf: object) -> None:
    s = make_setup()
    result = s.verify(s.mandate(cnf=cnf).token)
    assert isinstance(result, Rejected) and result.ucp_code == "agent_missing_key"
    assert result.reason.startswith("chain:cnf_")


def test_m2_wrong_chain_length_and_wrong_vct() -> None:
    s = make_setup()
    two_open = s.mandate(hops=3).token
    rejected(s.verify(two_open), "M2", "chain:structure_chain_length", "mandate_invalid_signature")
    rejected(
        s.verify(s.mandate(open_vct="mandate.payment.open.1").token),
        "M2",
        "chain:vct_mismatch",
        "mandate_invalid_signature",
    )


def test_an_unknown_mandate_error_code_fails_closed() -> None:
    class Strange(MandateError):
        code = "never_seen_before"

    rejection = _map_mandate_error(Strange("x"))
    assert rejection.ucp_code == "mandate_invalid_signature"
    assert rejection.reason == "chain:never_seen_before"


# ----- M3 checkout hash -----


def test_m3_checkout_hash_claim_differs() -> None:
    s = make_setup()
    token = s.mandate(checkout_hash_value="x" * 43).token
    rejected(s.verify(token), "M3", "checkout_hash_mismatch", "mandate_scope_mismatch")


def test_m3_mandate_for_another_checkout() -> None:
    s = make_setup()
    other = signed_response(
        make_checkout(price=100, checkout_id="chk_zzzzzzzzzzzzzzzzzzzzzz"), s.merchant_key
    )
    token = s.mandate(checkout_jwt_value=checkout_jwt(other)).token
    rejected(s.verify(token), "M3", "checkout_hash_mismatch", "mandate_scope_mismatch")


def test_m3_checkout_hash_claim_absent() -> None:
    s = make_setup()
    token = s.mandate(edit_kb_content=lambda c: c.pop("checkout_hash")).token
    rejected(s.verify(token), "M3", "checkout_hash_missing", "mandate_scope_mismatch")


def test_m3_session_checkout_unusable() -> None:
    s = make_setup()
    token = s.mandate().token
    result = s.verifier.verify(mandate=token, issued_checkout={"id": "x"}, current=s.checkout)
    rejected(result, "M3", "session_checkout_unavailable", "mandate_scope_mismatch")


# ----- M4 merchant authorization -----


def test_m4_merchant_authorization_stripped_entirely() -> None:
    s = make_setup()
    token = s.mandate(omit_checkout_jwt=True).token
    rejected(s.verify(token), "M4", "checkout_jwt_absent", "merchant_authorization_missing")


def test_m4_signature_segment_stripped() -> None:
    s = make_setup()
    head, payload, _ = s.jwt.split(".")
    stripped = f"{head}.{payload}."
    token = s.mandate(checkout_jwt_value=stripped, checkout_hash_value=checkout_hash(s.jwt)).token
    rejected(s.verify(token), "M4", "signature_stripped", "merchant_authorization_missing")


def test_m4_signed_with_a_key_that_is_not_ours() -> None:
    s = make_setup(session_key=validate_jwk(generate_jwk()))
    rejected(
        s.verify(s.mandate().token),
        "M4",
        "merchant_authorization_unverified",
        "merchant_authorization_invalid",
    )


@pytest.mark.parametrize("value", ["a.b", "a.b.c.d", ".b.c", "a..c"])
def test_m4_malformed_embedded_jwt(value: str) -> None:
    s = make_setup()
    token = s.mandate(checkout_jwt_value=value, checkout_hash_value=checkout_hash(s.jwt)).token
    rejected(s.verify(token), "M4", "checkout_jwt_malformed", "merchant_authorization_invalid")


def test_m4_embedded_jwt_that_is_not_text() -> None:
    s = make_setup()
    token = s.mandate(
        edit_kb_content=lambda c: c.update(checkout_jwt=5), omit_checkout_jwt=True
    ).token
    assert isinstance(s.verify(token), Rejected)


def test_m4_embedded_checkout_is_another_checkout_we_signed() -> None:
    s = make_setup()
    older = signed_response(make_checkout(price=100), s.merchant_key)
    token = s.mandate(
        checkout_jwt_value=checkout_jwt(older), checkout_hash_value=checkout_hash(s.jwt)
    ).token
    rejected(
        s.verify(token), "M4", "embedded_checkout_is_not_this_session", "mandate_scope_mismatch"
    )


def test_m4_embedded_payload_that_is_not_canonical_json() -> None:
    s = make_setup()
    head, payload, signature = s.jwt.split(".")
    raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
    spaced = json.dumps(json.loads(raw), indent=1).encode()
    bad = f"{head}.{base64.urlsafe_b64encode(spaced).rstrip(b'=').decode()}.{signature}"
    token = s.mandate(checkout_jwt_value=bad, checkout_hash_value=checkout_hash(s.jwt)).token
    result = s.verify(token)
    assert isinstance(result, Rejected) and result.step == "M4"
    assert result.ucp_code == "merchant_authorization_invalid"


# ----- M5 terms -----


@pytest.mark.parametrize(
    ("current_kwargs", "detail"),
    [
        ({"checkout_id": "chk_zzzzzzzzzzzzzzzzzzzzzz"}, "id"),
        ({"currency": "EUR"}, "currency"),
        ({"fee": 900}, "totals"),
        ({"price": 4100}, "line_items[0].item.price"),
        ({"quantity": 3}, "line_items[0].quantity"),
        ({"title": "Over-ear headphones, black"}, "line_items[0].item.title"),
    ],
)
def test_m5_embedded_terms_differ_from_the_current_session(
    current_kwargs: dict, detail: str
) -> None:
    s = make_setup()
    current = make_checkout(**current_kwargs)
    result = s.verify(s.mandate().token, current)
    rejected(result, "M5", "terms_mismatch", "mandate_scope_mismatch", detail)


def test_m5_embedded_checkout_not_a_checkout() -> None:
    s = make_setup()
    s.issued = sign_checkout({"id": s.checkout.id, "currency": "USD"}, s.merchant_key)
    result = s.verify(s.mandate().token)
    rejected(result, "M5", "embedded_checkout_malformed", "mandate_scope_mismatch")


def test_terms_difference_paths() -> None:
    assert terms_difference({"a": [1, {"b": 2}]}, {"a": [1, {"b": 2}]}) is None
    assert terms_difference({"a": [1, {"b": 2}]}, {"a": [1, {"b": 3}]}) == "a[1].b"
    assert terms_difference({"a": [1]}, {"a": [1, 2]}) == "a[length]"
    assert terms_difference({"a": 1}, {"a": 1, "b": 2}) == "b"
    assert terms_difference({"a": 1}, {"a": True}) == "a"  # 1 is not True


# ----- M7 constraints -----


def test_m7_default_evaluator_denies_everything() -> None:
    s = make_setup(constraints=DenyAllConstraints())
    rejected(
        s.verify(s.mandate().token),
        "M7",
        "constraint_unresolved",
        "mandate_scope_mismatch",
        "constraints_not_implemented",
    )


def test_m7_violated_constraint() -> None:
    class Violated:
        def evaluate(self, *, chain: object, checkout: Checkout, now: float) -> ConstraintResult:
            return ConstraintResult(False, "over_budget")

    s = make_setup(constraints=Violated())  # type: ignore[arg-type]
    rejected(
        s.verify(s.mandate().token),
        "M7",
        "constraint_violated",
        "mandate_scope_mismatch",
        "over_budget",
    )


@pytest.mark.parametrize("result", [None, True, "yes", ConstraintResult(1, "truthy")])  # type: ignore[arg-type]
def test_m7_only_exactly_satisfied_passes(result: object) -> None:
    class Odd:
        def evaluate(self, *, chain: object, checkout: Checkout, now: float) -> object:
            return result

    s = make_setup(constraints=Odd())  # type: ignore[arg-type]
    assert isinstance(s.verify(s.mandate().token), Rejected)
    assert s.store._open == {}  # nothing stayed reserved


def test_an_evaluator_that_crashes_rejects_and_reserves_nothing() -> None:
    s = make_setup(constraints=RaisingConstraintsForTests())
    token = s.mandate().token
    rejected(s.verify(token), "M2", "internal_error", "mandate_invalid_signature")
    assert s.store._open == {}


# ----- M8 single use -----


def test_m8_replayed_nonce_under_another_open_mandate_and_checkout() -> None:
    s = make_setup()
    accepted(
        s.verify(
            s.mandate(nonce="shared-nonce", keys=None).token
            if False
            else s.mandate(nonce="shared-nonce").token
        )
    )
    other = make_checkout(checkout_id="chk_bbbbbbbbbbbbbbbbbbbbbb")
    issued2 = signed_response(other, s.merchant_key)
    token2 = s.mandate(nonce="shared-nonce", checkout_jwt_value=checkout_jwt(issued2)).token
    result = s.verifier.verify(mandate=token2, issued_checkout=issued2, current=other)
    rejected(result, "M8", "nonce_replayed", "mandate_scope_mismatch")


def test_m8_reused_checkout_hash() -> None:
    s = make_setup()
    accepted(s.verify(s.mandate().token))
    rejected(s.verify(s.mandate().token), "M8", "checkout_hash_reused", "mandate_scope_mismatch")


def test_m8_second_purchase_under_one_open_mandate() -> None:
    s = make_setup()
    first = s.mandate()
    accepted(s.verify(first.token))
    other = make_checkout(checkout_id="chk_bbbbbbbbbbbbbbbbbbbbbb")
    issued2 = signed_response(other, s.merchant_key)
    second = s.mandate(
        reuse_open_token=first.open_token, nonce="second", checkout_jwt_value=checkout_jwt(issued2)
    )
    result = s.verifier.verify(mandate=second.token, issued_checkout=issued2, current=other)
    rejected(result, "M8", "open_mandate_in_use", "mandate_scope_mismatch")


def test_m8_human_present_mandate_cannot_be_reused_either() -> None:
    s = make_setup()
    token = issue_human_present(s.keys, checkout_jwt_value=s.jwt)
    accepted(s.verify(token))
    assert isinstance(s.verify(token), Rejected)


def test_a_failed_attempt_leaves_the_open_mandate_usable() -> None:
    s = make_setup()
    first = s.mandate(checkout_hash_value="x" * 43)  # rejected at M3
    rejected(s.verify(first.token), "M3", "checkout_hash_mismatch", "mandate_scope_mismatch")
    retry = s.mandate(reuse_open_token=first.open_token, nonce="retry")
    accepted(s.verify(retry.token))


def test_a_rejection_at_every_early_step_consumes_nothing() -> None:
    s = make_setup()
    token = s.mandate().token
    for current in (make_checkout(price=1), make_checkout(currency="EUR")):
        assert isinstance(s.verify(token, current), Rejected)
    accepted(s.verify(token))  # the very same closed mandate still works


def test_a_constraint_failure_then_success_with_the_same_mandate() -> None:
    class Flip:
        allow = False

        def evaluate(self, *, chain: object, checkout: Checkout, now: float) -> ConstraintResult:
            return ConstraintResult(self.allow, "flip")

    flip = Flip()
    s = make_setup(constraints=flip)  # type: ignore[arg-type]
    token = s.mandate().token
    assert isinstance(s.verify(token), Rejected)
    flip.allow = True
    accepted(s.verify(token))


def test_a_log_failure_on_acceptance_fails_the_operation_and_aborts_the_reservation() -> None:
    s = make_setup()
    token = s.mandate().token
    s.log.fail = True
    with pytest.raises(DecisionLogError):
        s.verify(token)
    assert s.store._open == {}
    s.log.fail = False
    accepted(s.verify(token))  # nothing was consumed by the failed operation


def test_a_log_failure_on_rejection_fails_the_operation() -> None:
    s = make_setup()
    s.log.fail = True
    with pytest.raises(DecisionLogError):
        s.verify(None)


# ----- the reservation store on its own -----


def _request(n: int = 1, scope: bool = True) -> ReservationRequest:
    return ReservationRequest(
        f"chk_{n}",
        f"hash_{n}",
        f"digest_{n}",
        ("thumb", "merchant", f"nonce_{n}") if scope else None,
    )


def test_store_reserve_is_all_or_nothing() -> None:
    store = InMemoryReservationStore()
    store.reserve(_request(1))
    clash = ReservationRequest("chk_2", "hash_2", "digest_1", ("thumb", "merchant", "nonce_2"))
    with pytest.raises(AlreadyReservedError):
        store.reserve(clash)
    # the refused request reserved none of its other keys
    store.reserve(
        ReservationRequest("chk_2", "hash_2", "digest_2", ("thumb", "merchant", "nonce_2"))
    )


def test_store_abort_release_and_consume() -> None:
    store = InMemoryReservationStore()
    r = store.reserve(_request(1))
    store.abort(r)
    store.reserve(_request(1))  # everything free again
    store2 = InMemoryReservationStore()
    r2 = store2.reserve(_request(1))
    store2.release(r2)
    with pytest.raises(AlreadyReservedError) as taken:
        store2.reserve(_request(1))
    assert taken.value.reason == "checkout_hash_reused"  # hash and nonce stay consumed
    store2.reserve(ReservationRequest("chk_9", "hash_9", "digest_1", None))  # mandate is free
    store3 = InMemoryReservationStore()
    r3 = store3.reserve(_request(1))
    store3.consume(r3)
    with pytest.raises(AlreadyReservedError):
        store3.reserve(ReservationRequest("chk_9", "hash_9", "digest_1", None))
    for ended in (r, r2, r3):
        with pytest.raises(ReservationError):
            store3.consume(ended)


# ----- concurrency -----


def test_twenty_parallel_verifications_of_one_closed_mandate_yield_one_success() -> None:
    s = make_setup()
    token = s.mandate().token
    barrier = threading.Barrier(20)

    def attempt(_: int) -> object:
        barrier.wait()
        return s.verify(token)

    with ThreadPoolExecutor(max_workers=20) as pool:
        results = list(pool.map(attempt, range(20)))
    assert sum(isinstance(r, Accepted) for r in results) == 1
    losers = [r for r in results if isinstance(r, Rejected)]
    assert len(losers) == 19
    assert {(r.step, r.reason) for r in losers} == {("M8", "checkout_hash_reused")}
    assert len(s.log.entries) == 20


def test_twenty_parallel_closed_mandates_under_one_open_mandate_yield_one_success() -> None:
    s = make_setup()
    first = s.mandate()
    jobs = []
    for n in range(20):
        checkout = make_checkout(checkout_id=f"chk_{n:022d}")
        issued = signed_response(checkout, s.merchant_key)
        mandate = s.mandate(
            reuse_open_token=first.open_token,
            nonce=f"n{n}",
            checkout_jwt_value=checkout_jwt(issued),
        )
        jobs.append((mandate.token, issued, checkout))
    barrier = threading.Barrier(20)

    def attempt(job: tuple) -> object:
        barrier.wait()
        token, issued, checkout = job
        return s.verifier.verify(mandate=token, issued_checkout=issued, current=checkout)

    with ThreadPoolExecutor(max_workers=20) as pool:
        results = list(pool.map(attempt, jobs))
    assert sum(isinstance(r, Accepted) for r in results) == 1
    assert {r.reason for r in results if isinstance(r, Rejected)} == {"open_mandate_in_use"}


# ----- the rejection object and codes -----


def test_every_ucp_code_is_produced_by_some_step() -> None:
    seen: set[str] = set()
    s = make_setup()
    seen.add(s.verify(None).ucp_code)
    seen.add(s.verify(s.mandate(kb_aud="x").token).ucp_code)
    seen.add(s.verify(s.mandate(open_exp=NOW - 100).token).ucp_code)
    seen.add(s.verify(s.mandate(cnf=None).token).ucp_code)
    seen.add(s.verify(s.mandate(checkout_hash_value="x" * 43).token).ucp_code)
    seen.add(s.verify(s.mandate(omit_checkout_jwt=True).token).ucp_code)
    bad = make_setup(session_key=validate_jwk(generate_jwk()))
    seen.add(bad.verify(bad.mandate().token).ucp_code)
    assert seen == UCP_CODES


def test_a_rejection_needs_a_known_step_and_ucp_code() -> None:
    with pytest.raises(ValueError):
        Rejection("M9", "x", "mandate_required")
    with pytest.raises(ValueError):
        Rejection("M1", "x", "made_up_code")


def test_messages_never_echo_request_text() -> None:
    s = make_setup()
    result = s.verify("<script>alert(1)</script>~")
    assert isinstance(result, Rejected)
    assert "script" not in json.dumps(result.messages) + result.receipt


def test_setup_helpers_are_independent() -> None:
    a, b = make_setup(), make_setup()
    assert isinstance(a, Setup) and a.store is not b.store
    assert isinstance(a.constraints, AllowAllConstraintsForTests)
    assert Keys().issuer.thumbprint() != Keys().issuer.thumbprint()


def test_m8_same_checkout_id_with_a_new_hash_is_refused() -> None:
    """The checkout id is its own key: re-signing the checkout does not make it a new purchase."""
    s = make_setup()
    accepted(s.verify(s.mandate().token))
    changed = make_checkout(price=4100)
    issued2 = signed_response(changed, s.merchant_key)
    second = s.mandate(nonce="n2", checkout_jwt_value=checkout_jwt(issued2))
    result = s.verifier.verify(mandate=second.token, issued_checkout=issued2, current=changed)
    rejected(result, "M8", "checkout_hash_reused", "mandate_scope_mismatch")


def test_store_each_key_is_unique_on_its_own() -> None:
    """The store contract, independent of how the verifier builds requests."""
    base = ReservationRequest("chk_1", "hash_1", "digest_1", ("t", "merchant", "n1"))
    cases = {
        "checkout_hash_reused": ReservationRequest("chk_2", "hash_1", "digest_2", ("t", "m", "n2")),
        "nonce_replayed": ReservationRequest(
            "chk_2", "hash_2", "digest_2", ("t", "merchant", "n1")
        ),
        "open_mandate_in_use": ReservationRequest("chk_2", "hash_2", "digest_1", ("t", "m", "n2")),
    }
    for reason, request in cases.items():
        store = InMemoryReservationStore()
        store.reserve(base)
        with pytest.raises(AlreadyReservedError) as taken:
            store.reserve(request)
        assert taken.value.reason == reason
        # the same holds after the first reservation was released: only the mandate is freed
        store.release(store.reserve(ReservationRequest("c", "h", "d", None)))
    store = InMemoryReservationStore()
    store.release(store.reserve(base))
    for reason in ("checkout_hash_reused", "nonce_replayed"):
        with pytest.raises(AlreadyReservedError) as taken:
            store.reserve(
                cases[reason].__class__(
                    "chk_2",
                    "hash_1" if reason[0] == "c" else "hash_2",
                    "digest_2",
                    ("t", "merchant", "n1" if reason[0] == "n" else "n2"),
                )
            )
        assert taken.value.reason == reason


def test_a_receipt_with_another_typ_does_not_verify() -> None:
    from joserfc import jws

    from countersign.canonical import canonicalize

    s = make_setup()
    for typ in ("JWT", "checkout-receipt+jwt ", "receipt"):
        forged = jws.serialize_compact(
            {"alg": "ES256", "kid": s.merchant_key.kid, "typ": typ},
            canonicalize({"status": "Success"}),
            s.merchant_key.private_key,
            algorithms=["ES256"],
        )
        with pytest.raises(receipts.ReceiptError):
            receipts.verify_receipt(forged, [s.merchant_key.public_jwk])


def test_concurrent_reservations_are_atomic_under_forced_thread_switching() -> None:
    import sys

    previous = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        for _ in range(40):
            store = InMemoryReservationStore()
            barrier = threading.Barrier(8)

            def attempt(
                n: int,
                store: InMemoryReservationStore = store,
                barrier: threading.Barrier = barrier,
            ) -> bool:
                barrier.wait()
                try:
                    store.reserve(ReservationRequest(f"c{n}", "same-hash", f"d{n}", None))
                except AlreadyReservedError:
                    return False
                return True

            with ThreadPoolExecutor(max_workers=8) as pool:
                outcomes = list(pool.map(attempt, range(8)))
            assert sum(outcomes) == 1
    finally:
        sys.setswitchinterval(previous)


def test_every_state_change_of_the_store_happens_under_its_lock() -> None:
    """Deterministic: thread stress cannot reliably expose a missing lock, so assert it is held."""

    class SpyLock:
        def __init__(self) -> None:
            self.held = 0
            self.entered = 0

        def __enter__(self) -> None:
            self.held += 1
            self.entered += 1

        def __exit__(self, *exc: object) -> None:
            self.held -= 1

    store = InMemoryReservationStore()
    spy = SpyLock()
    store._lock = spy  # type: ignore[assignment]
    r1 = store.reserve(_request(1))
    store.abort(r1)
    r2 = store.reserve(_request(2))
    store.release(r2)
    r3 = store.reserve(_request(3))
    store.consume(r3)
    assert spy.entered == 6 and spy.held == 0
