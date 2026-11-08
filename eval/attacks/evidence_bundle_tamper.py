"""evidence_bundle_tamper: a field of a finished evidence bundle is rewritten and the verifier must notice.

The world built for the other cases has no device consent record behind its open mandates, so it cannot
assemble a bundle (`EvidenceUnavailable`). This case therefore starts from the committed synthetic bundle
`tests/vectors/evidence/valid.json` and judges by evidence verification alone: the offline verifier
(`countersign_verify`) must accept the untouched bundle and refuse each rewritten one. The browser verifier
is held to the same vectors by `tests/integration/test_verify_page_browser.py`, not by this case.
"""

import json
from pathlib import Path

from countersign_verify import verify_text
from eval.core import BLOCKED, Actor, AttackCase, Ctx, Expect

VALID = Path(__file__).resolve().parents[2] / "tests" / "vectors" / "evidence" / "valid.json"


def _failed(bundle: dict[str, object]) -> list[str]:
    results = verify_text(json.dumps(bundle).encode(), None)
    return [r.name for r in results if not r.ok and r.name != "trusted_keys"]


def run(ctx: Ctx) -> None:
    original = json.loads(VALID.read_text())
    if _failed(original):
        ctx.violations.append("an_untouched_bundle_does_not_verify")
    edits = {
        "capture_amount": lambda b: b["paypal"]["capture"][0].update(
            amount={"currency_code": "USD", "value": "0.01"}
        ),
        "checkout_id": lambda b: b.update(checkout_id="chk_" + "A" * 22),
        "capture_id": lambda b: b.update(capture_id="CAP-FORGED"),
        "dropped_log": lambda b: b["log"].update(entries=[]),
    }
    for name, edit in edits.items():
        bundle = json.loads(VALID.read_text())
        try:
            edit(bundle)
        except (KeyError, TypeError, AttributeError):
            ctx.violations.append(f"tamper_could_not_be_applied:{name}")
            continue
        failed = _failed(bundle)
        ctx.reason = failed[0] if failed else "tamper_not_detected"
        if not failed:
            ctx.violations.append(f"a_tampered_bundle_verifies:{name}")


CASE = AttackCase(
    id="evidence_bundle_tamper",
    category="evidence_tamper",
    description="Fields of a finished evidence bundle are rewritten after the fact.",
    actor=Actor.COMPROMISED_MERCHANT_COMPONENT,
    steps=(
        "take a valid evidence bundle",
        "rewrite the captured amount, the checkout id, the capture id, then drop the log entries",
        "run the offline verifier over each rewritten bundle",
    ),
    success_condition="the offline verifier accepts a bundle whose content was changed",
    expected={
        "full": Expect(BLOCKED, None, "the verifier recomputes every binding offline"),
        "baseline": Expect(BLOCKED, None, "bundles and their verifier are the same in every mode"),
    },
    run=run,
)
