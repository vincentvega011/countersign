"""The approval value that `PayPalClient.capture_authorization` requires.

A capture moves money, so the client does not take loose arguments for it. It takes a
`CaptureApproval`, which says: this authorization, for this checkout, with this exact total, and
these exact `invoice_id` and `custom_id`, has passed the capture gate (docs/architecture.md, the
gate steps). The only way to build one is `mint_capture_approval`, which the gate module is the
only library code allowed to call.

What this does and does not enforce. The constructor is sealed, the class cannot be subclassed,
copied or pickled, and the minting function is not re-exported, so no library code can capture by
accident or by a shortcut. A test (tests/unit/test_capture_surface.py) fails if any file under
`src/` other than `countersign/gate/` imports the minting function or calls the capture, and lists
the recording and test helpers outside `src/` that may. Python cannot stop a caller that is willing
to reach into private names; the guard is the structure plus that test plus review (INV-4).
"""

from __future__ import annotations

from typing import Any, NoReturn

from countersign.canonical.money import Money
from countersign.paypal.limits import check_custom_id, check_invoice_id, check_path_id

_SEAL = object()


class CaptureApproval:
    """Proof that the gate passed for one authorization. Immutable; build it with the mint."""

    __slots__ = ("authorization_id", "checkout_id", "custom_id", "expected_total", "invoice_id")

    authorization_id: str
    checkout_id: str
    custom_id: str
    expected_total: Money
    invoice_id: str

    def __init__(
        self,
        seal: object,
        *,
        checkout_id: str,
        authorization_id: str,
        expected_total: Money,
        invoice_id: str,
        custom_id: str,
    ) -> None:
        if seal is not _SEAL:
            raise TypeError("a CaptureApproval is made by the capture gate, not directly")
        if not isinstance(expected_total, Money) or expected_total.minor <= 0:
            raise ValueError("the expected total must be a positive Money")
        if not isinstance(checkout_id, str) or not checkout_id:
            raise ValueError("the checkout id must be a non-empty string")
        for name, value in (
            ("checkout_id", checkout_id),
            ("authorization_id", check_path_id(authorization_id, "authorization id")),
            ("expected_total", expected_total),
            ("invoice_id", check_invoice_id(invoice_id)),
            ("custom_id", check_custom_id(custom_id)),
        ):
            object.__setattr__(self, name, value)

    def __init_subclass__(cls, **kwargs: Any) -> NoReturn:
        raise TypeError("CaptureApproval cannot be subclassed")

    def __setattr__(self, name: str, value: object) -> NoReturn:
        raise AttributeError("a CaptureApproval is immutable")

    def __delattr__(self, name: str) -> NoReturn:
        raise AttributeError("a CaptureApproval is immutable")

    def __copy__(self) -> NoReturn:
        raise TypeError("a CaptureApproval cannot be copied")

    def __deepcopy__(self, memo: object) -> NoReturn:
        raise TypeError("a CaptureApproval cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("a CaptureApproval cannot be pickled")

    def __repr__(self) -> str:
        return f"CaptureApproval(checkout={self.checkout_id!r}, authorization={self.authorization_id!r})"


def mint_capture_approval(
    *,
    checkout_id: str,
    authorization_id: str,
    expected_total: Money,
    invoice_id: str,
    custom_id: str,
) -> CaptureApproval:
    """Build the approval. Only `countersign.gate` calls this, after every gate step has passed."""
    return CaptureApproval(
        _SEAL,
        checkout_id=checkout_id,
        authorization_id=authorization_id,
        expected_total=expected_total,
        invoice_id=invoice_id,
        custom_id=custom_id,
    )
