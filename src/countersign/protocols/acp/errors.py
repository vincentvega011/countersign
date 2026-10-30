"""ACP protocol errors (vendored `openapi.agentic_checkout.yaml`, schema `Error`).

`Error` has exactly `type` (`invalid_request`, `processing_error` or `service_unavailable`), `code`
(implementation defined, so the stable Countersign codes live here), `message` and an optional `param`
(an RFC 9535 JSONPath). It is used when no valid session can be returned. Messages are fixed text:
nothing from the request is echoed (INV-8 spirit), so a hostile body cannot shape a response.

Codes that Countersign defines (the vendored schema leaves `code` open):

- `mandate_required`: the principal is locked, or the merchant policy requires AP2, and no valid
  mandate was presented. The ACP equivalent of the UCP code of the same name.
- `unmandated_checkout_not_allowed`: no lock applies, but Countersign completes no checkout without a
  mandate unless a merchant policy allows it (docs/PROTOCOL.md Decision 53).
- `delegated_payment_unsupported`: Countersign implements no ACP delegated payment.
- plus ordinary request errors (`invalid_json`, `invalid_field`, `item_not_found`, ...).
"""

from __future__ import annotations

from typing import Any, Final

INVALID_REQUEST: Final = "invalid_request"
PROCESSING_ERROR: Final = "processing_error"
SERVICE_UNAVAILABLE: Final = "service_unavailable"

MANDATE_REQUIRED: Final = "mandate_required"
UNMANDATED_NOT_ALLOWED: Final = "unmandated_checkout_not_allowed"
DELEGATED_PAYMENT_UNSUPPORTED: Final = "delegated_payment_unsupported"


class AcpError(Exception):
    """A protocol-level ACP error: an HTTP status and an `Error` body."""

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        *,
        kind: str = INVALID_REQUEST,
        param: str | None = None,
    ) -> None:
        super().__init__(f"{code}: {message}")
        self.status = status
        self.kind = kind
        self.code = code
        self.message = message
        self.param = param

    def body(self) -> dict[str, Any]:
        out: dict[str, Any] = {"type": self.kind, "code": self.code, "message": self.message}
        if self.param is not None:
            out["param"] = self.param
        return out


def denied(code: str, message: str, param: str = "$.payment_data") -> AcpError:
    return AcpError(403, code, message, param=param)


def internal() -> AcpError:
    return AcpError(
        500, "internal_error", "The request could not be processed.", kind=PROCESSING_ERROR
    )
