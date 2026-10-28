"""Typed errors for mandate parsing and verification (INV-10: fail closed).

Every failure in this package is a `MandateError` subclass with a stable `code`. The code is the
"failing step" that the shared vectors in tests/vectors/mandates/ name and that the Node
cross-check scripts/mandate_chain_check.mjs must reproduce. Nothing in this package returns a
partially verified object: a function either returns a fully verified value or raises.

The codes are internal. Mapping them to the UCP error codes (`mandate_invalid_signature`,
`mandate_expired`, `mandate_scope_mismatch`, ...) is the job of the merchant and cp roles.
"""

from __future__ import annotations


class MandateError(ValueError):
    """Base class. `code` is a stable machine-readable reason."""

    code = "mandate_invalid"


# --- structure (nothing has been decoded as JSON yet) ---


class MandateStructureError(MandateError):
    code = "structure_invalid"


class MandateTypeError(MandateStructureError):
    code = "structure_not_text"


class MandateTooLargeError(MandateStructureError):
    code = "structure_too_large"


class CharacterSetError(MandateStructureError):
    code = "structure_charset"


class ChainSeparatorError(MandateStructureError):
    code = "structure_separator"


class MissingTrailingTildeError(MandateStructureError):
    code = "structure_trailing_tilde"


class TrailingKeyBindingError(MandateStructureError):
    code = "structure_trailing_kb"


class SegmentCountError(MandateStructureError):
    code = "structure_segments"


class Base64UrlError(MandateStructureError):
    code = "structure_base64url"


class DuplicateDisclosureError(MandateStructureError):
    code = "structure_duplicate_disclosure"


class ChainLengthError(MandateStructureError):
    code = "structure_chain_length"


# --- JWS ---


class MandateJsonError(MandateError):
    """A header, payload or disclosure failed the strict JSON loader. `json_code` is its reason."""

    code = "json_invalid"

    def __init__(self, message: str, json_code: str) -> None:
        super().__init__(message)
        self.json_code = json_code


class AlgorithmNotAllowedError(MandateError):
    code = "alg_not_allowed"


class HeaderParameterError(MandateError):
    code = "header_invalid"


class TypMismatchError(MandateError):
    code = "typ_mismatch"


class PayloadShapeError(MandateError):
    code = "payload_shape"


class SignatureInvalidError(MandateError):
    code = "signature_invalid"


# --- disclosures ---


class DisclosureError(MandateError):
    code = "disclosure_invalid"


class DisclosureMalformedError(DisclosureError):
    code = "disclosure_malformed"


class UnreferencedDisclosureError(DisclosureError):
    code = "disclosure_unreferenced"


class DuplicateDigestError(DisclosureError):
    code = "disclosure_duplicate_digest"


class ClaimCollisionError(DisclosureError):
    code = "disclosure_claim_collision"


class UnsupportedSdAlgError(DisclosureError):
    code = "sd_alg_unsupported"


class DelegatePayloadError(MandateError):
    code = "delegate_payload_invalid"


# --- key binding ---


class KeyBindingClaimError(MandateError):
    code = "kb_claim_missing"


class SdHashMissingError(MandateError):
    code = "sd_hash_missing"


class SdHashMismatchError(MandateError):
    code = "sd_hash_mismatch"


class AudienceMismatchError(MandateError):
    code = "kb_audience_mismatch"


class NonceMismatchError(MandateError):
    code = "kb_nonce_mismatch"


# --- vct ---


class VctMissingError(MandateError):
    code = "vct_missing"


class VctMismatchError(MandateError):
    """The `vct` is not the exact string expected at this position, including any unknown one."""

    code = "vct_mismatch"


class UnknownExpectedVctError(MandateError):
    """The caller asked for a `vct` this package does not know. A caller bug, still fail closed."""

    code = "vct_unknown_expected"


# --- cnf ---


class CnfMissingError(MandateError):
    code = "cnf_missing"


class CnfMalformedError(MandateError):
    code = "cnf_malformed"


class CnfUnsupportedKeyError(MandateError):
    code = "cnf_unsupported_key"


# --- time ---


class ClaimTypeError(MandateError):
    code = "time_claim_type"


class ExpMissingError(MandateError):
    code = "exp_missing"


class ExpiredError(MandateError):
    code = "expired"


class NotYetValidError(MandateError):
    code = "not_yet_valid"


class IssuedInFutureError(MandateError):
    code = "issued_in_future"
